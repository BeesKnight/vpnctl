package engine

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

// wgInterface is the fixed interface name vpnctl gives every WireGuard/
// AmneziaWG profile it brings up. Only one profile is ever active at a time
// (see netguard.Namespace), so there is never a need to derive a unique name
// per profile — a fixed name keeps health-check/stop logic trivial.
const wgInterface = netguard.WireGuardInterface

// handshakeStaleAfter is how old a WireGuard handshake can get before the
// tunnel is considered unhealthy. Keepalive is typically 25s, so this is
// generous slack for one or two missed keepalives before flagging "DOWN".
const handshakeStaleAfter = 3 * time.Minute

type wgHandle struct {
	ng       netguard.Engine
	confPath string
	logPath  string
	kind     profile.Kind
}

func startWireGuard(ng netguard.Engine, p profile.Profile, status netguard.Status) (Handle, error) {
	if p.WG == nil {
		return nil, fmt.Errorf("profile %q has no parsed WireGuard config", p.Name)
	}

	confPath, err := writeResolvedConf(p, status.ResolvedIP, status.ResolvedPort)
	if err != nil {
		return nil, err
	}

	quickBin, err := awgQuickBinary(p.Kind)
	if err != nil {
		return nil, err
	}

	cmd, err := ng.Command(quickBin, []string{"up", confPath}, netguard.ExecOptions{})
	if err != nil {
		return nil, err
	}

	logPath, logFile, err := openLog("awg-quick")
	if err != nil {
		return nil, err
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// awg-quick/wg-quick configure the interface and routes, then exit —
	// there is no persistent foreground process to track for WireGuard, so
	// this Run (not Start) is expected to complete quickly.
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s up: %w (see %s)", quickBin, err, logPath)
	}

	return &wgHandle{ng: ng, confPath: confPath, logPath: logPath, kind: p.Kind}, nil
}

// awgQuickBinary prefers the AmneziaWG-specific wrapper, falling back to
// plain wg-quick when it's a non-obfuscated WireGuard profile and
// amneziawg-tools isn't installed.
func awgQuickBinary(kind profile.Kind) (string, error) {
	if _, err := exec.LookPath("awg-quick"); err == nil {
		return "awg-quick", nil
	}
	if kind == profile.KindAmneziaWG {
		return "", fmt.Errorf("awg-quick not found: AmneziaWG profiles require amneziawg-tools")
	}
	if _, err := exec.LookPath("wg-quick"); err == nil {
		return "wg-quick", nil
	}
	return "", fmt.Errorf("wg-quick not found: install amneziawg-tools or wireguard-tools")
}

// writeResolvedConf copies the profile's WireGuard config to a fixed path
// with the Endpoint line rewritten to the pre-resolved IP, so awg-quick
// never needs to perform DNS resolution itself from inside the locked-down
// namespace (which by design cannot reach a DNS resolver).
func writeResolvedConf(p profile.Profile, resolvedIP string, port int) (string, error) {
	dir, err := netguard.EnsureStateDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, wgInterface+".conf")

	rewritten, err := rewriteEndpoint(p.WG.Raw, resolvedIP, port)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// rewriteEndpoint rewrites [Peer]'s Endpoint to the pre-resolved IP (see
// writeResolvedConf) and drops [Interface]'s DNS line entirely. DNS is never
// left for awg-quick to manage: awg-quick's set_dns() shells out to
// `resolvconf`, which fights NetworkManager/systemd-resolved (whichever one
// happens to own /etc/resolv.conf on the host) for write access to the
// host's file — exactly the kind of host-touching side effect the netns
// isolation model exists to avoid. Dropping the DNS line makes set_dns() a
// no-op (its $DNS array ends up empty); the namespace gets its own
// resolvers via netguard's /etc/netns/<namespace>/resolv.conf instead,
// which every command run inside the namespace picks up without any
// resolvconf tooling on the host at all.
func rewriteEndpoint(raw, resolvedIP string, port int) (string, error) {
	var out strings.Builder
	section := ""
	replaced := false
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
			out.WriteString(line + "\n")
			continue
		}
		if section == "interface" {
			idx := strings.Index(trimmed, "=")
			if idx >= 0 && strings.EqualFold(strings.TrimSpace(trimmed[:idx]), "DNS") {
				continue
			}
		}
		if section == "peer" {
			idx := strings.Index(trimmed, "=")
			if idx >= 0 && strings.EqualFold(strings.TrimSpace(trimmed[:idx]), "Endpoint") {
				out.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", resolvedIP, port))
				replaced = true
				continue
			}
		}
		out.WriteString(line + "\n")
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if !replaced {
		return "", fmt.Errorf("could not find Endpoint line to rewrite in [Peer] section")
	}
	return out.String(), nil
}

func (h *wgHandle) Healthy() (bool, error) { return wgHandshakeHealthy(h.ng) }

// wgHandshakeHealthy queries the kernel/userspace WireGuard implementation
// directly for the interface's latest handshake — this is what "health"
// means for WireGuard/AmneziaWG, since awg-quick itself has no persistent
// foreground process to check aliveness of. Works from any process (doesn't
// need the wgHandle that originally started it), so the health-check
// goroutine and `vpnctl status` in a freshly-invoked process can both call it.
func wgHandshakeHealthy(ng netguard.Engine) (bool, error) {
	cmd, err := ng.Command("wg", []string{"show", wgInterface, "latest-handshakes"}, netguard.ExecOptions{})
	if err != nil {
		return false, err
	}
	out, err := cmd.Output()
	if err != nil {
		cmd, err = ng.Command("awg", []string{"show", wgInterface, "latest-handshakes"}, netguard.ExecOptions{})
		if err != nil {
			return false, err
		}
		out, err = cmd.Output()
		if err != nil {
			return false, fmt.Errorf("querying handshake: %w", err)
		}
	}

	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return false, nil
	}
	unixSecs, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
	if err != nil || unixSecs == 0 {
		return false, nil // never handshaked yet
	}
	return time.Since(time.Unix(unixSecs, 0)) < handshakeStaleAfter, nil
}

func (h *wgHandle) Stop() error { return stopWireGuard(h.ng, h.kind) }

// stopWireGuard brings the interface down by its well-known config path
// rather than anything held in memory, so it works even when called from a
// process other than the one that brought it up (e.g. a later `vpnctl down`).
func stopWireGuard(ng netguard.Engine, kind profile.Kind) error {
	dir, err := netguard.StateDir()
	if err != nil {
		return err
	}
	confPath := filepath.Join(dir, wgInterface+".conf")
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return nil
	}
	quickBin, err := awgQuickBinary(kind)
	if err != nil {
		return err
	}
	cmd, err := ng.Command(quickBin, []string{"down", confPath}, netguard.ExecOptions{})
	if err != nil {
		return err
	}
	return cmd.Run()
}

func (h *wgHandle) LogPath() string { return h.logPath }
func (h *wgHandle) PID() int        { return 0 }
func (h *wgHandle) Kind() string    { return "awg-quick" }

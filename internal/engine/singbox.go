package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

// SOCKSPort is the fixed SOCKS5 port sing-box listens on inside the
// namespace, per spec §3.3. Client applications (or `vpnctl test`) must
// point their SOCKS5 settings at netguard.NamespaceIP:SOCKSPort — sing-box
// only exposes a proxy inbound here, not a transparent TUN, so unlike
// WireGuard/AmneziaWG (a real interface with its own default route) a
// launched CLI/GUI/TUI program only actually goes through the tunnel if it
// is itself SOCKS5-aware (curl --socks5, browser proxy settings, etc). This
// is a deliberate scope decision matching the spec's literal wording
// ("SOCKS5-inbound слушает на internal IP"); anything that isn't proxy-aware
// still can't leak, since the namespace's iptables only permits traffic to
// the resolved server IP/port — it just won't get anywhere either, which is
// the correct fail-closed behavior.
const SOCKSPort = 1080

type singBoxHandle struct {
	proc    *os.Process
	logPath string
}

func startSingBox(ng netguard.Engine, p profile.Profile, status netguard.Status) (Handle, error) {
	if p.Outbound == nil {
		return nil, fmt.Errorf("profile %q has no parsed sing-box outbound", p.Name)
	}

	cfgPath, err := writeSingBoxConfig(p, status.ResolvedIP, status.ResolvedPort)
	if err != nil {
		return nil, err
	}

	cmd, err := ng.Command("sing-box", []string{"run", "-c", cfgPath}, netguard.ExecOptions{})
	if err != nil {
		return nil, err
	}

	logPath, logFile, err := openLog("sing-box")
	if err != nil {
		return nil, err
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("starting sing-box: %w", err)
	}
	// The engine must outlive this function call (and the vpnctl process
	// that invoked it — see the "sessions survive closing the TUI"
	// requirement), so we deliberately do not Wait() on it here; the
	// process is reaped by the ps/kill tracking layer instead.

	return &singBoxHandle{proc: cmd.Process, logPath: logPath}, nil
}

func writeSingBoxConfig(p profile.Profile, resolvedIP string, port int) (string, error) {
	outbound := make(map[string]any, len(p.Outbound))
	for k, v := range p.Outbound {
		outbound[k] = v
	}
	outbound["tag"] = "proxy-out"
	outbound["server"] = resolvedIP
	outbound["server_port"] = port

	cfg := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"inbounds": []map[string]any{
			{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      netguard.NamespaceIP,
				"listen_port": SOCKSPort,
				"sniff":       true,
			},
		},
		"outbounds": []map[string]any{
			outbound,
			{"type": "direct", "tag": "direct-out"},
		},
		"route": map[string]any{"final": "proxy-out"},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}

	dir, err := netguard.EnsureStateDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "sing-box-active.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (h *singBoxHandle) Healthy() (bool, error) { return pidAlive(h.PID()), nil }

func (h *singBoxHandle) Stop() error { return stopByPID(h.PID()) }

func (h *singBoxHandle) LogPath() string { return h.logPath }
func (h *singBoxHandle) PID() int {
	if h.proc == nil {
		return 0
	}
	return h.proc.Pid
}
func (h *singBoxHandle) Kind() string { return "sing-box" }

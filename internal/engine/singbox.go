package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

const dnsServerTag = "remote-dns"

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
		"dns": map[string]any{
			"servers": []map[string]any{
				{
					"type":   "udp",
					"tag":    dnsServerTag,
					"server": "1.1.1.1",
					"detour": "proxy-out",
				},
			},
			"final":    dnsServerTag,
			"strategy": "prefer_ipv4",
		},
		"inbounds": []map[string]any{
			{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": netguard.SingBoxTunInterface,
				"address":        []string{netguard.SingBoxTunAddress},
				"auto_route":     true,
				"strict_route":   true,
				"route_exclude_address": []string{
					routeExcludeAddress(resolvedIP),
				},
				// "system" stack relies on the OS itself completing the TCP
				// handshake and redirecting the resulting socket to sing-box
				// via NAT/TPROXY rules that sing-box's own auto_route is
				// supposed to install — inside vpnctl's namespace this
				// silently never happens (confirmed live: tcpdump shows the
				// SYN actually reaching the tun device and being accepted by
				// the kill-switch, but sing-box's own log never registers an
				// inbound connection for it, and no PREROUTING/TPROXY rule
				// ever appears in `nft list ruleset` — so it just retransmits
				// SYNs into a void until the client times out). UDP happened
				// to work regardless (DNS resolved fine), which is what made
				// this look like a routing problem at first rather than a
				// stack problem specifically. "gvisor" is a full userspace
				// TCP/IP stack that terminates connections directly from the
				// raw packets sing-box reads off the tun fd — no OS-level
				// redirection needed, and confirmed working end-to-end
				// (real HTTP response through a live Hysteria2 tunnel) on
				// the same setup that "system" silently failed on.
				"stack": "gvisor",
			},
		},
		"outbounds": []map[string]any{
			outbound,
			{"type": "direct", "tag": "direct-out"},
		},
		"route": map[string]any{
			// Per-inbound "sniff": true was removed in sing-box 1.13 (legacy
			// inbound fields); sniffing is now its own route rule action,
			// which must run before the hijack-dns rule so DNS traffic is
			// still recognized as such.
			"rules": []map[string]any{
				{"action": "sniff"},
				{"protocol": "dns", "action": "hijack-dns"},
			},
			"final":                 "proxy-out",
			"auto_detect_interface": false,
		},
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

func routeExcludeAddress(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return ip + "/128"
	}
	return ip + "/32"
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
func (h *singBoxHandle) HelperPID() int { return 0 }
func (h *singBoxHandle) Kind() string   { return "sing-box" }

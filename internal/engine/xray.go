package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

// xraySocksPort is the fixed loopback port Xray-core's local SOCKS5 inbound
// listens on inside the namespace. It's never exposed for the user to point
// a browser at by hand — it exists purely as the internal hop between
// tun2socks and Xray (see startXray), the same way sing-box's tun inbound
// has no analogous user-facing address either.
const xraySocksPort = 11080

// xrayStartupGrace/tun2socksStartupGrace bound how long startXray waits after
// forking each half of the Xray+tun2socks pair before trusting it's actually
// up. Xray-core has no native TUN inbound (unlike sing-box), so getting the
// same full transparency requires pairing it with tun2socks: Xray terminates
// the VLESS tunnel behind a local-only SOCKS5 inbound, and tun2socks turns
// that into a real vpnctl-tun TUN device the kill-switch's existing
// `OUTPUT -o vpnctl-tun` rule already accounts for (see lockdownNamespace).
const (
	xrayStartupGrace      = 300 * time.Millisecond
	tun2socksStartupGrace = 500 * time.Millisecond
)

type xrayHandle struct {
	proc          *os.Process
	tun2socksProc *os.Process
	logPath       string
}

func startXray(ng netguard.Engine, p profile.Profile, status netguard.Status) (Handle, error) {
	if p.Outbound == nil {
		return nil, fmt.Errorf("profile %q has no parsed VLESS outbound", p.Name)
	}

	cfgPath, err := writeXrayConfig(p, status.ResolvedIP, status.ResolvedPort)
	if err != nil {
		return nil, err
	}

	logPath, logFile, err := openLog("xray")
	if err != nil {
		return nil, err
	}

	xrayCmd, err := ng.Command("xray", []string{"run", "-c", cfgPath}, netguard.ExecOptions{})
	if err != nil {
		logFile.Close()
		return nil, err
	}
	xrayCmd.Stdout = logFile
	xrayCmd.Stderr = logFile
	if err := xrayCmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("starting xray: %w", err)
	}

	// Xray needs a moment to parse its config and bind the local SOCKS
	// inbound before tun2socks has anything to connect to — same rationale
	// as actions.engineStartupGrace, just scoped to this one internal hop.
	time.Sleep(xrayStartupGrace)
	if !pidAlive(xrayCmd.Process.Pid) {
		logFile.Close()
		return nil, fmt.Errorf("xray exited immediately after starting (see %s)", logPath)
	}

	tun2socksCmd, err := ng.Command("tun2socks", []string{
		"-device", "tun://" + netguard.SingBoxTunInterface,
		"-proxy", fmt.Sprintf("socks5://127.0.0.1:%d", xraySocksPort),
		"-tun-post-up", tunPostUpCommand(),
	}, netguard.ExecOptions{})
	if err != nil {
		_ = xrayCmd.Process.Kill()
		logFile.Close()
		return nil, err
	}
	tun2socksCmd.Stdout = logFile
	tun2socksCmd.Stderr = logFile
	if err := tun2socksCmd.Start(); err != nil {
		_ = xrayCmd.Process.Kill()
		logFile.Close()
		return nil, fmt.Errorf("starting tun2socks: %w", err)
	}

	// tun2socks needs a moment to create the TUN device and run
	// -tun-post-up (see tunPostUpCommand) before trusting the tunnel is up.
	time.Sleep(tun2socksStartupGrace)
	if !pidAlive(tun2socksCmd.Process.Pid) {
		_ = xrayCmd.Process.Kill()
		logFile.Close()
		return nil, fmt.Errorf("tun2socks exited immediately after starting (see %s)", logPath)
	}

	return &xrayHandle{proc: xrayCmd.Process, tun2socksProc: tun2socksCmd.Process, logPath: logPath}, nil
}

// tunPostUpCommand addresses and routes the TUN device through tun2socks's
// own `-tun-post-up` hook (documented upstream for exactly this: "automatically
// configure the ip address for our interface addresses and routes"), rather
// than vpnctl polling for the interface to appear and configuring it
// separately. tun2socks runs this via its own subprocess only once the
// device actually exists, and that subprocess inherits the same network
// namespace tun2socks itself is running in — so plain `ip` commands here
// land in the right namespace without going through netguard.Engine.Command
// a second time. Point-to-point, no gateway needed, same as sing-box's own
// `auto_route` for its native tun inbound.
func tunPostUpCommand() string {
	return fmt.Sprintf(
		"sh -c 'ip addr add %s dev %s && ip link set %s up && ip route replace default dev %s'",
		netguard.SingBoxTunAddress, netguard.SingBoxTunInterface,
		netguard.SingBoxTunInterface, netguard.SingBoxTunInterface,
	)
}

// writeXrayConfig renders p's parsed VLESS outbound (a generic map in the
// same sing-box-outbound shape internal/importer produces, so both engines
// share one on-disk profile format) into a real Xray-core config: a
// loopback-only SOCKS5 inbound for tun2socks to hand traffic to, the VLESS
// outbound itself, and a `dns` outbound so locally-hijacked port-53 traffic
// resolves through the tunnel rather than leaking — the direct Xray-core
// equivalent of sing-box's `hijack-dns` route action. The top-level `dns`
// block is required too: without it Xray-core's own internal resolves fall
// back to the OS resolver inside the netns, which tun2socks's default route
// then loops back into Xray's own TUN interface and times out.
func writeXrayConfig(p profile.Profile, resolvedIP string, port int) (string, error) {
	proxyOut, err := buildXrayOutbound(p, resolvedIP, port)
	if err != nil {
		return "", err
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"dns": map[string]any{
			"servers": []string{"1.1.1.1"},
		},
		"inbounds": []map[string]any{
			{
				"tag":      "socks-in",
				"listen":   "127.0.0.1",
				"port":     xraySocksPort,
				"protocol": "socks",
				"settings": map[string]any{"udp": true, "auth": "noauth"},
			},
		},
		"outbounds": []map[string]any{
			proxyOut,
			{"tag": "direct-out", "protocol": "freedom"},
			{
				"tag":           "dns-out",
				"protocol":      "dns",
				"settings":      map[string]any{"address": "1.1.1.1", "port": 53, "network": "udp"},
				"proxySettings": map[string]any{"tag": "proxy-out"},
			},
		},
		"routing": map[string]any{
			"rules": []map[string]any{
				{"type": "field", "network": "udp", "port": 53, "outboundTag": "dns-out"},
				{"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
			},
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
	path := filepath.Join(dir, "xray-active.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// buildXrayOutbound converts the generic parsed VLESS outbound (uuid, flow,
// tls/reality, transport) into Xray-core's own "vless" protocol outbound
// shape (vnext/users, streamSettings) — the two schemas share no field names
// even though they describe the same handful of concepts.
func buildXrayOutbound(p profile.Profile, resolvedIP string, port int) (map[string]any, error) {
	uuid, _ := p.Outbound["uuid"].(string)
	if uuid == "" {
		return nil, fmt.Errorf("profile %q outbound has no uuid", p.Name)
	}

	user := map[string]any{"id": uuid, "encryption": "none"}
	if flow, ok := p.Outbound["flow"].(string); ok && flow != "" {
		user["flow"] = flow
	}

	stream := map[string]any{}
	network := "tcp"
	if transport, ok := p.Outbound["transport"].(map[string]any); ok {
		if t, ok := transport["type"].(string); ok && t != "" {
			network = t
		}
		applyTransportStreamSettings(stream, network, transport)
	}
	stream["network"] = network

	if tls, ok := p.Outbound["tls"].(map[string]any); ok {
		applyTLSStreamSettings(stream, tls)
	} else {
		stream["security"] = "none"
	}

	return map[string]any{
		"tag":      "proxy-out",
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []map[string]any{
				{
					"address": resolvedIP,
					"port":    port,
					"users":   []map[string]any{user},
				},
			},
		},
		"streamSettings": stream,
	}, nil
}

// applyTransportStreamSettings fills in the network-specific settings block
// Xray-core expects (wsSettings/grpcSettings/xhttpSettings/httpSettings) —
// tcp/kcp/quic need none of these for a minimal working config, so they fall
// through untouched.
func applyTransportStreamSettings(stream map[string]any, network string, transport map[string]any) {
	switch network {
	case "ws":
		ws := map[string]any{}
		if path, ok := transport["path"].(string); ok && path != "" {
			ws["path"] = path
		}
		if headers, ok := transport["headers"].(map[string]any); ok {
			ws["headers"] = headers
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]any{}
		if svc, ok := transport["service_name"].(string); ok && svc != "" {
			grpc["serviceName"] = svc
		}
		stream["grpcSettings"] = grpc
	case "xhttp":
		xh := map[string]any{}
		if path, ok := transport["path"].(string); ok && path != "" {
			xh["path"] = path
		}
		if host, ok := transport["host"].(string); ok && host != "" {
			xh["host"] = host
		}
		if mode, ok := transport["mode"].(string); ok && mode != "" {
			xh["mode"] = mode
		}
		stream["xhttpSettings"] = xh
	case "http":
		h := map[string]any{}
		if path, ok := transport["path"].(string); ok && path != "" {
			h["path"] = path
		}
		if headers, ok := transport["headers"].(map[string]any); ok {
			if host, ok := headers["Host"].(string); ok && host != "" {
				h["host"] = []string{host}
			}
		}
		stream["httpSettings"] = h
	}
}

// applyTLSStreamSettings translates the imported tls block (enabled,
// server_name, insecure, utls.fingerprint, reality.*) into Xray-core's
// security/tlsSettings/realitySettings fields.
func applyTLSStreamSettings(stream map[string]any, tls map[string]any) {
	enabled, _ := tls["enabled"].(bool)
	if !enabled {
		stream["security"] = "none"
		return
	}

	serverName, _ := tls["server_name"].(string)
	insecure, _ := tls["insecure"].(bool)
	fingerprint := ""
	if utls, ok := tls["utls"].(map[string]any); ok {
		fingerprint, _ = utls["fingerprint"].(string)
	}

	if reality, ok := tls["reality"].(map[string]any); ok {
		if realityEnabled, _ := reality["enabled"].(bool); realityEnabled {
			realitySettings := map[string]any{"serverName": serverName, "show": false}
			if pbk, ok := reality["public_key"].(string); ok && pbk != "" {
				realitySettings["publicKey"] = pbk
			}
			if sid, ok := reality["short_id"].(string); ok && sid != "" {
				realitySettings["shortId"] = sid
			}
			if fingerprint != "" {
				realitySettings["fingerprint"] = fingerprint
			}
			stream["security"] = "reality"
			stream["realitySettings"] = realitySettings
			return
		}
	}

	tlsSettings := map[string]any{"serverName": serverName}
	if insecure {
		tlsSettings["allowInsecure"] = true
	}
	if fingerprint != "" {
		tlsSettings["fingerprint"] = fingerprint
	}
	stream["security"] = "tls"
	stream["tlsSettings"] = tlsSettings
}

func (h *xrayHandle) Healthy() (bool, error) {
	return pidAlive(h.PID()) && pidAlive(h.HelperPID()), nil
}

func (h *xrayHandle) Stop() error {
	if err := stopByPID(h.HelperPID()); err != nil {
		return err
	}
	return stopByPID(h.PID())
}

func (h *xrayHandle) LogPath() string { return h.logPath }

func (h *xrayHandle) PID() int {
	if h.proc == nil {
		return 0
	}
	return h.proc.Pid
}

func (h *xrayHandle) HelperPID() int {
	if h.tun2socksProc == nil {
		return 0
	}
	return h.tun2socksProc.Pid
}

func (h *xrayHandle) Kind() string { return "xray" }

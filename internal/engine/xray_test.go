package engine

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

func TestWriteXrayConfigXHTTPTransport(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")

	p := profile.Profile{
		Name: "FirstVDS---01-[RU]---VLESS",
		Kind: profile.KindVLESS,
		Outbound: map[string]any{
			"type":        "vless",
			"server":      "vless.example.com",
			"server_port": float64(443),
			"uuid":        "b831381d-6324-4d53-ad4f-8cda48b30811",
			"flow":        "xtls-rprx-vision",
			"tls": map[string]any{
				"enabled":     true,
				"server_name": "cdn.example.com",
			},
			"transport": map[string]any{
				"type": "xhttp",
				"path": "/xhttp",
				"host": "cdn.example.com",
				"mode": "stream-one",
			},
		},
	}

	path, err := writeXrayConfig(p, "185.220.10.5", 443)
	if err != nil {
		t.Fatalf("writeXrayConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}

	inbounds, ok := cfg["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("expected exactly one inbound, got %v", cfg["inbounds"])
	}
	socksIn := inbounds[0].(map[string]any)
	if socksIn["protocol"] != "socks" || socksIn["listen"] != "127.0.0.1" {
		t.Errorf("expected loopback-only socks inbound, got %v", socksIn)
	}
	if socksIn["port"] != float64(xraySocksPort) {
		t.Errorf("expected fixed socks port %d, got %v", xraySocksPort, socksIn["port"])
	}
	settings, ok := socksIn["settings"].(map[string]any)
	if !ok || settings["udp"] != true {
		t.Errorf("expected udp=true on socks inbound (needed for DNS/UDP over tun2socks), got %v", socksIn["settings"])
	}

	outbounds, ok := cfg["outbounds"].([]any)
	if !ok || len(outbounds) < 1 {
		t.Fatalf("expected at least one outbound, got %v", cfg["outbounds"])
	}
	proxyOut := outbounds[0].(map[string]any)
	if proxyOut["protocol"] != "vless" || proxyOut["tag"] != "proxy-out" {
		t.Fatalf("expected first outbound to be the vless proxy-out, got %v", proxyOut)
	}

	vlessSettings, ok := proxyOut["settings"].(map[string]any)
	if !ok {
		t.Fatalf("expected vless settings, got %v", proxyOut["settings"])
	}
	vnext, ok := vlessSettings["vnext"].([]any)
	if !ok || len(vnext) != 1 {
		t.Fatalf("expected one vnext entry, got %v", vlessSettings["vnext"])
	}
	server := vnext[0].(map[string]any)
	if server["address"] != "185.220.10.5" {
		t.Errorf("expected vnext address overridden to resolved IP, got %v", server["address"])
	}
	if server["port"] != float64(443) {
		t.Errorf("expected vnext port 443, got %v", server["port"])
	}
	users, ok := server["users"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("expected one user, got %v", server["users"])
	}
	user := users[0].(map[string]any)
	if user["id"] != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Errorf("expected uuid preserved as vnext user id, got %v", user["id"])
	}
	if user["flow"] != "xtls-rprx-vision" {
		t.Errorf("expected flow preserved, got %v", user["flow"])
	}
	if user["encryption"] != "none" {
		t.Errorf("expected encryption none (required by VLESS), got %v", user["encryption"])
	}

	stream, ok := proxyOut["streamSettings"].(map[string]any)
	if !ok {
		t.Fatalf("expected streamSettings, got %v", proxyOut["streamSettings"])
	}
	if stream["network"] != "xhttp" {
		t.Errorf("expected xhttp network, got %v", stream["network"])
	}
	if stream["security"] != "tls" {
		t.Errorf("expected tls security, got %v", stream["security"])
	}
	tlsSettings, ok := stream["tlsSettings"].(map[string]any)
	if !ok || tlsSettings["serverName"] != "cdn.example.com" {
		t.Errorf("expected tls serverName for correct SNI, got %v", stream["tlsSettings"])
	}
	xhttpSettings, ok := stream["xhttpSettings"].(map[string]any)
	if !ok {
		t.Fatalf("expected xhttpSettings block, got %v", stream["xhttpSettings"])
	}
	if xhttpSettings["path"] != "/xhttp" || xhttpSettings["host"] != "cdn.example.com" || xhttpSettings["mode"] != "stream-one" {
		t.Errorf("expected xhttp path/host/mode preserved, got %v", xhttpSettings)
	}

	// DNS must be hijacked and tunneled, mirroring sing-box's hijack-dns
	// route action, or DNS queries leak outside the kill-switch.
	dnsOut := outbounds[2].(map[string]any)
	if dnsOut["protocol"] != "dns" {
		t.Fatalf("expected a dns outbound, got %v", dnsOut)
	}
	proxySettings, ok := dnsOut["proxySettings"].(map[string]any)
	if !ok || proxySettings["tag"] != "proxy-out" {
		t.Errorf("expected dns-out chained through proxy-out to avoid a DNS leak, got %v", dnsOut["proxySettings"])
	}

	routing, ok := cfg["routing"].(map[string]any)
	if !ok {
		t.Fatalf("expected routing section, got %v", cfg["routing"])
	}
	rules, ok := routing["rules"].([]any)
	if !ok || len(rules) != 2 {
		t.Fatalf("expected two routing rules, got %v", routing["rules"])
	}
	dnsRule := rules[0].(map[string]any)
	if dnsRule["outboundTag"] != "dns-out" || dnsRule["port"] != float64(53) {
		t.Errorf("expected port-53 traffic routed to dns-out, got %v", dnsRule)
	}
}

func TestWriteXrayConfigTopLevelDNS(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")

	p := profile.Profile{
		Name: "dns-check",
		Kind: profile.KindVLESS,
		Outbound: map[string]any{
			"type":   "vless",
			"server": "vless.example.com",
			"uuid":   "b831381d-6324-4d53-ad4f-8cda48b30811",
		},
	}

	path, err := writeXrayConfig(p, "185.220.10.5", 443)
	if err != nil {
		t.Fatalf("writeXrayConfig: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}

	// Without a top-level dns block, Xray-core's own internal resolves fall
	// back to the OS resolver inside the netns, which loops back into Xray's
	// own TUN interface (via tun2socks's default route) and times out.
	dns, ok := cfg["dns"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level dns block, got %v", cfg["dns"])
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) != 1 || servers[0] != "1.1.1.1" {
		t.Errorf("expected dns.servers to contain 1.1.1.1, got %v", dns["servers"])
	}
}

func TestWriteXrayConfigRealityAndWS(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")

	p := profile.Profile{
		Name: "ws-reality",
		Kind: profile.KindVLESS,
		Outbound: map[string]any{
			"type":   "vless",
			"server": "vpn.example.com",
			"uuid":   "uuid-here",
			"tls": map[string]any{
				"enabled":     true,
				"server_name": "cloudflare.com",
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{
					"enabled":    true,
					"public_key": "abc123",
					"short_id":   "de",
				},
			},
			"transport": map[string]any{
				"type": "ws",
				"path": "/ws",
			},
		},
	}

	path, err := writeXrayConfig(p, "1.2.3.4", 8443)
	if err != nil {
		t.Fatalf("writeXrayConfig: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}
	outbounds := cfg["outbounds"].([]any)
	proxyOut := outbounds[0].(map[string]any)
	stream := proxyOut["streamSettings"].(map[string]any)

	if stream["security"] != "reality" {
		t.Errorf("expected reality security when tls.reality.enabled, got %v", stream["security"])
	}
	realitySettings, ok := stream["realitySettings"].(map[string]any)
	if !ok {
		t.Fatalf("expected realitySettings, got %v", stream["realitySettings"])
	}
	if realitySettings["publicKey"] != "abc123" || realitySettings["shortId"] != "de" {
		t.Errorf("expected reality public key/short id preserved, got %v", realitySettings)
	}
	if realitySettings["fingerprint"] != "chrome" {
		t.Errorf("expected utls fingerprint carried into realitySettings, got %v", realitySettings["fingerprint"])
	}

	wsSettings, ok := stream["wsSettings"].(map[string]any)
	if !ok || wsSettings["path"] != "/ws" {
		t.Errorf("expected ws path preserved, got %v", stream["wsSettings"])
	}
}

func TestTunPostUpCommandExcludesServerFromTun(t *testing.T) {
	cmd := tunPostUpCommand("185.220.10.5")

	hostRoute := "ip route add 185.220.10.5/32 via " + netguard.HostIP + " dev " + netguard.VethNS
	if !strings.Contains(cmd, hostRoute) {
		t.Fatalf("expected post-up command to route the resolved server IP via the original veth path, got %q", cmd)
	}

	replaceDefault := "ip route replace default dev " + netguard.SingBoxTunInterface
	hostRouteIdx := strings.Index(cmd, hostRoute)
	replaceDefaultIdx := strings.Index(cmd, replaceDefault)
	if replaceDefaultIdx == -1 {
		t.Fatalf("expected post-up command to replace the default route, got %q", cmd)
	}
	if hostRouteIdx > replaceDefaultIdx {
		t.Errorf("expected the resolved server's host route to be added before the default route is replaced, got %q", cmd)
	}
}

func TestBuildXrayOutboundRejectsMissingUUID(t *testing.T) {
	p := profile.Profile{
		Name:     "broken",
		Outbound: map[string]any{"type": "vless", "server": "1.2.3.4"},
	}
	if _, err := buildXrayOutbound(p, "1.2.3.4", 443); err == nil {
		t.Fatal("expected error for outbound with no uuid")
	}
}

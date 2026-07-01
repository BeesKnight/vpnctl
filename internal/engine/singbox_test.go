package engine

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

func TestWriteSingBoxConfigPreservesOutboundFieldsAndOverridesServer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")

	p := profile.Profile{
		Name: "nl02-mk01",
		Kind: profile.KindVLESS,
		Outbound: map[string]any{
			"type":        "vless",
			"tag":         "original-tag",
			"server":      "vless.example.com",
			"server_port": float64(443),
			"uuid":        "b831381d-6324-4d53-ad4f-8cda48b30811",
			"tls": map[string]any{
				"enabled":     true,
				"server_name": "example.com",
			},
		},
	}

	path, err := writeSingBoxConfig(p, "185.220.10.5", 443)
	if err != nil {
		t.Fatalf("writeSingBoxConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}

	outbounds, ok := cfg["outbounds"].([]any)
	if !ok || len(outbounds) < 1 {
		t.Fatalf("expected at least one outbound, got %v", cfg["outbounds"])
	}
	proxyOut, ok := outbounds[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first outbound to be an object, got %T", outbounds[0])
	}

	if proxyOut["server"] != "185.220.10.5" {
		t.Errorf("expected server overridden to resolved IP, got %v", proxyOut["server"])
	}
	if proxyOut["tag"] != "proxy-out" {
		t.Errorf("expected tag rewritten to proxy-out, got %v", proxyOut["tag"])
	}
	if proxyOut["uuid"] != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Errorf("expected uuid preserved, got %v", proxyOut["uuid"])
	}
	tls, ok := proxyOut["tls"].(map[string]any)
	if !ok || tls["server_name"] != "example.com" {
		t.Errorf("expected tls.server_name preserved for correct SNI, got %v", proxyOut["tls"])
	}

	inbounds, ok := cfg["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("expected exactly one inbound, got %v", cfg["inbounds"])
	}
	tunIn := inbounds[0].(map[string]any)
	if tunIn["type"] != "tun" {
		t.Errorf("expected TUN inbound, got %v", tunIn["type"])
	}
	if tunIn["interface_name"] != "vpnctl-tun" {
		t.Errorf("expected fixed TUN interface name, got %v", tunIn["interface_name"])
	}
	if got := tunIn["address"]; got == nil {
		t.Fatal("expected TUN address to be set")
	}
	if tunIn["auto_route"] != true || tunIn["strict_route"] != true {
		t.Errorf("expected auto_route and strict_route enabled, got auto_route=%v strict_route=%v", tunIn["auto_route"], tunIn["strict_route"])
	}
	excludes, ok := tunIn["route_exclude_address"].([]any)
	if !ok || len(excludes) != 1 || excludes[0] != "185.220.10.5/32" {
		t.Errorf("expected resolved server IP to be excluded from TUN routes, got %v", tunIn["route_exclude_address"])
	}

	dns, ok := cfg["dns"].(map[string]any)
	if !ok {
		t.Fatalf("expected dns section, got %v", cfg["dns"])
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("expected one DNS server, got %v", dns["servers"])
	}
	remoteDNS := servers[0].(map[string]any)
	if remoteDNS["detour"] != "proxy-out" {
		t.Errorf("expected DNS server to detour through proxy-out, got %v", remoteDNS["detour"])
	}

	route, ok := cfg["route"].(map[string]any)
	if !ok {
		t.Fatalf("expected route section, got %v", cfg["route"])
	}
	if route["auto_detect_interface"] != false {
		t.Errorf("expected auto_detect_interface=false, got %v", route["auto_detect_interface"])
	}
}

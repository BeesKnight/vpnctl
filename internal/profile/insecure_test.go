package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSetTLSInsecureTogglesOnlyTargetProfile(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()

	writeFile(t, filepath.Join(base, "proxy", "flaky-cert.json"),
		`{"type":"hysteria2","server":"5.6.7.8","server_port":443,"password":"x","tls":{"enabled":true,"server_name":"flaky-cert.example.com"}}`)
	writeFile(t, filepath.Join(base, "proxy", "other.json"),
		`{"type":"vless","server":"1.2.3.4","server_port":443,"uuid":"y","tls":{"enabled":true,"server_name":"other.example.com"}}`)

	target, err := Find("flaky-cert")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if err := SetTLSInsecure(target, true); err != nil {
		t.Fatalf("SetTLSInsecure: %v", err)
	}

	reloaded, err := Find("flaky-cert")
	if err != nil {
		t.Fatalf("Find after set: %v", err)
	}
	tls, ok := reloaded.Outbound["tls"].(map[string]any)
	if !ok || tls["insecure"] != true {
		t.Errorf("expected insecure=true on the target profile, got %v", reloaded.Outbound["tls"])
	}
	if tls["server_name"] != "flaky-cert.example.com" {
		t.Errorf("expected unrelated tls fields preserved, got %v", tls)
	}

	other, err := Find("other")
	if err != nil {
		t.Fatalf("Find other: %v", err)
	}
	otherTLS, _ := other.Outbound["tls"].(map[string]any)
	if _, present := otherTLS["insecure"]; present {
		t.Errorf("expected the unrelated profile to be untouched, got %v", otherTLS)
	}

	if err := SetTLSInsecure(reloaded, false); err != nil {
		t.Fatalf("SetTLSInsecure(off): %v", err)
	}
	final, err := Find("flaky-cert")
	if err != nil {
		t.Fatalf("Find after unset: %v", err)
	}
	finalTLS, _ := final.Outbound["tls"].(map[string]any)
	if finalTLS["insecure"] != false {
		t.Errorf("expected insecure=false after toggling off, got %v", finalTLS["insecure"])
	}
}

func TestSetTLSInsecureRejectsWireGuardProfile(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()
	writeFile(t, filepath.Join(base, "wg", "switz.conf"), amneziaConf)

	p, err := Find("switz")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if err := SetTLSInsecure(p, true); err == nil {
		t.Fatal("expected an error setting tls.insecure on a WireGuard profile")
	}
}

func TestSetTLSInsecureWritesValidJSON(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()
	path := filepath.Join(base, "proxy", "notls.json")
	writeFile(t, path, `{"type":"vless","server":"1.2.3.4","server_port":443,"uuid":"z"}`)

	p, err := Find("notls")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if err := SetTLSInsecure(p, true); err != nil {
		t.Fatalf("SetTLSInsecure on a profile with no prior tls block: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("rewritten file is not valid JSON: %v", err)
	}
	tls, ok := m["tls"].(map[string]any)
	if !ok || tls["insecure"] != true {
		t.Errorf("expected a new tls block with insecure=true, got %v", m["tls"])
	}
}

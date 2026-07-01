package importer

import "testing"

func TestParseHysteria2Basic(t *testing.T) {
	uri := "hysteria2://s3cr3t@95.142.10.30:443?sni=cdn.example.com&insecure=1&obfs=salamander&obfs-password=obfspw#kz03-hy01"

	name, outbound, err := ParseHysteria2(uri)
	if err != nil {
		t.Fatalf("ParseHysteria2: %v", err)
	}
	if name != "kz03-hy01" {
		t.Errorf("expected name kz03-hy01, got %q", name)
	}
	if outbound["type"] != "hysteria2" {
		t.Errorf("expected type hysteria2, got %v", outbound["type"])
	}
	if outbound["server"] != "95.142.10.30" || outbound["server_port"] != 443 {
		t.Errorf("unexpected server/port: %v %v", outbound["server"], outbound["server_port"])
	}
	if outbound["password"] != "s3cr3t" {
		t.Errorf("expected password preserved, got %v", outbound["password"])
	}

	tls, ok := outbound["tls"].(map[string]any)
	if !ok || tls["server_name"] != "cdn.example.com" || tls["insecure"] != true {
		t.Fatalf("unexpected tls block: %v", outbound["tls"])
	}

	obfs, ok := outbound["obfs"].(map[string]any)
	if !ok || obfs["type"] != "salamander" || obfs["password"] != "obfspw" {
		t.Fatalf("unexpected obfs block: %v", outbound["obfs"])
	}
}

func TestParseHysteria2AcceptsHy2Scheme(t *testing.T) {
	_, outbound, err := ParseHysteria2("hy2://pw@host.example.com:443")
	if err != nil {
		t.Fatalf("ParseHysteria2: %v", err)
	}
	if outbound["server"] != "host.example.com" {
		t.Errorf("unexpected server: %v", outbound["server"])
	}
}

func TestParseHysteria2RejectsMissingPassword(t *testing.T) {
	_, _, err := ParseHysteria2("hysteria2://@host:443")
	if err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestParseHysteria2RejectsWrongScheme(t *testing.T) {
	_, _, err := ParseHysteria2("vless://uuid@host:443")
	if err == nil {
		t.Fatal("expected error for non-hysteria2 scheme")
	}
}

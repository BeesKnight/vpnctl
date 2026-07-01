package importer

import "testing"

func TestParseVLESSBasic(t *testing.T) {
	uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@185.220.10.5:443?encryption=none&security=tls&sni=example.com&type=tcp&flow=xtls-rprx-vision#MyServer%20NL"

	name, outbound, err := ParseVLESS(uri)
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}
	if name != "MyServer-NL" {
		t.Errorf("expected sanitized name %q, got %q", "MyServer-NL", name)
	}
	if outbound["type"] != "vless" {
		t.Errorf("expected type vless, got %v", outbound["type"])
	}
	if outbound["server"] != "185.220.10.5" {
		t.Errorf("expected server 185.220.10.5, got %v", outbound["server"])
	}
	if outbound["server_port"] != 443 {
		t.Errorf("expected port 443, got %v", outbound["server_port"])
	}
	if outbound["uuid"] != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Errorf("expected uuid preserved, got %v", outbound["uuid"])
	}
	if outbound["flow"] != "xtls-rprx-vision" {
		t.Errorf("expected flow preserved, got %v", outbound["flow"])
	}
	tls, ok := outbound["tls"].(map[string]any)
	if !ok {
		t.Fatalf("expected tls block, got %v", outbound["tls"])
	}
	if tls["server_name"] != "example.com" {
		t.Errorf("expected sni example.com, got %v", tls["server_name"])
	}
	if _, hasTransport := outbound["transport"]; hasTransport {
		t.Errorf("expected no transport block for type=tcp, got %v", outbound["transport"])
	}
}

func TestParseVLESSWebSocketAndReality(t *testing.T) {
	uri := "vless://uuid-here@vpn.example.com:8443?security=reality&sni=cloudflare.com&fp=chrome&pbk=abc123&sid=de&type=ws&path=%2Fws&host=cdn.example.com#WS%2BReality"

	name, outbound, err := ParseVLESS(uri)
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}
	if name != "WS+Reality" {
		t.Errorf("expected name %q, got %q", "WS+Reality", name)
	}

	tls, ok := outbound["tls"].(map[string]any)
	if !ok {
		t.Fatalf("expected tls block")
	}
	reality, ok := tls["reality"].(map[string]any)
	if !ok {
		t.Fatalf("expected reality block, got %v", tls["reality"])
	}
	if reality["public_key"] != "abc123" || reality["short_id"] != "de" {
		t.Errorf("unexpected reality fields: %v", reality)
	}
	utls, ok := tls["utls"].(map[string]any)
	if !ok || utls["fingerprint"] != "chrome" {
		t.Errorf("expected utls fingerprint chrome, got %v", tls["utls"])
	}

	transport, ok := outbound["transport"].(map[string]any)
	if !ok || transport["type"] != "ws" || transport["path"] != "/ws" {
		t.Fatalf("expected ws transport with path, got %v", outbound["transport"])
	}
	headers, ok := transport["headers"].(map[string]any)
	if !ok || headers["Host"] != "cdn.example.com" {
		t.Errorf("expected Host header cdn.example.com, got %v", transport["headers"])
	}
}

func TestParseVLESSXHTTPTransport(t *testing.T) {
	uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?security=tls&sni=cdn.example.com&type=xhttp&path=%2Fxhttp&host=cdn.example.com&mode=stream-one#FirstVDS---01-%5BRU%5D---VLESS"

	name, outbound, err := ParseVLESS(uri)
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}
	if name != "FirstVDS---01-[RU]---VLESS" {
		t.Errorf("expected sanitized name preserved, got %q", name)
	}

	transport, ok := outbound["transport"].(map[string]any)
	if !ok {
		t.Fatalf("expected transport block, got %v", outbound["transport"])
	}
	if transport["type"] != "xhttp" {
		t.Errorf("expected xhttp transport type, got %v", transport["type"])
	}
	if transport["path"] != "/xhttp" {
		t.Errorf("expected path /xhttp, got %v", transport["path"])
	}
	if transport["host"] != "cdn.example.com" {
		t.Errorf("expected host cdn.example.com as a plain field (not a header), got %v", transport["host"])
	}
	if transport["mode"] != "stream-one" {
		t.Errorf("expected mode stream-one, got %v", transport["mode"])
	}
}

func TestParseVLESSSplitHTTPIsXHTTPAlias(t *testing.T) {
	_, outbound, err := ParseVLESS("vless://uuid@host.example.com:443?type=splithttp&path=%2Fsh")
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}
	transport, ok := outbound["transport"].(map[string]any)
	if !ok || transport["type"] != "xhttp" {
		t.Fatalf("expected splithttp to be normalized to xhttp, got %v", outbound["transport"])
	}
}

func TestParseVLESSRejectsWrongScheme(t *testing.T) {
	_, _, err := ParseVLESS("hysteria2://pw@host:443")
	if err == nil {
		t.Fatal("expected error for non-vless scheme")
	}
}

func TestParseVLESSRejectsMissingUUID(t *testing.T) {
	_, _, err := ParseVLESS("vless://@host:443")
	if err == nil {
		t.Fatal("expected error for missing uuid")
	}
}

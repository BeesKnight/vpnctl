package profile

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	// Cleared, not set to a literal false: absence of the field is the same
	// "verify normally" default sing-box/Xray already apply, and this keeps
	// the "off" path identical for both the insecure-bool case (Hysteria2)
	// and the pinned-cert case (VLESS, see TestSetTLSInsecureVLESSPinsCert)
	// rather than needing two different "cleared" representations.
	if _, present := finalTLS["insecure"]; present {
		t.Errorf("expected insecure cleared after toggling off, got %v", finalTLS["insecure"])
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
	// hysteria2, not vless: VLESS's insecure=true path dials the server to
	// fetch and pin its certificate (see TestSetTLSInsecureVLESSPinsCert),
	// which would turn this test into a real network call against a bogus
	// IP — this test's own point is just "handles a profile with no prior
	// tls block", which doesn't need that.
	writeFile(t, path, `{"type":"hysteria2","server":"1.2.3.4","server_port":443,"password":"z"}`)

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

// selfSignedTLSListener starts a real local TLS listener presenting a
// freshly generated self-signed certificate, accepting exactly one
// connection before closing — enough for fetchPeerCertSHA256's one-shot
// handshake, nothing more. Returns the listener's address and the
// certificate's own hex sha256 (computed independently of
// fetchPeerCertSHA256, so the test isn't just checking the function
// against itself).
func selfSignedTLSListener(t *testing.T) (addr string, wantHash string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vpnctl-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	sum := sha256.Sum256(der)
	wantHash = hex.EncodeToString(sum[:])

	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if tconn, ok := conn.(*tls.Conn); ok {
			_ = tconn.Handshake()
		}
	}()

	return ln.Addr().String(), wantHash
}

// TestSetTLSInsecureVLESSPinsCert is the real end-to-end test for the fix
// described in SetTLSInsecure's doc comment: current Xray-core rejects a
// plain tls.insecure=true outright, so for VLESS profiles specifically,
// enabling "insecure" must fetch the server's actual certificate and pin
// its hash instead — confirmed here against a real local TLS listener
// (not a mock), checking the stored pin matches the certificate's true
// sha256 computed independently.
func TestSetTLSInsecureVLESSPinsCert(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()

	addr, wantHash := selfSignedTLSListener(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting %q: %v", addr, err)
	}

	writeFile(t, filepath.Join(base, "proxy", "vlesspin.json"),
		`{"type":"vless","server":"`+host+`","server_port":`+portStr+`,"uuid":"z"}`)

	p, err := Find("vlesspin")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if err := SetTLSInsecure(p, true); err != nil {
		t.Fatalf("SetTLSInsecure: %v", err)
	}

	reloaded, err := Find("vlesspin")
	if err != nil {
		t.Fatalf("Find after set: %v", err)
	}
	tls, ok := reloaded.Outbound["tls"].(map[string]any)
	if !ok {
		t.Fatalf("expected a tls block to be written, got %v", reloaded.Outbound["tls"])
	}
	if tls["pinned_cert_sha256"] != wantHash {
		t.Errorf("expected pinned_cert_sha256 %q, got %v", wantHash, tls["pinned_cert_sha256"])
	}
	if _, present := tls["insecure"]; present {
		t.Errorf("expected no plain \"insecure\" field for a VLESS profile (Xray-core rejects it), got %v", tls)
	}
	if tls["enabled"] != true {
		t.Errorf("expected tls.enabled=true, got %v", tls["enabled"])
	}

	// Toggling off must clear the pin, not just leave it stale alongside a
	// reverted "insecure" flag that was never set for VLESS in the first
	// place.
	if err := SetTLSInsecure(reloaded, false); err != nil {
		t.Fatalf("SetTLSInsecure(off): %v", err)
	}
	final, err := Find("vlesspin")
	if err != nil {
		t.Fatalf("Find after unset: %v", err)
	}
	finalTLS, _ := final.Outbound["tls"].(map[string]any)
	if _, present := finalTLS["pinned_cert_sha256"]; present {
		t.Errorf("expected pinned_cert_sha256 cleared after toggling off, got %v", finalTLS)
	}
}

// TestSetTLSInsecureRejectsRealityProfile confirms Reality profiles are
// explicitly rejected rather than silently dialing a server whose
// authentication doesn't even work via certificate trust in the first
// place (Reality authenticates via its own public/private keypair scheme
// against a decoy site's real, already-trusted certificate) — "insecure"
// has nothing meaningful to do there, and blindly attempting the fetch
// would either hang against a real Reality-fronted server or succeed
// against the wrong thing entirely (the decoy site's own cert, not
// anything the VLESS connection itself authenticates against).
func TestSetTLSInsecureRejectsRealityProfile(t *testing.T) {
	withTempHome(t)
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := Dir()
	writeFile(t, filepath.Join(base, "proxy", "reality.json"),
		`{"type":"vless","server":"1.2.3.4","server_port":443,"uuid":"z","tls":{"enabled":true,"reality":{"enabled":true,"public_key":"pk","short_id":"sid"}}}`)

	p, err := Find("reality")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if err := SetTLSInsecure(p, true); err == nil {
		t.Fatal("expected an error toggling insecure on a Reality profile")
	}
}

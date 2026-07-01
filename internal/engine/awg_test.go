package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

const sampleAmneziaConf = `[Interface]
PrivateKey = 4NnCLYNWjEcv92rIWv+I7lIcNyBP7sJ1kJIiSNlDKUY=
Address = 10.8.1.2/24
DNS = 1.1.1.1
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 116
S2 = 88
H1 = 1573362613
H2 = 1573362614
H3 = 1573362615
H4 = 1573362616

[Peer]
PublicKey = xTIBAgDzhNUlSg5tXTV9uKQfQx0zR9d29XChm/kAyk8=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestRewriteEndpointPreservesObfuscationFields(t *testing.T) {
	out, err := rewriteEndpoint(sampleAmneziaConf, "185.130.44.10", 51821)
	if err != nil {
		t.Fatalf("rewriteEndpoint: %v", err)
	}

	if !strings.Contains(out, "Endpoint = 185.130.44.10:51821") {
		t.Errorf("expected rewritten Endpoint line, got:\n%s", out)
	}
	if strings.Contains(out, "vpn.example.com") {
		t.Errorf("original hostname should have been replaced, got:\n%s", out)
	}
	for _, field := range []string{"Jc = 5", "Jmin = 50", "Jmax = 1000", "S1 = 116", "H4 = 1573362616"} {
		if !strings.Contains(out, field) {
			t.Errorf("expected obfuscation field %q to survive rewrite, got:\n%s", field, out)
		}
	}
	if strings.Contains(out, "DNS") {
		t.Errorf("expected DNS line to be dropped so awg-quick never calls resolvconf, got:\n%s", out)
	}
}

func TestRewriteEndpointErrorsWithoutPeerSection(t *testing.T) {
	_, err := rewriteEndpoint("[Interface]\nPrivateKey = x\n", "1.2.3.4", 51820)
	if err == nil {
		t.Fatal("expected error when there is no Endpoint line to rewrite")
	}
}

func TestAWGQuickBinaryDoesNotUseWGQuickForAmneziaWG(t *testing.T) {
	dir := t.TempDir()
	wgQuick := filepath.Join(dir, "wg-quick")
	if err := os.WriteFile(wgQuick, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	got, err := awgQuickBinary(profile.KindWireGuard)
	if err != nil {
		t.Fatalf("plain WireGuard should fall back to wg-quick: %v", err)
	}
	if got != "wg-quick" {
		t.Fatalf("expected wg-quick fallback, got %q", got)
	}

	if _, err := awgQuickBinary(profile.KindAmneziaWG); err == nil {
		t.Fatal("expected AmneziaWG to require awg-quick instead of falling back to wg-quick")
	}
}

package engine

import (
	"strings"
	"testing"
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
}

func TestRewriteEndpointErrorsWithoutPeerSection(t *testing.T) {
	_, err := rewriteEndpoint("[Interface]\nPrivateKey = x\n", "1.2.3.4", 51820)
	if err == nil {
		t.Fatal("expected error when there is no Endpoint line to rewrite")
	}
}

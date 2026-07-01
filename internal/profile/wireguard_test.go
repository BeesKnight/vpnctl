package profile

import "testing"

const amneziaConf = `[Interface]
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
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeQnjU=
Endpoint = 185.130.44.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

const plainWGConf = `[Interface]
PrivateKey = 6NnCLYNWjEcv92rIWv+I7lIcNyBP7sJ1kJIiSNlDKUY=
Address = 10.8.2.2/24

[Peer]
PublicKey = yTIBAgDzhNUlSg5tXTV9uKQfQx0zR9d29XChm/kAyk8=
Endpoint = 88.99.10.20:51821
AllowedIPs = 0.0.0.0/0, ::/0
`

func TestParseWireGuardDetectsAmneziaObfuscation(t *testing.T) {
	cfg, err := ParseWireGuard(amneziaConf)
	if err != nil {
		t.Fatalf("ParseWireGuard: %v", err)
	}
	if cfg.Kind() != KindAmneziaWG {
		t.Errorf("expected AmneziaWG detection due to Jc/Jmin/etc fields, got %s", cfg.Kind())
	}
	if cfg.Interface["Jc"] != "5" || cfg.Interface["S1"] != "116" || cfg.Interface["H4"] != "1573362616" {
		t.Errorf("expected all obfuscation fields parsed, got %+v", cfg.Interface)
	}
	if cfg.Peer.Host() != "185.130.44.10" {
		t.Errorf("expected host 185.130.44.10, got %s", cfg.Peer.Host())
	}
	if cfg.Peer.PortNum() != 51820 {
		t.Errorf("expected port 51820, got %d", cfg.Peer.PortNum())
	}
}

func TestParseWireGuardPlainConfigIsNotAmnezia(t *testing.T) {
	cfg, err := ParseWireGuard(plainWGConf)
	if err != nil {
		t.Fatalf("ParseWireGuard: %v", err)
	}
	if cfg.Kind() != KindWireGuard {
		t.Errorf("expected plain WireGuard, got %s", cfg.Kind())
	}
}

func TestParseWireGuardRejectsMissingPeer(t *testing.T) {
	_, err := ParseWireGuard("[Interface]\nPrivateKey = x\n")
	if err == nil {
		t.Fatal("expected error for missing [Peer] section")
	}
}

func TestParseWireGuardRejectsMissingEndpoint(t *testing.T) {
	_, err := ParseWireGuard("[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = y\n")
	if err == nil {
		t.Fatal("expected error for [Peer] section missing Endpoint")
	}
}

func TestDNSServersParsesCommaSeparatedIPs(t *testing.T) {
	cfg, err := ParseWireGuard("[Interface]\nPrivateKey = x\nDNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\n")
	if err != nil {
		t.Fatalf("ParseWireGuard: %v", err)
	}
	got := cfg.DNSServers()
	want := []string{"1.1.1.1", "8.8.8.8"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestDNSServersSkipsNonIPEntries(t *testing.T) {
	cfg, err := ParseWireGuard("[Interface]\nPrivateKey = x\nDNS = 1.1.1.1, mydomain.local\n\n[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\n")
	if err != nil {
		t.Fatalf("ParseWireGuard: %v", err)
	}
	got := cfg.DNSServers()
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("expected only the valid IP to survive, got %v", got)
	}
}

func TestDNSServersNilWhenAbsent(t *testing.T) {
	cfg, err := ParseWireGuard(plainWGConf)
	if err != nil {
		t.Fatalf("ParseWireGuard: %v", err)
	}
	if got := cfg.DNSServers(); got != nil {
		t.Errorf("expected nil DNS servers for a config without a DNS line, got %v", got)
	}
}

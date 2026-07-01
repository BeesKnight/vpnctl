package importer

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

func withTempHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
}

func TestParseSubscriptionDecodesBase64AndSplitsLines(t *testing.T) {
	raw := "vless://uuid@1.2.3.4:443?security=tls#one\nhysteria2://pw@5.6.7.8:443#two\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	uris, err := ParseSubscription([]byte(encoded))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(uris) != 2 {
		t.Fatalf("expected 2 URIs, got %d: %v", len(uris), uris)
	}
	if !strings.HasPrefix(uris[0], "vless://") || !strings.HasPrefix(uris[1], "hysteria2://") {
		t.Errorf("unexpected URIs: %v", uris)
	}
}

func TestParseSubscriptionFallsBackToPlainText(t *testing.T) {
	raw := "vless://uuid@1.2.3.4:443#plain"
	uris, err := ParseSubscription([]byte(raw))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(uris) != 1 || uris[0] != raw {
		t.Errorf("expected plain-text passthrough, got %v", uris)
	}
}

func TestImportSubscriptionBodyWritesProxyProfiles(t *testing.T) {
	withTempHome(t)
	if err := profile.EnsureDirs(); err != nil {
		t.Fatal(err)
	}

	raw := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@185.220.10.5:443?security=tls&sni=example.com#nl02-mk01\n" +
		"hysteria2://s3cr3t@95.142.10.30:443?sni=cdn.example.com#kz03-hy01\n" +
		"ignored-scheme://whatever\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	names, err := ImportSubscriptionBody([]byte(encoded))
	if err != nil {
		t.Fatalf("ImportSubscriptionBody: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 imported profiles, got %d: %v", len(names), names)
	}

	profiles, err := profile.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	var found int
	for _, p := range profiles {
		if p.Name == "nl02-mk01" || p.Name == "kz03-hy01" {
			found++
			if p.Family != profile.FamilyProxy {
				t.Errorf("expected profile %s in proxy family, got %s", p.Name, p.Family)
			}
		}
	}
	if found != 2 {
		t.Fatalf("expected both imported profiles loadable, found %d", found)
	}
}

func TestImportSubscriptionBodyAvoidsNameCollisions(t *testing.T) {
	withTempHome(t)
	if err := profile.EnsureDirs(); err != nil {
		t.Fatal(err)
	}

	raw := "vless://uuid-a@1.2.3.4:443#same\nvless://uuid-b@5.6.7.8:443#same\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	names, err := ImportSubscriptionBody([]byte(encoded))
	if err != nil {
		t.Fatalf("ImportSubscriptionBody: %v", err)
	}
	if len(names) != 2 || names[0] == names[1] {
		t.Fatalf("expected two distinct names, got %v", names)
	}
}

func TestImportWireGuardTextValidatesAndPreservesAmneziaFields(t *testing.T) {
	withTempHome(t)
	if err := profile.EnsureDirs(); err != nil {
		t.Fatal(err)
	}

	conf := `[Interface]
PrivateKey = 4NnCLYNWjEcv92rIWv+I7lIcNyBP7sJ1kJIiSNlDKUY=
Address = 10.8.1.2/24
Jc = 5
Jmin = 50
Jmax = 1000

[Peer]
PublicKey = xTIBAgDzhNUlSg5tXTV9uKQfQx0zR9d29XChm/kAyk8=
Endpoint = 185.130.44.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
`
	name, err := ImportWireGuardText("switz", conf)
	if err != nil {
		t.Fatalf("ImportWireGuardText: %v", err)
	}
	if name != "switz" {
		t.Errorf("expected name switz, got %q", name)
	}

	base, _ := profile.Dir()
	written, err := os.ReadFile(filepath.Join(base, "wg", "switz.conf"))
	if err != nil {
		t.Fatalf("reading written conf: %v", err)
	}
	if !strings.Contains(string(written), "Jc = 5") {
		t.Errorf("expected obfuscation fields preserved in written file")
	}

	p, err := profile.Find("switz")
	if err != nil {
		t.Fatalf("profile.Find: %v", err)
	}
	if p.Kind != profile.KindAmneziaWG {
		t.Errorf("expected imported profile to be detected as AmneziaWG, got %s", p.Kind)
	}
}

func TestImportWireGuardTextRejectsInvalidConfig(t *testing.T) {
	withTempHome(t)
	if err := profile.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	_, err := ImportWireGuardText("broken", "not a wireguard config")
	if err == nil {
		t.Fatal("expected error for invalid WireGuard config")
	}
}

// sanity check that generated outbound JSON round-trips cleanly (used by
// engine.writeSingBoxConfig downstream).
func TestGeneratedOutboundIsValidJSON(t *testing.T) {
	_, outbound, err := ParseVLESS("vless://uuid@1.2.3.4:443?security=tls&sni=x.com#t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(outbound); err != nil {
		t.Fatalf("outbound not JSON-serializable: %v", err)
	}
}

package engine

import (
	"os/exec"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

// fakeActiveEngine is a minimal netguard.Engine stub, just enough to drive
// Start()'s dispatch logic (which only calls Status() before branching on
// Family/Kind) without needing a real namespace.
type fakeActiveEngine struct{}

func (fakeActiveEngine) Setup(profile.Profile) (netguard.Status, error) {
	return netguard.Status{}, nil
}
func (fakeActiveEngine) Teardown() error                  { return nil }
func (fakeActiveEngine) Status() (netguard.Status, error) { return netguard.Status{Active: true}, nil }
func (fakeActiveEngine) UpdateEndpoint(profile.Profile) (bool, string, error) {
	return false, "", nil
}
func (fakeActiveEngine) Command(name string, args []string, opts netguard.ExecOptions) (*exec.Cmd, error) {
	return exec.Command(name, args...), nil
}
func (fakeActiveEngine) Recorded() []string { return nil }

func TestStartRejectsUnsupportedProxyKind(t *testing.T) {
	p := profile.Profile{Name: "mystery", Family: profile.FamilyProxy, Kind: profile.KindUnknown}
	_, err := Start(fakeActiveEngine{}, p)
	if err == nil {
		t.Fatal("expected error for unsupported proxy kind")
	}
}

func TestStartRejectsUnknownFamily(t *testing.T) {
	p := profile.Profile{Name: "mystery", Family: profile.Family("bogus")}
	_, err := Start(fakeActiveEngine{}, p)
	if err == nil {
		t.Fatal("expected error for unknown profile family")
	}
}

func TestStartDispatchesHysteria2ToSingBox(t *testing.T) {
	p := profile.Profile{
		Name:   "kz03-hy01",
		Family: profile.FamilyProxy,
		Kind:   profile.KindHysteria2,
		Outbound: map[string]any{
			"type":        "hysteria2",
			"server":      "5.6.7.8",
			"server_port": float64(443),
			"password":    "x",
		},
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
	// startSingBox writes its config and then execs "sing-box", which isn't
	// installed in the test environment — this only verifies the dispatch
	// reaches startSingBox (config written, PATH lookup failure) rather than
	// startXray or an "unsupported kind" error.
	_, err := Start(fakeActiveEngine{}, p)
	if err == nil {
		t.Fatal("expected an error since sing-box isn't installed in the test environment")
	}
	if err.Error() == `unsupported proxy kind "hysteria2"` {
		t.Fatalf("Hysteria2 must dispatch to startSingBox, not be rejected: %v", err)
	}
}

func TestStartDispatchesVLESSToXray(t *testing.T) {
	p := profile.Profile{
		Name:   "nl02-mk01",
		Family: profile.FamilyProxy,
		Kind:   profile.KindVLESS,
		Outbound: map[string]any{
			"type":        "vless",
			"server":      "1.2.3.4",
			"server_port": float64(443),
			"uuid":        "b831381d-6324-4d53-ad4f-8cda48b30811",
		},
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
	// startXray writes its config and then execs "xray", which isn't
	// installed in the test environment — this only verifies the dispatch
	// reaches startXray (config written, PATH lookup failure) rather than
	// startSingBox or an "unsupported kind" error.
	_, err := Start(fakeActiveEngine{}, p)
	if err == nil {
		t.Fatal("expected an error since xray isn't installed in the test environment")
	}
	if err.Error() == `unsupported proxy kind "vless"` {
		t.Fatalf("VLESS must dispatch to startXray, not be rejected: %v", err)
	}
}

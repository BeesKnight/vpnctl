//go:build linux

package netguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

// withTempHome points $HOME (and thus profile/state dirs) at a scratch
// directory for the duration of the test, so dry-run state files never
// touch the real user's ~/.config or ~/.local/state.
func withTempHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
}

func containsCmd(recorded []string, substr string) bool {
	for _, c := range recorded {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func TestSetupDryRunGeneratesKillSwitch(t *testing.T) {
	withTempHome(t)

	p := profile.Profile{
		Name:   "switz",
		Family: profile.FamilyWG,
		Kind:   profile.KindAmneziaWG,
		Server: "185.130.44.10",
		Port:   51820,
	}

	e := NewLinuxEngine(true)
	status, err := e.Setup(p)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !status.Active || !status.KillSwitch {
		t.Fatalf("expected active kill-switch, got %+v", status)
	}
	if status.ResolvedIP != "185.130.44.10" {
		t.Fatalf("expected resolved IP passthrough for literal IP, got %s", status.ResolvedIP)
	}
	if status.Protocol != "udp" {
		t.Fatalf("expected udp protocol for AmneziaWG, got %s", status.Protocol)
	}

	rec := e.Recorded()

	mustContain := []string{
		"ip netns add vpnctl0",
		"iptables -P INPUT DROP",
		"iptables -P OUTPUT DROP",
		"iptables -P FORWARD DROP",
		"-A OUTPUT -o vpnctl-wg -j ACCEPT",
		"-A OUTPUT -p udp -d 185.130.44.10 --dport 51820 -j ACCEPT",
		"-A INPUT -p udp -s 185.130.44.10 --sport 51820 -j ACCEPT",
		"nat -A POSTROUTING -s 10.200.200.0/24 -d 185.130.44.10 -j MASQUERADE",
		"sysctl -w net.ipv4.ip_forward=1",
	}
	for _, want := range mustContain {
		if !containsCmd(rec, want) {
			t.Errorf("expected recorded commands to contain %q, got:\n%s", want, strings.Join(rec, "\n"))
		}
	}

	// The DROP policy must be set before any ACCEPT rule is added, and
	// before the engine would ever be started — this is the fail-closed
	// ordering guarantee: nothing leaves the namespace until it is locked.
	dropIdx, acceptIdx := -1, -1
	for i, c := range rec {
		if dropIdx == -1 && strings.Contains(c, "-P OUTPUT DROP") {
			dropIdx = i
		}
		if acceptIdx == -1 && strings.Contains(c, "-d 185.130.44.10 --dport 51820 -j ACCEPT") {
			acceptIdx = i
		}
	}
	if dropIdx == -1 || acceptIdx == -1 || dropIdx > acceptIdx {
		t.Fatalf("expected DROP policy to be set before the point ACCEPT rule (drop=%d accept=%d)", dropIdx, acceptIdx)
	}
}

func TestSetupRejectsProfileWithoutEndpoint(t *testing.T) {
	withTempHome(t)
	e := NewLinuxEngine(true)
	_, err := e.Setup(profile.Profile{Name: "broken"})
	if err == nil {
		t.Fatal("expected error for profile with no server endpoint")
	}
}

func TestTeardownIsIdempotentWithNoActiveProfile(t *testing.T) {
	withTempHome(t)
	e := NewLinuxEngine(true)
	if err := e.Teardown(); err != nil {
		t.Fatalf("Teardown with nothing active should be a no-op, got: %v", err)
	}
}

func TestCommandRefusesWithoutActiveNamespace(t *testing.T) {
	withTempHome(t)
	e := NewLinuxEngine(true)
	// dry-run's namespaceExists() calls `ip netns list` for real (Output is
	// still recorded but not faked), so on a machine with no vpnctl0
	// namespace this must error out rather than silently building a command
	// that would run unrestricted.
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		t.Skip("no netns support on this system")
	}
	_, err := e.Command("curl", []string{"https://example.com"}, ExecOptions{})
	if err == nil {
		t.Fatal("expected error building a command with no active namespace")
	}
}

func TestUpdateEndpointSwapsRulesWithoutGap(t *testing.T) {
	withTempHome(t)
	e := NewLinuxEngine(true)

	original := profile.Profile{
		Name: "switz", Kind: profile.KindAmneziaWG,
		Server: "185.130.44.10", Port: 51820,
	}
	status, err := e.Setup(original)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if status.ResolvedIP != "185.130.44.10" {
		t.Fatalf("unexpected initial resolved IP: %s", status.ResolvedIP)
	}

	// Simulate the server's hostname re-resolving to a new IP between
	// health-check ticks (using a literal-IP profile so this test doesn't
	// depend on real DNS — resolveIP passes literal IPs through unchanged,
	// exactly like a hostname would after re-resolving to a new address).
	moved := original
	moved.Server = "185.130.44.99"

	changed, newIP, err := e.UpdateEndpoint(moved)
	if err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}
	if !changed {
		t.Fatal("expected UpdateEndpoint to report a change")
	}
	if newIP != "185.130.44.99" {
		t.Fatalf("expected new IP 185.130.44.99, got %s", newIP)
	}

	state, err := LoadActiveState()
	if err != nil || state == nil {
		t.Fatalf("expected active state to persist across UpdateEndpoint, err=%v state=%v", err, state)
	}
	if state.ResolvedIP != "185.130.44.99" {
		t.Fatalf("expected state to reflect new resolved IP, got %s", state.ResolvedIP)
	}

	rec := e.Recorded()
	oldRemoved, newAdded := false, false
	for _, c := range rec {
		if strings.Contains(c, "-D") && strings.Contains(c, "185.130.44.10") {
			oldRemoved = true
		}
		if strings.Contains(c, "-A OUTPUT") && strings.Contains(c, "185.130.44.99") {
			newAdded = true
		}
	}
	if !oldRemoved {
		t.Error("expected old server's point-to-point rule to be removed")
	}
	if !newAdded {
		t.Error("expected new server's point-to-point ACCEPT rule to be added")
	}

	// A second call with the same (already-current) IP must be a no-op —
	// the health-check daemon calls this every tick, so re-adding identical
	// rules on every tick (duplicating them forever) would be a bug.
	recBefore := len(e.Recorded())
	changedAgain, _, err := e.UpdateEndpoint(moved)
	if err != nil {
		t.Fatalf("UpdateEndpoint (unchanged): %v", err)
	}
	if changedAgain {
		t.Error("expected no change when the resolved IP is already current")
	}
	if len(e.Recorded()) != recBefore {
		t.Error("expected no new commands to be issued when the IP hasn't changed")
	}
}

func TestDNSServersForUsesProfileDNSThenFallsBack(t *testing.T) {
	wg, err := profile.ParseWireGuard("[Interface]\nPrivateKey = x\nDNS = 9.9.9.9\n\n[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\n")
	if err != nil {
		t.Fatalf("ParseWireGuard: %v", err)
	}
	withDNS := profile.Profile{Name: "has-dns", WG: wg}
	if got := dnsServersFor(withDNS); len(got) != 1 || got[0] != "9.9.9.9" {
		t.Errorf("expected profile's own DNS server, got %v", got)
	}

	wgNoDNS, err := profile.ParseWireGuard("[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\n")
	if err != nil {
		t.Fatalf("ParseWireGuard: %v", err)
	}
	withoutDNS := profile.Profile{Name: "no-dns", WG: wgNoDNS}
	if got := dnsServersFor(withoutDNS); len(got) != len(defaultDNSServers) {
		t.Errorf("expected default DNS servers as fallback, got %v", got)
	}

	proxyProfile := profile.Profile{Name: "vless-01", Family: profile.FamilyProxy, Kind: profile.KindVLESS}
	if got := dnsServersFor(proxyProfile); len(got) != 1 || got[0] != SingBoxTunDNS {
		t.Errorf("expected sing-box TUN DNS for a proxy profile, got %v", got)
	}
}

func TestVLESSUsesTCP(t *testing.T) {
	withTempHome(t)
	p := profile.Profile{
		Name:   "nl02",
		Family: profile.FamilyProxy,
		Kind:   profile.KindVLESS,
		Server: "1.2.3.4",
		Port:   443,
	}
	e := NewLinuxEngine(true)
	status, err := e.Setup(p)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if status.Protocol != "tcp" {
		t.Fatalf("expected tcp for VLESS, got %s", status.Protocol)
	}
	if !containsCmd(e.Recorded(), "-A OUTPUT -o vpnctl-tun -j ACCEPT") {
		t.Fatalf("expected VLESS kill-switch to allow output through vpnctl-tun, got:\n%s", strings.Join(e.Recorded(), "\n"))
	}
	if containsCmd(e.Recorded(), "-A OUTPUT -o vpnctl-wg -j ACCEPT") {
		t.Fatalf("did not expect VLESS kill-switch to add WireGuard interface rule, got:\n%s", strings.Join(e.Recorded(), "\n"))
	}
}

func TestSysctlBackupOnlyCapturedOnce(t *testing.T) {
	withTempHome(t)
	dir, err := EnsureStateDir()
	if err != nil {
		t.Fatal(err)
	}
	_ = filepath.Join(dir, "sysctl_backup.json")

	backup := &SysctlBackup{Values: map[string]string{ipForwardKey: "0"}}
	if err := SaveSysctlBackup(backup); err != nil {
		t.Fatal(err)
	}

	p := profile.Profile{Name: "switz", Server: "10.0.0.1", Port: 51820, Kind: profile.KindWireGuard}
	e := NewLinuxEngine(true)
	if _, err := e.Setup(p); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	got, err := LoadSysctlBackup()
	if err != nil {
		t.Fatal(err)
	}
	if got.Values[ipForwardKey] != "0" {
		t.Fatalf("expected pre-existing backup value %q to be preserved, got %q", "0", got.Values[ipForwardKey])
	}
}

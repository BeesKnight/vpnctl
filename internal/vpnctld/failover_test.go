package vpnctld

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// TestAutoFailoverSwitchesToBackupOnSustainedUnhealth exercises the whole
// failover path end to end: activate a profile with a configured backup,
// let its health check observe sustained unhealth (fakeSucceedingEngine's
// Command always runs "true", so `wg show ... latest-handshakes` never
// reports a real handshake — see wgHandshakeHealthy — making a WG-family
// profile activated against it permanently "unhealthy" from the very
// first tick, which is exactly the condition this test needs), and
// confirm the daemon switches over to the backup on its own.
func TestAutoFailoverSwitchesToBackupOnSustainedUnhealth(t *testing.T) {
	t.Setenv("VPNCTL_HEALTHCHECK_INTERVAL", "1") // seconds — keep the test fast; failoverThreshold=2 ticks

	// homeDirForUID is overridden (not $HOME) because triggerFailover
	// resolves the activating peer's home directory via a real uid lookup
	// (os/user.LookupId), which this test's own process uid can't be
	// pointed at a temp directory for — see failover.go's doc comment on
	// this var.
	failoverHome := t.TempDir()
	origHomeDirForUID := homeDirForUID
	homeDirForUID = func(uint32) (string, error) { return failoverHome, nil }
	t.Cleanup(func() { homeDirForUID = origHomeDirForUID })

	wgDir := filepath.Join(failoverHome, ".config", "vpnctl", "profiles", "wg")
	if err := os.MkdirAll(wgDir, 0o755); err != nil {
		t.Fatalf("creating backup profile dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wgDir, "backup.conf"), []byte(testWGConf), 0o600); err != nil {
		t.Fatalf("writing backup profile: %v", err)
	}
	// Confirm profile.FindInDir can actually see it before trusting the
	// daemon to — a failure here means the test fixture is wrong, not the
	// failover logic.
	if _, err := profile.FindInDir(filepath.Join(failoverHome, ".config", "vpnctl", "profiles"), "backup"); err != nil {
		t.Fatalf("test fixture: backup profile not resolvable: %v", err)
	}

	sock := startTestServer(t)

	activateResp := call(t, sock, rpc.MethodActivate, rpc.ActivateParams{
		Name: "primary", Kind: string(profile.KindWireGuard), Family: string(profile.FamilyWG),
		WGRaw: testWGConf, Backup: "backup",
	})
	if activateResp.Error != "" {
		t.Fatalf("Activate: %s", activateResp.Error)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		statusResp := call(t, sock, rpc.MethodStatus, nil)
		if statusResp.Error == "" {
			var status rpc.StatusResult
			if err := json.Unmarshal(statusResp.Result, &status); err == nil {
				if status.Status.Active && status.Status.ProfileName == "backup" {
					return // failover happened
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("timed out waiting for auto-failover to switch the active profile to \"backup\"")
}

// TestNoFailoverWithoutBackupConfigured confirms staying unhealthy
// indefinitely is a no-op when Backup isn't set — auto-failover must be
// strictly opt-in per profile, never a surprise behavior change for
// existing profiles with no `backup:` in their meta.yaml.
func TestNoFailoverWithoutBackupConfigured(t *testing.T) {
	t.Setenv("VPNCTL_HEALTHCHECK_INTERVAL", "1")
	sock := startTestServer(t)

	activateResp := call(t, sock, rpc.MethodActivate, rpc.ActivateParams{
		Name: "solo", Kind: string(profile.KindWireGuard), Family: string(profile.FamilyWG), WGRaw: testWGConf,
	})
	if activateResp.Error != "" {
		t.Fatalf("Activate: %s", activateResp.Error)
	}

	// Give it several unhealthy ticks — well past failoverThreshold — and
	// confirm it's still "solo", not torn down or switched to anything.
	time.Sleep(3500 * time.Millisecond)

	statusResp := call(t, sock, rpc.MethodStatus, nil)
	if statusResp.Error != "" {
		t.Fatalf("Status: %s", statusResp.Error)
	}
	var status rpc.StatusResult
	if err := json.Unmarshal(statusResp.Result, &status); err != nil {
		t.Fatalf("unmarshaling StatusResult: %v", err)
	}
	if !status.Status.Active || status.Status.ProfileName != "solo" {
		t.Errorf("expected profile %q to still be active with no backup configured, got %+v", "solo", status.Status)
	}
}

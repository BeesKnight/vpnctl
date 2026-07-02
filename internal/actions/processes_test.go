package actions

import (
	"os"
	"testing"
)

// TestTerminateReportsPermissionErrorRatherThanSilentSuccess is the
// regression test for a real bug found while testing `vpnctl kill` on a
// live stand: killing a process this caller has no permission to signal
// (e.g. a `vpnctl run --` CLI process still running as root, since cmdKill
// unlike cmdRun doesn't require root) must not be reported as a successful
// kill. Before the fix, signal-0's EPERM was treated identically to ESRCH
// ("already gone"), so KillProcess silently dropped the process from
// tracking without ever touching it — orphaning it.
func TestTerminateReportsPermissionErrorRatherThanSilentSuccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: signal 0 to pid 1 would succeed, defeating this test")
	}

	err := terminate(1) // pid 1 (init/systemd) always exists, never ours to signal
	if err == nil {
		t.Fatal("expected terminate(1) to report a permission error, got nil (silently claimed success)")
	}
}

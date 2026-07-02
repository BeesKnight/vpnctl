package vpnctld

import (
	"context"
	"errors"
	"log"
	"os"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

// fakeFailingStopHandle is an engine.Handle whose Stop() always fails,
// simulating the real failure this test guards against: a child process
// (e.g. `awg-quick down`) getting killed mid-execution — found on a live
// stand when systemd's default KillMode=control-group SIGTERMed the
// daemon's in-flight teardown child during `systemctl stop`.
type fakeFailingStopHandle struct{}

func (fakeFailingStopHandle) Healthy() (bool, error) { return true, nil }
func (fakeFailingStopHandle) Stop() error            { return errors.New("simulated: child killed mid-teardown") }
func (fakeFailingStopHandle) LogPath() string        { return "" }
func (fakeFailingStopHandle) PID() int               { return 0 }
func (fakeFailingStopHandle) HelperPID() int         { return 0 }
func (fakeFailingStopHandle) Kind() string           { return "fake" }

// TestDeactivateTearsDownEvenWhenEngineStopFails is the regression test for
// the live-stand finding: Teardown (namespace/kill-switch removal) must run
// even when handle.Stop() fails, or a transient engine-stop failure leaves
// the namespace orphaned exactly like the A1 bug — see
// deactivateLocked's doc comment.
func TestDeactivateTearsDownEvenWhenEngineStopFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")

	ng := &fakeSucceedingEngine{}
	srv := NewWithEngine(ng, log.New(os.Stderr, "", 0))

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.active = &activeState{
		profile:    profile.Profile{Name: "switz"},
		handle:     fakeFailingStopHandle{},
		healthStop: cancel,
	}
	ng.mu.Lock()
	ng.active = true
	ng.mu.Unlock()

	err := srv.deactivateLocked()
	if err == nil {
		t.Fatal("expected deactivateLocked to surface the Stop error")
	}

	status, statusErr := ng.Status()
	if statusErr != nil {
		t.Fatalf("Status: %v", statusErr)
	}
	if status.Active {
		t.Error("expected Teardown to have run (engine inactive) even though Stop failed")
	}
	if srv.active != nil {
		t.Error("expected s.active to be cleared even though Stop failed")
	}
}

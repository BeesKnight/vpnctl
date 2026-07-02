package vpnctlclient

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/rpc"
	"github.com/BeesKnight/vpnctl/internal/vpnctld"
)

// realExecEngine lets Activate's own engine-startup command (wg-quick,
// which internal/engine/awg.go shells out to directly, not just through
// this Command() seam) succeed trivially without a real wg-quick binary or
// namespace, while still actually running whatever Exec asks it to run —
// Exec's whole point is streaming real process I/O, so tests need a real
// command for that part, but Activate needs to succeed first to have an
// active profile to Exec against at all.
type realExecEngine struct{ active bool }

func (e *realExecEngine) Setup(p profile.Profile) (netguard.Status, error) {
	e.active = true
	return netguard.Status{ProfileName: p.Name}, nil
}
func (e *realExecEngine) Teardown() error { e.active = false; return nil }
func (e *realExecEngine) Status() (netguard.Status, error) {
	return netguard.Status{Active: e.active}, nil
}
func (e *realExecEngine) UpdateEndpoint(profile.Profile) (bool, string, error) {
	return false, "", nil
}
func (e *realExecEngine) Command(name string, args []string, opts netguard.ExecOptions) (*exec.Cmd, error) {
	switch name {
	case "awg-quick", "wg-quick", "wg", "awg":
		return exec.Command("true"), nil
	default:
		return exec.Command(name, args...), nil
	}
}
func (e *realExecEngine) Recorded() []string { return nil }

// startExecTestDaemon starts a real vpnctld backed by realExecEngine and
// activates a profile through the normal client Activate RPC (rather than
// reaching into the daemon's internals), then points $VPNCTL_SOCKET at it
// — Exec refuses to run anything without an active profile, same as the
// real daemon.
func startExecTestDaemon(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
	if err := profile.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := profile.Dir()
	path := filepath.Join(base, "wg", "switz.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(testWGConf), 0o644); err != nil {
		t.Fatal(err)
	}

	sockPath := filepath.Join(t.TempDir(), "vpnctld.sock")
	t.Setenv("VPNCTL_SOCKET", sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	srv := vpnctld.NewWithEngine(&realExecEngine{}, log.New(io.Discard, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	if _, _, err := Activate("switz"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
}

func TestExecCLIModeRoundTrip(t *testing.T) {
	startExecTestDaemon(t)

	var stdout bytes.Buffer
	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(&stdout, r)
	}()

	result, err := Exec(rpc.ExecModeCLI, []string{"echo", "hello from exec"}, ExecOptions{})

	w.Close()
	os.Stdout = origStdout
	<-done

	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if result.PID == 0 {
		t.Error("expected a nonzero PID")
	}
	if got := stdout.String(); got != "hello from exec\n" {
		t.Errorf("expected %q, got %q", "hello from exec\n", got)
	}
}

func TestExecGUIModeReturnsImmediately(t *testing.T) {
	startExecTestDaemon(t)

	result, err := Exec(rpc.ExecModeGUI, []string{"sleep", "0.1"}, ExecOptions{})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.PID == 0 {
		t.Error("expected a nonzero PID")
	}
}

func TestExecEmptyArgvIsRejectedLocally(t *testing.T) {
	// No daemon started — if this doesn't fail before dialing, the test
	// would hang/timeout instead of failing fast.
	t.Setenv("VPNCTL_SOCKET", filepath.Join(t.TempDir(), "unused.sock"))
	if _, err := Exec(rpc.ExecModeCLI, nil, ExecOptions{}); err == nil {
		t.Fatal("expected an error for an empty argv")
	}
}

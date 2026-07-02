// Package run implements the three ways vpnctl launches a program through
// the active profile (the core of the product): blocking CLI
// commands with real stdio streaming, full terminal-takeover TUI programs,
// and detached GUI applications with desktop-session environment
// passthrough and privilege dropping.
package run

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// Type identifies how a launched program should be run.
type Type string

const (
	TypeCLI Type = "cli"
	TypeGUI Type = "gui"
)

// CLI runs argv inside the active namespace, connecting stdin/stdout/stderr
// directly (real streaming — progress bars, live output — not buffered),
// and returns its exit code. The process is tracked for the duration of the
// call so `vpnctl ps`/the "atomic switch" guard can see it.
//
// Still used by internal/actions.TestConnectivity (the file-backed model
// the TUI still runs on — see DAEMON_MIGRATION.md); `vpnctl run` itself
// moved to vpnctlclient.Exec, which allocates a real PTY server-side for
// `--tui` instead of directly inheriting a terminal fd the way this
// function does, since a detached daemon has no terminal of its own to
// inherit from. That's also why there's no TUI() here anymore.
func CLI(ng netguard.Engine, argv []string) (int, error) {
	return foreground(ng, argv, TypeCLI)
}

func foreground(ng netguard.Engine, argv []string, kind Type) (int, error) {
	if len(argv) == 0 {
		return 1, fmt.Errorf("no command given")
	}
	cmd, err := ng.Command(argv[0], argv[1:], netguard.ExecOptions{})
	if err != nil {
		return 1, err
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("starting %v: %w", argv, err)
	}

	pi := netguard.ProcessInfo{
		PID:       cmd.Process.Pid,
		Name:      argv[0],
		Type:      string(kind),
		Command:   argv,
		StartedAt: time.Now(),
	}
	_ = netguard.AddProcess(pi)
	defer func() { _ = netguard.RemoveProcess(pi.PID) }()

	err = cmd.Wait()
	return exitCodeOf(cmd, err), unwrapExitError(err)
}

// GUI launches argv detached from the current terminal/process — vpnctl
// does not wait for it, so the caller (CLI or TUI) continues immediately.
// The process runs as the real desktop user (never root),
// with DISPLAY/WAYLAND_DISPLAY/XAUTHORITY/DBUS_SESSION_BUS_ADDRESS/
// PULSE_SERVER passed through from the real user's session, and
// HOME/USER/LOGNAME set to that user's own account so profile-based apps
// (Firefox, Tor Browser) find their profile instead of failing to load one.
func GUI(ng netguard.Engine, argv []string) (int, error) {
	if len(argv) == 0 {
		return 0, fmt.Errorf("no command given")
	}

	uid, gid, err := sysuser.RealUIDGID()
	if err != nil {
		return 0, fmt.Errorf("resolving real user for privilege drop: %w", err)
	}

	cmd, err := ng.Command(argv[0], argv[1:], netguard.ExecOptions{
		Env:       ResolveGUIEnv(uid),
		DropToUID: &uid,
		DropToGID: &gid,
	})
	if err != nil {
		return 0, err
	}
	// Detached: no controlling terminal, doesn't hold vpnctl's stdio open.
	cmd.Stdin = nil
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		cmd.Stdout = devnull
		cmd.Stderr = devnull
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting %v: %w", argv, err)
	}

	pi := netguard.ProcessInfo{
		PID:       cmd.Process.Pid,
		Name:      argv[0],
		Type:      string(TypeGUI),
		Command:   argv,
		StartedAt: time.Now(),
	}
	_ = netguard.AddProcess(pi)
	// Deliberately not waited on: vpnctl's own process exits right after
	// this returns, orphaning the child to init, which reaps it — that's
	// what "detached, vpnctl doesn't block" means in practice.

	return cmd.Process.Pid, nil
}

func exitCodeOf(cmd *exec.Cmd, err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}

// unwrapExitError returns nil for a plain nonzero exit (that's not a vpnctl
// failure, it's the launched program's own exit code — the caller should
// propagate it via os.Exit, not print an error).
func unwrapExitError(err error) error {
	if _, ok := err.(*exec.ExitError); ok {
		return nil
	}
	return err
}

package actions

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/BeesKnight/vpnctl/internal/netguard"
)

// ListProcesses returns everything tracked as launched through the active
// profile (vpnctl run / run --tui / run --gui, or an app started from the
// TUI's Apps panel) — the data behind `vpnctl ps` and the TUI's processes
func ListProcesses() ([]netguard.ProcessInfo, error) {
	state, err := netguard.LoadActiveState()
	if err != nil || state == nil {
		return nil, err
	}
	return state.Processes, nil
}

// KillProcess finds a tracked process by PID or exact name and terminates
// it (SIGTERM, escalating to SIGKILL after 3s) — without touching the
// tunnel engine or any other tracked process, and never touching an
// untracked process that merely happens to share a name.
func KillProcess(target string) (netguard.ProcessInfo, error) {
	state, err := netguard.LoadActiveState()
	if err != nil {
		return netguard.ProcessInfo{}, err
	}
	if state == nil {
		return netguard.ProcessInfo{}, fmt.Errorf("no active profile")
	}

	found := findProcess(state.Processes, target)
	if found == nil {
		return netguard.ProcessInfo{}, fmt.Errorf("no tracked process matches %q", target)
	}

	pi := *found
	if err := terminate(pi.PID); err != nil {
		return pi, err
	}
	_ = netguard.RemoveProcess(pi.PID)
	return pi, nil
}

func findProcess(procs []netguard.ProcessInfo, target string) *netguard.ProcessInfo {
	if pid, err := strconv.Atoi(target); err == nil {
		for i := range procs {
			if procs[i].PID == pid {
				return &procs[i]
			}
		}
	}
	for i := range procs {
		if procs[i].Name == target {
			return &procs[i]
		}
	}
	return nil
}

// stillAlive probes pid with signal 0 (sends no actual signal, just checks
// deliverability). Critically, this distinguishes "the process is gone"
// (ESRCH) from "the process exists but this caller can't signal it" (EPERM,
// e.g. a `vpnctl run --` CLI process still running as root while `vpnctl
// kill` itself runs unprivileged, which cmdKill unlike cmdRun doesn't
// require — see internal/run.CLI, which never drops privileges the way
// GUI() does). Treating EPERM as "already gone" would make KillProcess
// silently report success and drop the process from active.json's tracking
// without ever having signaled it — orphaning it exactly like the teardown
// bugs this tool otherwise guards against.
func stillAlive(proc *os.Process) bool {
	err := proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

func terminate(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if !stillAlive(proc) {
		return nil // already gone
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("no permission to signal pid %d (it may still be running as root — try again with sudo)", pid)
		}
		return nil // ESRCH etc: gone by the time we got here
	}
	for i := 0; i < 30; i++ {
		if !stillAlive(proc) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("no permission to signal pid %d (it may still be running as root — try again with sudo)", pid)
		}
		return nil
	}
	return nil
}

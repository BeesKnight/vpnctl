package actions

import (
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
// panel (spec §3.4.5).
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

func terminate(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if proc.Signal(syscall.Signal(0)) != nil {
		return nil // already gone
	}
	_ = proc.Signal(syscall.SIGTERM)
	for i := 0; i < 30; i++ {
		if proc.Signal(syscall.Signal(0)) != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return proc.Signal(syscall.SIGKILL)
}

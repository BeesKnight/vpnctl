package engine

import (
	"os"
	"syscall"
	"time"
)

func pidAlive(pid int) bool {
	if pid == 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// stopByPID gracefully terminates a detached process by PID alone (no
// in-memory *exec.Cmd survives across process invocations), escalating to
// SIGKILL if it doesn't exit promptly.
func stopByPID(pid int) error {
	if pid == 0 {
		return nil
	}
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

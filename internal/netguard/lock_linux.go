//go:build linux

package netguard

import (
	"os"
	"syscall"
)

// flockExclusive and funlock back withStateLock's cross-process mutual
// exclusion with a real advisory file lock (flock(2)), so a concurrent
// vpnctl invocation and the detached health-check daemon (see
// internal/healthcheck) block on each other rather than racing to
// read-modify-write the same active.json.
func flockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func funlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

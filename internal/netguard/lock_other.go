//go:build !linux

package netguard

import (
	"os"
	"sync"
)

// flockExclusive/funlock on non-Linux platforms (placeholder for a future
// Windows port, matching internal/run/guienv_other.go's approach): there is
// no flock(2) here, so this only serializes within this one process via an
// in-memory mutex. That's strictly weaker than the Linux implementation
// (it can't stop a second OS process from racing), but there is no second
// netguard.Engine implementation on non-Linux platforms yet for that to
// matter in practice.
var fallbackLockMu sync.Mutex

func flockExclusive(f *os.File) error {
	fallbackLockMu.Lock()
	return nil
}

func funlock(f *os.File) error {
	fallbackLockMu.Unlock()
	return nil
}

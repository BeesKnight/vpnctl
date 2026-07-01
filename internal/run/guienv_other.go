//go:build !linux

package run

import "os"

// resolveGUIEnv on non-Linux platforms (placeholder for a future Windows
// port) just forwards whatever the current process already
// has; there is no /proc to scan and no X11/Wayland session model to borrow
// from.
func resolveGUIEnv(uid int) []string {
	return os.Environ()
}

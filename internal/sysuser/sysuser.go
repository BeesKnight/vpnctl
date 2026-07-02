// Package sysuser resolves the "real" invoking user even when vpnctl is
// running under sudo, since the network/kill-switch operations require root
// but config, state, and GUI passthrough must all target the human at the
// desktop, not root's own account.
package sysuser

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Real returns the invoking user's account. If running under sudo, this is
// the user who ran `sudo` (from $SUDO_USER), not root.
func Real() (*user.User, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			return u, nil
		}
	}
	return user.Current()
}

// RealHome returns the invoking (real, non-root-under-sudo) user's home
// directory.
//
// $VPNCTL_STATE_HOME, if set, wins outright: it lets a caller that already
// knows the right directory (packaging/prerm, which found active.json by
// walking /home/*/.local/state/vpnctl and /root/.local/state/vpnctl itself)
// hand it over explicitly rather than trust this package to re-derive it.
// This matters because dpkg runs maintainer scripts as root with a stripped,
// non-interactive environment — $SUDO_USER lookup or $HOME can silently
// resolve to the wrong account there, which previously made `vpnctl down`
// find no active.json, exit 0, and leave the engine process/namespace
// running (see packaging/prerm).
//
// Otherwise, under sudo, $HOME is often left as root's (or unset), so this
// looks up $SUDO_USER's home directly via the password database. Failing
// that it defers to os.UserHomeDir(), which honors $HOME like every other
// Unix tool (and is what makes this overridable in tests).
func RealHome() (string, error) {
	if home := os.Getenv("VPNCTL_STATE_HOME"); home != "" {
		return home, nil
	}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}

// RealUIDGID returns the invoking user's numeric uid/gid, used to drop
// privileges before exec'ing GUI applications so they never run as root.
func RealUIDGID() (uid, gid int, err error) {
	u, err := Real()
	if err != nil {
		return 0, 0, err
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing uid %q: %w", u.Uid, err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing gid %q: %w", u.Gid, err)
	}
	return uid, gid, nil
}

// IsRoot reports whether the process is currently running as root
// (typically true for all of vpnctl's network-affecting subcommands).
func IsRoot() bool {
	return os.Geteuid() == 0
}

// RanViaSudo reports whether root privileges came from `sudo` (as opposed to
// e.g. being logged in as root directly), i.e. whether $SUDO_USER is set.
func RanViaSudo() bool {
	return os.Getenv("SUDO_USER") != ""
}

// ChownToRealUserIfRoot chowns the given paths to the real invoking user
// when running as root under sudo. No-op otherwise (e.g. when the real
// user's own process created them, or when running as root directly with
// no $SUDO_USER to attribute ownership to).
func ChownToRealUserIfRoot(paths ...string) error {
	if !IsRoot() || !RanViaSudo() {
		return nil
	}
	uid, gid, err := RealUIDGID()
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", p, err)
		}
	}
	return nil
}

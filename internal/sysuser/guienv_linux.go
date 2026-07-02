//go:build linux

package sysuser

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// guiEnvKeys are the desktop-session environment variables a GUI program
// needs to find the display/audio/session bus. X11/Wayland
// sockets are UNIX domain sockets, not network sockets, so the namespace's
// kill-switch never blocks them by itself — but the launched process still
// needs these variables explicitly, since it's exec'd via nsenter as a
// detached child, not inherited from an interactive desktop shell.
var guiEnvKeys = []string{
	"DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
	"DBUS_SESSION_BUS_ADDRESS", "PULSE_SERVER",
}

// ResolveGUIEnv gathers those variables for the real (non-root) user vpnctl
// is acting on behalf of. vpnctl normally runs under `sudo`, which — unless
// invoked with `sudo -E` or explicit env_keep — strips exactly these
// variables before vpnctl ever sees them (this is the "не полагаться на
// sudo -u user без --preserve-env" warning from the spec). So rather than
// trusting the current process's own environment, this scans /proc for a
// process already owned by the target uid that has DISPLAY or
// WAYLAND_DISPLAY set — typically the user's X/Wayland session or desktop
// shell — and borrows its environment. Falls back to the current process's
// environment, then to conventional single-seat-desktop defaults.
//
// Exported: cmd/vpnctl/run.go's `vpnctl run --gui` path and
// internal/tui/appsview.go's GUI-app launch path both need the exact same
// resolution when building rpc.ExecParams.Env, since the daemon has no
// desktop session of its own to inherit anything from either.
func ResolveGUIEnv(uid int) []string {
	found := scanProcEnvForUser(uid)

	env := map[string]string{}
	for _, k := range guiEnvKeys {
		if v, ok := found[k]; ok && v != "" {
			env[k] = v
		}
	}
	for _, k := range guiEnvKeys {
		if _, ok := env[k]; ok {
			continue
		}
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
	if env["DISPLAY"] == "" && env["WAYLAND_DISPLAY"] == "" {
		env["DISPLAY"] = ":0"
	}
	if env["XDG_RUNTIME_DIR"] == "" {
		env["XDG_RUNTIME_DIR"] = fmt.Sprintf("/run/user/%d", uid)
	}
	if env["DBUS_SESSION_BUS_ADDRESS"] == "" {
		env["DBUS_SESSION_BUS_ADDRESS"] = fmt.Sprintf("unix:path=/run/user/%d/bus", uid)
	}

	// HOME/USER/LOGNAME are looked up authoritatively from the password
	// database rather than scanned from /proc or inherited from the current
	// process, since GUI apps (Firefox, Tor Browser) refuse to start without
	// a real, writable $HOME to load their profile from — and vpnctl's own
	// process environment under sudo has $HOME pointing at root's, not the
	// target uid's.
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		env["HOME"] = u.HomeDir
		env["USER"] = u.Username
		env["LOGNAME"] = u.Username
	}

	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func scanProcEnvForUser(uid int) map[string]string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		info, err := os.Stat("/proc/" + e.Name())
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != uid {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			continue // no permission, or process gone — try the next one
		}
		vars := map[string]string{}
		for _, kv := range strings.Split(string(data), "\x00") {
			if kv == "" {
				continue
			}
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				vars[parts[0]] = parts[1]
			}
		}
		if vars["DISPLAY"] != "" || vars["WAYLAND_DISPLAY"] != "" {
			return vars
		}
	}
	return nil
}

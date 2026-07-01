package netguard

import "time"

// Namespace networking constants, exported so other packages (internal/engine
// building a sing-box config, health-check code, etc.) can address the
// namespace's internal IP without importing anything OS-specific themselves.
const (
	NamespaceIP = "10.200.200.2"
	HostIP      = "10.200.200.1"
)

// Status reports the current state of the network isolation layer.
type Status struct {
	Active       bool      `json:"active"`
	ProfileName  string    `json:"profile_name"`
	ProfileKind  string    `json:"profile_kind"`
	Namespace    string    `json:"namespace"`
	KillSwitch   bool      `json:"kill_switch"`
	ResolvedIP   string    `json:"resolved_ip"`
	ResolvedPort int       `json:"resolved_port"`
	Protocol     string    `json:"protocol"`
	Since        time.Time `json:"since"`
	// EngineHealthy reflects whether the awg-quick/sing-box subprocess for
	// this namespace is still alive. False means "DOWN / NO ROUTE" in the TUI.
	EngineHealthy bool `json:"engine_healthy"`
}

// ExecOptions customizes a command built via Engine.Command.
type ExecOptions struct {
	// Env are additional environment variables appended to the command,
	// e.g. DISPLAY/WAYLAND_DISPLAY/XAUTHORITY/DBUS_SESSION_BUS_ADDRESS for
	// GUI passthrough. The command's own environment (os.Environ, since
	// exec.Command inherits it by default) is not cleared.
	Env []string
	// Dir sets the working directory for the command, if non-empty.
	Dir string
	// DropToUID/DropToGID, if set, make the command run as this uid/gid
	// instead of root once inside the namespace (GUI apps must never run as
	// root). Implemented via nsenter's own --setuid/
	// --setgid, since the namespace join itself still requires root: nsenter
	// does the privileged setns() first, then drops to this uid/gid, then
	// execve()s the target — there is no window where the target runs as root.
	DropToUID *int
	DropToGID *int
}

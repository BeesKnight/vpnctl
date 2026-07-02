package rpc

import "github.com/BeesKnight/vpnctl/internal/netguard"

// Method names, shared verbatim by the daemon's dispatch table and the
// client's call sites so a typo can't silently mismatch the two.
const (
	MethodPing             = "Ping"
	MethodActivate         = "Activate"
	MethodDeactivate       = "Deactivate"
	MethodStatus           = "Status"
	MethodTestConnectivity = "TestConnectivity"
	MethodListProcesses    = "ListProcesses"
	MethodKillProcess      = "KillProcess"
)

// PingResult reports the daemon's own version, for a client that wants to
// confirm it's actually talking to vpnctld (as opposed to the socket
// existing but nothing listening) before issuing a real command.
type PingResult struct {
	Version string `json:"version"`
}

// ActivateParams carries a profile the client has already resolved from
// its own ~/.config/vpnctl/profiles (see internal/profile) — the daemon
// never reads any user's profile files itself, so it works identically
// regardless of which user's profile is being activated. Exactly one of
// WGRaw/Outbound is set, matching profile.Family.
type ActivateParams struct {
	Name     string         `json:"name"`
	Kind     string         `json:"kind"`   // profile.Kind
	Family   string         `json:"family"` // profile.Family
	WGRaw    string         `json:"wg_raw,omitempty"`
	Outbound map[string]any `json:"outbound,omitempty"`
}

// ActivateResult mirrors what actions.Activate returns today (status text
// callers already know how to print), plus enough of the engine handle for
// a client to report success the same way `vpnctl use` does now.
type ActivateResult struct {
	Status     netguard.Status `json:"status"`
	EngineKind string          `json:"engine_kind"`
	EngineLog  string          `json:"engine_log"`
}

// StatusResult is netguard.Status plus the handshake/PID-based health
// check actions.CurrentStatus layers on top of the raw namespace state.
type StatusResult struct {
	Status  netguard.Status `json:"status"`
	Healthy bool            `json:"healthy"`
}

// TestConnectivityResult carries curl's captured output back whole rather
// than streaming it — curl already runs with -s -S (silent, errors only),
// so today's `vpnctl test` has no live progress meter to preserve; a
// single blocking round trip loses nothing users could see before.
type TestConnectivityResult struct {
	ExitCode  int    `json:"exit_code"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Output    string `json:"output"`
}

// ListProcessesResult is empty until `vpnctl run`/the TUI's process
// launchers move behind the daemon (see DAEMON_MIGRATION.md) — process
// tracking has nowhere to be populated from yet, so this always reports no
// processes for now, which is accurate, not a stub bug.
type ListProcessesResult struct {
	Processes []netguard.ProcessInfo `json:"processes"`
}

// KillProcessParams names a tracked process by PID or exact name, same as
// `vpnctl kill <pid|name>` today.
type KillProcessParams struct {
	Target string `json:"target"`
}

type KillProcessResult struct {
	Process netguard.ProcessInfo `json:"process"`
}

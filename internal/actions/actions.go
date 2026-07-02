// Package actions holds the core operations (activate/deactivate a profile,
// test connectivity, report status) shared by both the non-interactive CLI
// (cmd/vpnctl) and the TUI (internal/tui), so the two surfaces can never
// drift apart — every TUI action is backed by the same function a
// corresponding CLI flag calls.
package actions

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BeesKnight/vpnctl/internal/engine"
	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/run"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// engineStartupGrace is how long Activate waits after a persistent
// foreground engine process (sing-box/xray) forks before trusting that it's
// actually up. Decode errors, bind conflicts, and unsupported-transport
// failures typically kill such a process within the first few hundred
// milliseconds — well before a successful fork+exec alone would ever reveal
// that. WireGuard/AmneziaWG has no persistent process to wait on (awg-quick
// configures the interface and exits, and its own exit status is already
// checked in startWireGuard), so it's exempt — see the PID()==0 check below.
const engineStartupGrace = 300 * time.Millisecond

// logTailLines is how many trailing lines of the engine's log get folded
// into an activation-failure error, so the user isn't forced to go `cat` the
// log file themselves to see why the engine died.
const logTailLines = 5

// RequireRoot returns a clear error if vpnctl wasn't invoked with root
// privileges, needed for every network-affecting operation.
func RequireRoot() error {
	if !sysuser.IsRoot() {
		return fmt.Errorf("this command needs root (network namespace/iptables changes) — re-run with sudo")
	}
	return nil
}

// Activate brings up the named profile: kill-switch namespace first, then
// the awg-quick/sing-box engine inside it. Refuses to switch while
// processes are still running through the current profile
// — stop them with `vpnctl kill` first.
func Activate(name string) (profile.Profile, netguard.Status, engine.Handle, error) {
	if err := checkNoRunningProcesses(); err != nil {
		return profile.Profile{}, netguard.Status{}, nil, err
	}

	p, err := profile.Find(name)
	if err != nil {
		return profile.Profile{}, netguard.Status{}, nil, err
	}

	ng := netguard.NewLinuxEngine(false)
	status, err := ng.Setup(p)
	if err != nil {
		return p, netguard.Status{}, nil, fmt.Errorf("setting up kill-switch: %w", err)
	}

	handle, err := engine.Start(ng, p)
	if err != nil {
		_ = ng.Teardown()
		return p, status, nil, fmt.Errorf("starting engine: %w", err)
	}

	// A successful fork+exec only means the process launched, not that it
	// stayed up — give a persistent foreground engine (sing-box/xray) a real
	// chance to crash before reporting the activation a success. Without
	// this, a profile whose engine dies moments after starting (e.g. on an
	// unsupported transport) would still be reported as UP.
	if handle.PID() != 0 {
		time.Sleep(engineStartupGrace)
		if healthy, herr := handle.Healthy(); herr != nil || !healthy {
			_ = handle.Stop()
			_ = ng.Teardown()
			return p, status, nil, fmt.Errorf("engine failed to start (see %s):\n%s", handle.LogPath(), tailLogFile(handle.LogPath(), logTailLines))
		}
	}

	_ = netguard.UpdateActiveState(func(state *netguard.ActiveState) (*netguard.ActiveState, error) {
		if state == nil {
			return nil, nil
		}
		state.EnginePID = handle.PID()
		state.EngineKind = handle.Kind()
		state.EngineLog = handle.LogPath()
		state.HelperPID = handle.HelperPID()
		if pid, err := spawnHealthCheckDaemon(); err == nil {
			state.HealthPID = pid
		}
		return state, nil
	})

	return p, status, handle, nil
}

// tailLogFile returns the last n non-empty-file lines of the file at path,
// for folding straight into an activation-failure error. Best-effort: a
// missing or unreadable log (e.g. the engine died before ever writing one)
// yields an empty string rather than its own error, since the outer error
// already names the log path for the user to check by hand if needed.
func tailLogFile(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func checkNoRunningProcesses() error {
	state, err := netguard.LoadActiveState()
	if err != nil || state == nil {
		return nil
	}
	if len(state.Processes) > 0 {
		return fmt.Errorf("%d process(es) are still running through the active profile %q — stop them (vpnctl kill) before switching", len(state.Processes), state.ProfileName)
	}
	return nil
}

// Deactivate stops the engine and tears down the namespace/kill-switch.
func Deactivate() error {
	ng := netguard.NewLinuxEngine(false)
	if state, err := netguard.LoadActiveState(); err == nil && state != nil {
		if err := engine.Stop(ng, state); err != nil {
			return fmt.Errorf("stopping engine: %w", err)
		}
	}
	return ng.Teardown()
}

// CurrentStatus reports the active profile's namespace status and true
// engine health (handshake-based for WireGuard/AmneziaWG, PID-based for
// sing-box) — the definitive answer for both `vpnctl status` and the TUI's
// status panel.
func CurrentStatus() (netguard.Status, bool, error) {
	ng := netguard.NewLinuxEngine(false)
	status, err := ng.Status()
	if err != nil || !status.Active {
		return status, false, err
	}
	healthy := status.EngineHealthy
	if state, err2 := netguard.LoadActiveState(); err2 == nil && state != nil {
		if h, herr := engine.Healthy(ng, state); herr == nil {
			healthy = h
		}
	}
	return status, healthy, nil
}

// TestResult is the outcome of a connectivity test through the active profile.
type TestResult struct {
	ExitCode int
	Elapsed  time.Duration
}

// TestConnectivity curls an external IP-echo service through the active
// profile (streaming its output directly to stdout via run.CLI), so both
// `vpnctl test` and the TUI's "t" action see identical behavior.
func TestConnectivity() (TestResult, error) {
	ng := netguard.NewLinuxEngine(false)
	status, err := ng.Status()
	if err != nil {
		return TestResult{}, err
	}
	if !status.Active {
		return TestResult{}, fmt.Errorf("no active profile — activate one first")
	}

	curlArgs := []string{"-s", "-S", "--max-time", "10", "-w", "\nhttp_status=%{http_code} time=%{time_total}s\n", "https://ifconfig.me/ip"}

	start := time.Now()
	code, err := run.CLI(ng, append([]string{"curl"}, curlArgs...))
	elapsed := time.Since(start)
	if err != nil {
		return TestResult{}, fmt.Errorf("running curl: %w", err)
	}
	return TestResult{ExitCode: code, Elapsed: elapsed}, nil
}

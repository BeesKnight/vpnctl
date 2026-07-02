package vpnctld

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BeesKnight/vpnctl/internal/engine"
	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// engineStartupGrace/logTailLines/tailLogFile: startup grace period for
// engines with a persistent foreground process, and a small log-tail
// helper for GetLogTail/status reporting.
const (
	engineStartupGrace = 300 * time.Millisecond
	logTailLines       = 5
)

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

// profileFromParams reconstructs a profile.Profile from what the client
// sent, entirely from in-memory data — the daemon never touches any user's
// ~/.config/vpnctl/profiles itself. Re-parsing WGRaw (rather than trusting
// separately-sent Server/Port fields) reuses profile.ParseWireGuard's
// existing validation and keeps this from drifting out of sync with it.
func profileFromParams(p rpc.ActivateParams) (profile.Profile, error) {
	prof := profile.Profile{
		Name:   p.Name,
		Kind:   profile.Kind(p.Kind),
		Family: profile.Family(p.Family),
	}

	switch prof.Family {
	case profile.FamilyWG:
		wg, err := profile.ParseWireGuard(p.WGRaw)
		if err != nil {
			return profile.Profile{}, fmt.Errorf("parsing WireGuard config: %w", err)
		}
		prof.WG = wg
		prof.Server = wg.Peer.Host()
		prof.Port = wg.Peer.PortNum()
	case profile.FamilyProxy:
		if p.Outbound == nil {
			return profile.Profile{}, fmt.Errorf("proxy profile %q has no outbound config", p.Name)
		}
		prof.Outbound = p.Outbound
		prof.Server, _ = p.Outbound["server"].(string)
		switch v := p.Outbound["server_port"].(type) {
		case float64:
			prof.Port = int(v)
		case int:
			prof.Port = v
		}
	default:
		return profile.Profile{}, fmt.Errorf("unknown profile family %q", p.Family)
	}
	return prof, nil
}

func (s *Server) handlePing() (*rpc.PingResult, error) {
	return &rpc.PingResult{Version: rpc.APIVersion}, nil
}

// handleActivate brings a profile up: kill-switch namespace first, then the
// engine inside it, then a startup grace period for engines with a
// persistent foreground process. Keeps the result in s.active (in-memory,
// no active.json) and starts the health-check as
// a cancelable goroutine instead of a detached child process.
func (s *Server) handleActivate(p rpc.ActivateParams) (*rpc.ActivateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active != nil {
		return nil, fmt.Errorf("profile %q is already active — deactivate it first", s.active.profile.Name)
	}

	prof, err := profileFromParams(p)
	if err != nil {
		return nil, err
	}

	status, err := s.ng.Setup(prof)
	if err != nil {
		return nil, fmt.Errorf("setting up kill-switch: %w", err)
	}

	handle, err := engine.Start(s.ng, prof)
	if err != nil {
		_ = s.ng.Teardown()
		return nil, fmt.Errorf("starting engine: %w", err)
	}

	// A successful fork+exec only means the process launched, not that it
	// stayed up — give a persistent foreground engine (sing-box/xray) a real
	// chance to crash before reporting the activation a success. WireGuard/
	// AmneziaWG has no persistent process to wait on (PID()==0), so it's
	// exempt, same as actions.Activate.
	if handle.PID() != 0 {
		time.Sleep(engineStartupGrace)
		if healthy, herr := handle.Healthy(); herr != nil || !healthy {
			_ = handle.Stop()
			_ = s.ng.Teardown()
			return nil, fmt.Errorf("engine failed to start (see %s):\n%s", handle.LogPath(), tailLogFile(handle.LogPath(), logTailLines))
		}
	}

	hctx, cancel := context.WithCancel(context.Background())
	s.active = &activeState{
		profile:    prof,
		status:     status,
		handle:     handle,
		healthStop: cancel,
	}
	go s.healthCheckLoop(hctx, prof)

	return &rpc.ActivateResult{
		Status:     status,
		EngineKind: handle.Kind(),
		EngineLog:  handle.LogPath(),
	}, nil
}

func (s *Server) handleDeactivate() (*struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &struct{}{}, s.deactivateLocked()
}

// deactivateLocked stops the engine (if any) and tears down the namespace.
// Unlike actions.Deactivate (which returns early, skipping Teardown
// entirely, if stopping the engine fails), Teardown always runs regardless
// of whether Stop succeeded — found empirically on a live stand: a
// systemd stop with the default KillMode=control-group can SIGTERM the
// daemon's own in-flight `awg-quick down` child (spawned by Stop) before
// it finishes, which used to leave the namespace/kill-switch orphaned
// exactly like the A1 bug this whole project started by fixing. Teardown
// itself already kills tracked PIDs and removes the namespace/veth
// unconditionally, so it's the right fallback even when the graceful Stop
// didn't complete.
func (s *Server) deactivateLocked() error {
	// Kill everything still running through the profile (vpnctl run/run
	// --tui/run --gui) before the namespace they live inside disappears.
	// Teardown() can't do this itself here the way it does in the old
	// file-based model (killTrackedProcesses reads active.json, which the
	// daemon never writes) — this is the daemon's own equivalent, using its
	// in-memory s.processes instead.
	s.killTrackedProcessesLocked()

	var stopErr error
	if s.active != nil {
		s.active.healthStop()
		handle := s.active.handle
		s.active = nil
		if err := handle.Stop(); err != nil {
			stopErr = fmt.Errorf("stopping engine: %w", err)
		}
	}
	if err := s.ng.Teardown(); err != nil {
		if stopErr != nil {
			return fmt.Errorf("%w; also failed tearing down: %v", stopErr, err)
		}
		return err
	}
	return stopErr
}

// handleStatus reports from the daemon's own in-memory s.active rather than
// netguard.Engine.Status() — that method's Active/ProfileName/etc. are
// computed by reading active.json (internal/netguard/linux.go's Status()),
// which the daemon deliberately never writes; the daemon's in-memory state
// is now the authoritative source of truth instead, with no file to drift
// out of sync with it.
func (s *Server) handleStatus() (*rpc.StatusResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active == nil {
		return &rpc.StatusResult{Status: netguard.Status{Active: false}}, nil
	}

	status := s.active.status
	status.Active = true
	healthy, err := s.active.handle.Healthy()
	if err != nil {
		healthy = false
	}
	status.EngineHealthy = healthy
	return &rpc.StatusResult{Status: status, Healthy: healthy}, nil
}

// handleTestConnectivity runs curl inside the active namespace and
// captures its combined output, returning it whole once curl exits rather
// than streaming — curl already runs -s -S (silent, errors only), so
// there's no live progress meter to preserve by keeping the connection
// open the whole time.
func (s *Server) handleTestConnectivity() (*rpc.TestConnectivityResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active == nil {
		return nil, fmt.Errorf("no active profile — activate one first")
	}

	curlArgs := []string{"-s", "-S", "--max-time", "10", "-w", "\nhttp_status=%{http_code} time=%{time_total}s\n", "https://ifconfig.me/ip"}
	cmd, err := s.ng.Command("curl", curlArgs, netguard.ExecOptions{})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start)

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("running curl: %w", runErr)
		}
	}

	return &rpc.TestConnectivityResult{
		ExitCode:  exitCode,
		ElapsedMS: elapsed.Milliseconds(),
		Output:    out.String(),
	}, nil
}

// killTrackedProcessesLocked SIGTERMs everything tracked in s.processes,
// escalating to SIGKILL after a grace period — mirrors
// netguard.killTrackedProcesses (internal/netguard/linux.go), which exists
// for the same reason but reads its PID list from active.json instead.
func (s *Server) killTrackedProcessesLocked() {
	pids := make([]int, len(s.processes))
	for i, p := range s.processes {
		pids[i] = p.PID
	}
	s.processes = nil
	if len(pids) == 0 {
		return
	}
	for _, pid := range pids {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Signal(syscall.SIGTERM)
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, pid := range pids {
		if proc, err := os.FindProcess(pid); err == nil && proc.Signal(syscall.Signal(0)) == nil {
			_ = proc.Signal(syscall.SIGKILL)
		}
	}
}

// handleListProcesses/handleKillProcess report from/act on s.processes,
// which Exec (see exec.go) populates for every launch path that goes
// through it — `vpnctl run`/`run --tui`/`run --gui` and the TUI's own app
// launchers alike.
func (s *Server) handleListProcesses() (*rpc.ListProcessesResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]netguard.ProcessInfo, len(s.processes))
	copy(out, s.processes)
	return &rpc.ListProcessesResult{Processes: out}, nil
}

// handleKillProcess signals the tracked process directly (the daemon is
// always root, so no client-side EPERM dance is needed for a process that
// might be running as a different user, this can just send the signal) and
// lets the owning Exec goroutine's own
// cmd.Wait()/untrackProcess reap and untrack it normally — no separate
// bookkeeping needed here.
func (s *Server) handleKillProcess(p rpc.KillProcessParams) (*rpc.KillProcessResult, error) {
	s.mu.Lock()
	var found *netguard.ProcessInfo
	for i := range s.processes {
		if matchesProcessTarget(s.processes[i], p.Target) {
			pi := s.processes[i]
			found = &pi
			break
		}
	}
	s.mu.Unlock()

	if found == nil {
		return nil, fmt.Errorf("no tracked process matches %q", p.Target)
	}

	proc, err := os.FindProcess(found.PID)
	if err != nil {
		return nil, err
	}
	_ = proc.Signal(syscall.SIGTERM)
	go func() {
		time.Sleep(terminateGrace)
		if proc.Signal(syscall.Signal(0)) == nil {
			_ = proc.Signal(syscall.SIGKILL)
		}
	}()
	return &rpc.KillProcessResult{Process: *found}, nil
}

func matchesProcessTarget(p netguard.ProcessInfo, target string) bool {
	if pid, err := strconv.Atoi(target); err == nil && p.PID == pid {
		return true
	}
	return p.Name == target
}

// handleGetLogTail lets a client (the TUI's status panel) show the active
// engine's recent log output without needing filesystem access to it —
// vpnctld's own state dir is root-only, so it reads the file itself and
// returns the text rather than a path.
func (s *Server) handleGetLogTail(p rpc.GetLogTailParams) (*rpc.GetLogTailResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active == nil {
		return &rpc.GetLogTailResult{}, nil
	}
	n := p.Lines
	if n <= 0 {
		n = logTailLines
	}
	return &rpc.GetLogTailResult{Text: tailLogFile(s.active.handle.LogPath(), n)}, nil
}

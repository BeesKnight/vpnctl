// Package vpnctlclient is the thin-client side of vpnctld: it resolves
// profiles locally (the daemon never touches any user's
// ~/.config/vpnctl/profiles itself — see internal/profile) and sends
// already-resolved requests over the Unix socket defined in internal/rpc.
//
// The TUI's own process launchers (internal/tui/appsview.go, runview.go)
// aren't converted to this package yet — see DAEMON_MIGRATION.md.
package vpnctlclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// dialTimeout/callTimeout bound how long a client will wait to connect to
// and hear back from vpnctld. callTimeout is generous enough to cover
// TestConnectivity's own 10s curl --max-time plus the engine startup grace
// period Activate can wait through.
const (
	dialTimeout = 3 * time.Second
	callTimeout = 20 * time.Second
)

var nextID uint64

// SocketPath is the daemon socket this client dials, overridable via
// $VPNCTL_SOCKET (same convention as VPNCTL_DRY_RUN in
// internal/netguard/runner.go) for tests and for pointing at a
// non-default daemon instance during manual verification.
func SocketPath() string {
	if v := os.Getenv("VPNCTL_SOCKET"); v != "" {
		return v
	}
	return rpc.DefaultSocketPath
}

func call(method string, params any, out any) error {
	socketPath := SocketPath()
	conn, err := net.DialTimeout("unix", socketPath, dialTimeout)
	if err != nil {
		return fmt.Errorf("connecting to vpnctld at %s: %w (is the daemon running? see DAEMON_MIGRATION.md)", socketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(callTimeout))

	var raw json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		raw = data
	}

	req := rpc.Request{
		APIVersion: rpc.APIVersion,
		ID:         atomic.AddUint64(&nextID, 1),
		Method:     method,
		Params:     raw,
	}
	if err := rpc.WriteMessage(conn, &req); err != nil {
		return fmt.Errorf("sending request to vpnctld: %w", err)
	}

	var resp rpc.Response
	if err := rpc.ReadMessage(conn, &resp); err != nil {
		return fmt.Errorf("reading response from vpnctld: %w", err)
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("decoding response from vpnctld: %w", err)
		}
	}
	return nil
}

// Activate resolves name against the local profile store and asks vpnctld
// to bring it up.
func Activate(name string) (profile.Profile, rpc.ActivateResult, error) {
	p, err := profile.Find(name)
	if err != nil {
		return profile.Profile{}, rpc.ActivateResult{}, err
	}

	params := rpc.ActivateParams{Name: p.Name, Kind: string(p.Kind), Family: string(p.Family), Backup: p.Backup}
	switch p.Family {
	case profile.FamilyWG:
		if p.WG == nil {
			return profile.Profile{}, rpc.ActivateResult{}, fmt.Errorf("profile %q has no parsed WireGuard config", p.Name)
		}
		params.WGRaw = p.WG.Raw
	case profile.FamilyProxy:
		params.Outbound = p.Outbound
	}

	var result rpc.ActivateResult
	if err := call(rpc.MethodActivate, params, &result); err != nil {
		return profile.Profile{}, rpc.ActivateResult{}, err
	}
	return p, result, nil
}

// Deactivate tears down the active profile, if any.
func Deactivate() error {
	return call(rpc.MethodDeactivate, nil, nil)
}

// Status reports the active profile's namespace status and engine health.
func Status() (rpc.StatusResult, error) {
	var result rpc.StatusResult
	err := call(rpc.MethodStatus, nil, &result)
	return result, err
}

// TestConnectivity runs a connectivity check through the active profile.
func TestConnectivity() (rpc.TestConnectivityResult, error) {
	var result rpc.TestConnectivityResult
	err := call(rpc.MethodTestConnectivity, nil, &result)
	return result, err
}

// ListProcesses lists processes tracked as launched through the active
// profile.
func ListProcesses() ([]netguard.ProcessInfo, error) {
	var result rpc.ListProcessesResult
	err := call(rpc.MethodListProcesses, nil, &result)
	return result.Processes, err
}

// KillProcess terminates a tracked process by PID or exact name.
func KillProcess(target string) (netguard.ProcessInfo, error) {
	var result rpc.KillProcessResult
	err := call(rpc.MethodKillProcess, rpc.KillProcessParams{Target: target}, &result)
	return result.Process, err
}

// GetLogTail returns the last n lines of the active engine's log — for the
// TUI's status panel, which used to read active.json/EngineLog directly
// off disk (see internal/tui/mainview.go's viewLogs) but no longer can:
// vpnctld's own state dir is root-only.
func GetLogTail(lines int) (string, error) {
	var result rpc.GetLogTailResult
	err := call(rpc.MethodGetLogTail, rpc.GetLogTailParams{Lines: lines}, &result)
	return result.Text, err
}

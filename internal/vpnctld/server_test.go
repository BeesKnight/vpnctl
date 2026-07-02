package vpnctld

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/rpc"
)

const testWGConf = `[Interface]
PrivateKey = SAVkWKIFdAR0QBebdR9Ri4xIwSmCFHEzox/iYdW/kGg=
Address = 10.31.27.189/32

[Peer]
PublicKey = yzgmEGOF1GSTtsPNl3gHz9kD9gjA+1nreDXWRxN0SjI=
AllowedIPs = 0.0.0.0/0
Endpoint = 185.130.44.10:51820
`

// fakeSucceedingEngine is a netguard.Engine stub that tracks
// active/inactive like the real LinuxEngine, but whose Command() always
// returns a harmless "true" invocation instead of the real requested
// binary — this drives a genuinely successful Activate/Deactivate cycle
// through the daemon (unlike internal/netguard.NewLinuxEngine(true), whose
// dry-run Command()/Status() are gated on a real "ip netns list" that never
// shows anything in a unit test, and unlike internal/engine's own
// fakeActiveEngine, which deliberately runs the real target binary and
// expects it to be missing) without touching real networking or requiring
// awg-quick/sing-box/xray to be installed. Mirrors the same seam pattern
// engine_test.go already uses (fakeActiveEngine), one step further since
// what's under test here is the daemon's own state transitions, not just
// dispatch.
type fakeSucceedingEngine struct {
	mu     sync.Mutex
	active bool
}

func (e *fakeSucceedingEngine) Setup(p profile.Profile) (netguard.Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = true
	return netguard.Status{
		ProfileName:  p.Name,
		ProfileKind:  string(p.Kind),
		Namespace:    "vpnctl0",
		ResolvedIP:   "185.130.44.10",
		ResolvedPort: 51820,
		Protocol:     "udp",
	}, nil
}

func (e *fakeSucceedingEngine) Teardown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = false
	return nil
}

func (e *fakeSucceedingEngine) Status() (netguard.Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return netguard.Status{Active: e.active}, nil
}

func (e *fakeSucceedingEngine) UpdateEndpoint(profile.Profile) (bool, string, error) {
	return false, "", nil
}

func (e *fakeSucceedingEngine) Command(name string, args []string, opts netguard.ExecOptions) (*exec.Cmd, error) {
	return exec.Command("true"), nil
}

func (e *fakeSucceedingEngine) Recorded() []string { return nil }

// startTestServer spins up a Server backed by fakeSucceedingEngine,
// listening on a temp Unix socket, and registers its shutdown as cleanup.
func startTestServer(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")

	sockPath := filepath.Join(t.TempDir(), "vpnctld.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listening on %s: %v", sockPath, err)
	}

	srv := NewWithEngine(&fakeSucceedingEngine{}, log.New(os.Stderr, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sockPath
}

func call(t *testing.T, sockPath, method string, params any) rpc.Response {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dialing %s: %v", sockPath, err)
	}
	defer conn.Close()

	var raw json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			t.Fatalf("marshaling params: %v", err)
		}
		raw = data
	}
	req := rpc.Request{APIVersion: rpc.APIVersion, ID: 1, Method: method, Params: raw}
	if err := rpc.WriteMessage(conn, &req); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	var resp rpc.Response
	if err := rpc.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	return resp
}

func TestPing(t *testing.T) {
	sock := startTestServer(t)
	resp := call(t, sock, rpc.MethodPing, nil)
	if resp.Error != "" {
		t.Fatalf("Ping: %s", resp.Error)
	}
	var result rpc.PingResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshaling PingResult: %v", err)
	}
	if result.Version != rpc.APIVersion {
		t.Errorf("expected version %q, got %q", rpc.APIVersion, result.Version)
	}
}

func TestUnknownMethod(t *testing.T) {
	sock := startTestServer(t)
	resp := call(t, sock, "NotAMethod", nil)
	if resp.Error == "" {
		t.Fatal("expected an error for an unknown method")
	}
}

func TestProtocolVersionMismatch(t *testing.T) {
	sock := startTestServer(t)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dialing: %v", err)
	}
	defer conn.Close()

	req := rpc.Request{APIVersion: "999", ID: 1, Method: rpc.MethodPing}
	if err := rpc.WriteMessage(conn, &req); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	var resp rpc.Response
	if err := rpc.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected a protocol version mismatch error")
	}
}

func TestStatusReportsInactiveWithNothingActivated(t *testing.T) {
	sock := startTestServer(t)
	resp := call(t, sock, rpc.MethodStatus, nil)
	if resp.Error != "" {
		t.Fatalf("Status: %s", resp.Error)
	}
	var result rpc.StatusResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshaling StatusResult: %v", err)
	}
	if result.Status.Active {
		t.Error("expected Active=false with nothing activated")
	}
}

func TestActivateStatusDeactivateRoundTrip(t *testing.T) {
	sock := startTestServer(t)

	activateResp := call(t, sock, rpc.MethodActivate, rpc.ActivateParams{
		Name:   "switz",
		Kind:   string(profile.KindWireGuard),
		Family: string(profile.FamilyWG),
		WGRaw:  testWGConf,
	})
	if activateResp.Error != "" {
		t.Fatalf("Activate: %s", activateResp.Error)
	}
	var activateResult rpc.ActivateResult
	if err := json.Unmarshal(activateResp.Result, &activateResult); err != nil {
		t.Fatalf("unmarshaling ActivateResult: %v", err)
	}
	if activateResult.Status.ResolvedIP != "185.130.44.10" {
		t.Errorf("expected resolved IP 185.130.44.10, got %q", activateResult.Status.ResolvedIP)
	}

	// A second Activate while one is already active must be rejected, not
	// silently clobber the first — there is no "atomic switch" file guard to
	// race anymore; the mutex plus this explicit check is what replaces it.
	secondResp := call(t, sock, rpc.MethodActivate, rpc.ActivateParams{
		Name: "other", Kind: string(profile.KindWireGuard), Family: string(profile.FamilyWG), WGRaw: testWGConf,
	})
	if secondResp.Error == "" {
		t.Fatal("expected activating a second profile while one is active to fail")
	}

	statusResp := call(t, sock, rpc.MethodStatus, nil)
	if statusResp.Error != "" {
		t.Fatalf("Status: %s", statusResp.Error)
	}
	var status rpc.StatusResult
	if err := json.Unmarshal(statusResp.Result, &status); err != nil {
		t.Fatalf("unmarshaling StatusResult: %v", err)
	}
	if !status.Status.Active || status.Status.ProfileName != "switz" {
		t.Errorf("expected active profile %q, got %+v", "switz", status.Status)
	}

	deactivateResp := call(t, sock, rpc.MethodDeactivate, nil)
	if deactivateResp.Error != "" {
		t.Fatalf("Deactivate: %s", deactivateResp.Error)
	}

	statusAfter := call(t, sock, rpc.MethodStatus, nil)
	var statusAfterResult rpc.StatusResult
	if err := json.Unmarshal(statusAfter.Result, &statusAfterResult); err != nil {
		t.Fatalf("unmarshaling StatusResult: %v", err)
	}
	if statusAfterResult.Status.Active {
		t.Error("expected Active=false after Deactivate")
	}

	// Once torn down, a fresh Activate must succeed again — the earlier
	// rejection of the second Activate must not have left any lingering
	// "already active" state behind.
	thirdResp := call(t, sock, rpc.MethodActivate, rpc.ActivateParams{
		Name: "third", Kind: string(profile.KindWireGuard), Family: string(profile.FamilyWG), WGRaw: testWGConf,
	})
	if thirdResp.Error != "" {
		t.Fatalf("Activate after Deactivate: %s", thirdResp.Error)
	}
}

func TestKillProcessOnEmptyListReportsNotFound(t *testing.T) {
	sock := startTestServer(t)
	resp := call(t, sock, rpc.MethodKillProcess, rpc.KillProcessParams{Target: "123"})
	if resp.Error == "" {
		t.Fatal("expected an error killing an untracked process")
	}
}

func TestConcurrentConnectionsAreServedIndependently(t *testing.T) {
	sock := startTestServer(t)
	// Two Ping calls in parallel exercise Serve's per-connection goroutine
	// without touching s.active, so this should never block.
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			resp := call(t, sock, rpc.MethodPing, nil)
			if resp.Error != "" {
				t.Errorf("Ping: %s", resp.Error)
			}
			done <- struct{}{}
		}()
	}
	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("timed out waiting for concurrent Ping calls")
		}
	}
}

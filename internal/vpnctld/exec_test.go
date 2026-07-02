package vpnctld

import (
	"bytes"
	"encoding/json"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// realCommandEngine is a netguard.Engine stub whose Command() actually
// execs the requested command (unlike fakeSucceedingEngine's "true"
// placeholder) — Exec's whole point is streaming real process I/O, so
// these tests need a real, harmless local command. Deliberately wraps via
// `sh -c` rather than exec'ing the binary directly, so cmd.Args[0] is "sh"
// — matching the real LinuxEngine.Command's nsenter-wrapping closely
// enough (cmd.Args[0] there is always "nsenter", never the requested
// binary) to catch code that reads cmd.Args instead of the originally
// requested argv for things like ProcessInfo.Name.
type realCommandEngine struct{ active bool }

func (e *realCommandEngine) Setup(p profile.Profile) (netguard.Status, error) {
	e.active = true
	return netguard.Status{ProfileName: p.Name}, nil
}
func (e *realCommandEngine) Teardown() error { e.active = false; return nil }
func (e *realCommandEngine) Status() (netguard.Status, error) {
	return netguard.Status{Active: e.active}, nil
}
func (e *realCommandEngine) UpdateEndpoint(profile.Profile) (bool, string, error) {
	return false, "", nil
}
func (e *realCommandEngine) Command(name string, args []string, opts netguard.ExecOptions) (*exec.Cmd, error) {
	full := append([]string{name}, args...)
	quoted := make([]string, len(full))
	for i, a := range full {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return exec.Command("sh", "-c", strings.Join(quoted, " ")), nil
}
func (e *realCommandEngine) Recorded() []string { return nil }

func startExecTestServer(t *testing.T) (sock string, srv *Server) {
	t.Helper()
	sockPath := t.TempDir() + "/vpnctld.sock"
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	ng := &realCommandEngine{}
	srv = NewWithEngine(ng, nil)
	srv.active = &activeState{profile: profile.Profile{Name: "test"}, healthStop: func() {}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(t.Context(), ln)
	}()
	t.Cleanup(func() { <-done })
	return sockPath, srv
}

func dialExec(t *testing.T, sock string, params rpc.ExecParams) (net.Conn, rpc.Response) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dialing: %v", err)
	}
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshaling params: %v", err)
	}
	req := rpc.Request{APIVersion: rpc.APIVersion, ID: 1, Method: rpc.MethodExec, Params: data}
	if err := rpc.WriteMessage(conn, &req); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	var resp rpc.Response
	if err := rpc.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	return conn, resp
}

func TestExecCLIModeCapturesOutput(t *testing.T) {
	sock, _ := startExecTestServer(t)
	conn, resp := dialExec(t, sock, rpc.ExecParams{Mode: rpc.ExecModeCLI, Argv: []string{"echo", "hello"}})
	defer conn.Close()
	if resp.Error != "" {
		t.Fatalf("Exec: %s", resp.Error)
	}

	var out []byte
	var exitCode = -99
	for {
		ft, payload, err := rpc.ReadFrame(conn)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		switch ft {
		case rpc.FrameStdout:
			out = append(out, payload...)
		case rpc.FrameExit:
			var em rpc.ExitMessage
			if err := json.Unmarshal(payload, &em); err != nil {
				t.Fatalf("unmarshaling exit message: %v", err)
			}
			exitCode = em.Code
		}
		if exitCode != -99 {
			break
		}
	}
	if string(out) != "hello\n" {
		t.Errorf("expected %q, got %q", "hello\n", out)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestExecGUIModeReturnsAndDetaches(t *testing.T) {
	sock, srv := startExecTestServer(t)
	conn, resp := dialExec(t, sock, rpc.ExecParams{Mode: rpc.ExecModeGUI, Argv: []string{"sleep", "0.2"}})
	defer conn.Close()
	if resp.Error != "" {
		t.Fatalf("Exec: %s", resp.Error)
	}
	var result rpc.ExecStartedResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if result.PID == 0 {
		t.Fatal("expected a nonzero PID")
	}

	// GUI mode replies once and gives no further frames.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := rpc.ReadFrame(conn); err == nil {
		t.Error("expected the connection to end after ExecStartedResult in gui mode")
	}

	srv.mu.Lock()
	tracked := len(srv.processes)
	srv.mu.Unlock()
	if tracked != 1 {
		t.Errorf("expected the gui process to be tracked immediately, got %d tracked", tracked)
	}

	// Wait past the process's own lifetime and confirm the daemon reaps and
	// untracks it (an improvement over the old model's permanently-stale
	// entry — see execGUI's doc comment).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		n := len(srv.processes)
		srv.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("expected the gui process to be untracked once it exited")
}

func TestExecKillProcessTerminatesTrackedProcess(t *testing.T) {
	sock, srv := startExecTestServer(t)
	conn, resp := dialExec(t, sock, rpc.ExecParams{Mode: rpc.ExecModeCLI, Argv: []string{"sleep", "30"}})
	defer conn.Close()
	if resp.Error != "" {
		t.Fatalf("Exec: %s", resp.Error)
	}
	var result rpc.ExecStartedResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	killResult, err := srv.handleKillProcess(rpc.KillProcessParams{Target: "sleep"})
	if err != nil {
		t.Fatalf("handleKillProcess: %v", err)
	}
	if killResult.Process.PID != result.PID {
		t.Errorf("expected to kill pid %d, got %d", result.PID, killResult.Process.PID)
	}

	// The process dying should produce an exit frame shortly (SIGTERM, no
	// need to wait for the 3s SIGKILL escalation for a process that
	// actually honors SIGTERM).
	deadline := time.Now().Add(2 * time.Second)
	conn.SetReadDeadline(deadline)
	for {
		ft, payload, err := rpc.ReadFrame(conn)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if ft == rpc.FrameExit {
			var em rpc.ExitMessage
			_ = json.Unmarshal(payload, &em)
			if em.Code == 0 {
				t.Error("expected a nonzero exit code for a SIGTERM-killed process")
			}
			break
		}
	}
}

// TestExecConnectionDropKillsProcess is the regression test for a real bug
// found on a live stand: closing the connection before the process exits
// must kill it, rather than leaving it running unsupervised forever.
func TestExecConnectionDropKillsProcess(t *testing.T) {
	sock, srv := startExecTestServer(t)
	conn, resp := dialExec(t, sock, rpc.ExecParams{Mode: rpc.ExecModeCLI, Argv: []string{"sleep", "30"}})
	if resp.Error != "" {
		t.Fatalf("Exec: %s", resp.Error)
	}
	var result rpc.ExecStartedResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	// Close the connection outright (not a clean stdin-EOF frame) — same
	// as a crashed/killed client, or a network drop.
	conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		n := len(srv.processes)
		srv.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("expected pid %d to be killed once the connection dropped, but it's still tracked", result.PID)
}

// TestExecCleanStdinEOFDoesNotKillProcess is the companion regression test:
// a clean local stdin EOF (e.g. the client was launched with stdin
// pointed at /dev/null, as systemd-run does with no controlling terminal)
// must NOT be treated the same as a dropped connection — the process
// should keep running and exit normally on its own.
func TestExecCleanStdinEOFDoesNotKillProcess(t *testing.T) {
	sock, _ := startExecTestServer(t)
	conn, resp := dialExec(t, sock, rpc.ExecParams{Mode: rpc.ExecModeCLI, Argv: []string{"sleep", "0.3"}})
	defer conn.Close()
	if resp.Error != "" {
		t.Fatalf("Exec: %s", resp.Error)
	}

	// Signal a clean stdin EOF immediately (empty FrameStdin), then keep
	// the connection open and wait for the process to finish on its own.
	if err := rpc.WriteFrame(conn, rpc.FrameStdin, nil); err != nil {
		t.Fatalf("sending stdin EOF frame: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		ft, payload, err := rpc.ReadFrame(conn)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if ft == rpc.FrameExit {
			var em rpc.ExitMessage
			_ = json.Unmarshal(payload, &em)
			if em.Code != 0 {
				t.Errorf("expected the process to exit normally (code 0), got %d — stdin EOF must not have killed it", em.Code)
			}
			return
		}
	}
}

func TestExecNoActiveProfileIsRejected(t *testing.T) {
	sock, srv := startExecTestServer(t)
	srv.mu.Lock()
	srv.active = nil
	srv.mu.Unlock()

	conn, resp := dialExec(t, sock, rpc.ExecParams{Mode: rpc.ExecModeCLI, Argv: []string{"echo", "hi"}})
	defer conn.Close()
	if resp.Error == "" {
		t.Fatal("expected Exec to be rejected with no active profile")
	}
}

func TestExecTUIModeAllocatesRealPTY(t *testing.T) {
	sock, _ := startExecTestServer(t)
	conn, resp := dialExec(t, sock, rpc.ExecParams{
		Mode: rpc.ExecModeTUI, Argv: []string{"echo", "pty hello"}, Rows: 24, Cols: 80,
	})
	defer conn.Close()
	if resp.Error != "" {
		t.Fatalf("Exec: %s", resp.Error)
	}

	// Send a resize before anything else, to confirm it doesn't disrupt the
	// session (relayPTYInput must keep reading FrameStdin/FrameExit after
	// handling it).
	if err := rpc.WriteJSONFrame(conn, rpc.FrameResize, rpc.ResizeMessage{Rows: 40, Cols: 120}); err != nil {
		t.Fatalf("sending resize frame: %v", err)
	}

	var out []byte
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		ft, payload, err := rpc.ReadFrame(conn)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if ft == rpc.FrameStdout {
			out = append(out, payload...)
		}
		if ft == rpc.FrameExit {
			var em rpc.ExitMessage
			_ = json.Unmarshal(payload, &em)
			if em.Code != 0 {
				t.Errorf("expected exit code 0, got %d", em.Code)
			}
			break
		}
	}
	if !bytes.Contains(out, []byte("pty hello")) {
		t.Errorf("expected PTY output to contain %q, got %q", "pty hello", out)
	}
}

func TestListProcessesReflectsRunningExec(t *testing.T) {
	sock, srv := startExecTestServer(t)
	conn, resp := dialExec(t, sock, rpc.ExecParams{Mode: rpc.ExecModeCLI, Argv: []string{"sleep", "1"}})
	defer conn.Close()
	if resp.Error != "" {
		t.Fatalf("Exec: %s", resp.Error)
	}

	result, err := srv.handleListProcesses()
	if err != nil {
		t.Fatalf("handleListProcesses: %v", err)
	}
	if len(result.Processes) != 1 || result.Processes[0].Name != "sleep" {
		t.Errorf("expected one tracked 'sleep' process, got %+v", result.Processes)
	}
}

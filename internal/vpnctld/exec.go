package vpnctld

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// terminateGrace is how long a killed process gets to exit after SIGTERM
// before Exec escalates to SIGKILL — same graceful-then-forceful pattern
// as internal/netguard's killTrackedProcesses.
const terminateGrace = 3 * time.Second

// maxTrackedProcesses bounds how many processes Exec will launch and track
// at once. Without this, a client with nothing more than ordinary "vpnctl"
// group membership could run e.g. `for i in 1..10000; do vpnctl run --
// sleep 999 & done` and exhaust the host's process table/fd limits — gui
// mode's launches are especially cheap to spam since the exec.go RPC call
// itself returns as soon as the process starts, well before it exits.
const maxTrackedProcesses = 256

// handleExecConn services one MethodExec request end to end: builds the
// command inside the active namespace exactly like netguard.Engine.Command
// always has, then hands it to the mode-specific runner. The initial
// Request/Response handshake (api_version already checked by handleConn)
// is answered here with either an error or ExecStartedResult once the
// process has actually started — after that point the connection carries
// rpc.Frames instead of further Request/Response pairs.
func (s *Server) handleExecConn(conn net.Conn, req rpc.Request, peer peerIdentity) {
	var params rpc.ExecParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeExecError(conn, req.ID, fmt.Errorf("decoding params: %w", err))
		return
	}
	if len(params.Argv) == 0 {
		writeExecError(conn, req.ID, fmt.Errorf("empty command"))
		return
	}

	s.mu.Lock()
	if s.active == nil {
		s.mu.Unlock()
		writeExecError(conn, req.ID, fmt.Errorf("no active profile — activate one first"))
		return
	}
	if len(s.processes) >= maxTrackedProcesses {
		s.mu.Unlock()
		writeExecError(conn, req.ID, fmt.Errorf("too many processes already running through vpnctl (limit %d) — kill some first", maxTrackedProcesses))
		return
	}
	ng := s.ng
	s.mu.Unlock()

	dropUID, dropGID := execDropTarget(peer, params.DropUID, params.DropGID)
	s.logger.Printf("audit: uid=%d exec mode=%s argv=%q drop_to=%s", peer.UID, params.Mode, params.Argv, formatDropTarget(dropUID))

	opts := netguard.ExecOptions{Env: params.Env, DropToUID: dropUID, DropToGID: dropGID}
	cmd, err := ng.Command(params.Argv[0], params.Argv[1:], opts)
	if err != nil {
		writeExecError(conn, req.ID, err)
		return
	}

	switch params.Mode {
	case rpc.ExecModeGUI:
		s.execGUI(conn, req, cmd, params.Argv)
	case rpc.ExecModeTUI:
		s.execPTY(conn, req, cmd, params.Argv, params.Rows, params.Cols)
	default:
		s.execPipes(conn, req, cmd, params.Argv)
	}
}

// execDropTarget decides who Exec's target process actually runs as. The
// client-supplied params.DropUID/GID (rpc.ExecParams) can never be trusted
// on their own: /run/vpnctl.sock is reachable by every member of the
// "vpnctl" group, and without this check a non-root peer could simply omit
// DropUID/GID (or set them to 0) to get its command run as root — the
// daemon's own euid, since ng.Command only drops privilege when
// opts.DropToUID/GID is non-nil (see netguard.LinuxEngine.Command). A
// non-root peer's real, kernel-verified identity (SO_PEERCRED, see
// peercred_linux.go) always wins for a non-root peer, no matter what it
// asked for — this makes `vpnctl run`/the TUI's Run screen/Apps panel run
// as the invoking user, matching what "no sudo needed" was always meant to
// mean, not "runs as root now instead". Only a genuinely root peer's own
// request is honored as-is, since root asking to drop to a lesser uid
// (e.g. for a GUI app's X11 passthrough under `sudo vpnctl run --gui`) is
// safe — it can only ever reduce that peer's own privilege, never grant it
// someone else's.
func execDropTarget(peer peerIdentity, clientUID, clientGID *int) (*int, *int) {
	if peer.UID == 0 {
		return clientUID, clientGID
	}
	uid, gid := int(peer.UID), int(peer.GID)
	return &uid, &gid
}

// formatDropTarget renders a *int for the audit log — %d on a *int prints
// the pointer's address, not the value it points to, which would make
// every log line show a useless heap address instead of a uid.
func formatDropTarget(uid *int) string {
	if uid == nil {
		return "root(no-drop)"
	}
	return strconv.Itoa(*uid)
}

func writeExecError(conn net.Conn, id uint64, err error) {
	_ = rpc.WriteMessage(conn, &rpc.Response{ID: id, Error: err.Error()})
}

func writeExecStarted(conn net.Conn, id uint64, pid int) error {
	data, err := json.Marshal(rpc.ExecStartedResult{PID: pid})
	if err != nil {
		return err
	}
	return rpc.WriteMessage(conn, &rpc.Response{ID: id, Result: data})
}

// trackProcess/untrackProcess add/remove one entry in s.processes, holding
// Server.mu only briefly — never for an Exec session's whole lifetime,
// which would block unrelated Status/Activate/Deactivate calls for as long
// as an interactive `vpnctl run --tui` session happens to stay open.
func (s *Server) trackProcess(pi netguard.ProcessInfo) {
	s.mu.Lock()
	s.processes = append(s.processes, pi)
	s.mu.Unlock()
}

func (s *Server) untrackProcess(pid int) {
	s.mu.Lock()
	out := s.processes[:0]
	for _, p := range s.processes {
		if p.PID != pid {
			out = append(out, p)
		}
	}
	s.processes = out
	s.mu.Unlock()
}

// execGUI launches cmd detached (stdio to /dev/null) and replies with its
// PID as soon as it starts — there is nothing to stream. Because the daemon
// is long-lived, unlike the short-lived CLI process that requested this, it
// can actually wait on the child: reaping it here so it doesn't become a
// zombie under vpnctld also lets `vpnctl ps` correctly stop showing it once
// it exits, instead of showing a permanently stale entry.
func (s *Server) execGUI(conn net.Conn, req rpc.Request, cmd *exec.Cmd, argv []string) {
	cmd.Stdin = nil
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		writeExecError(conn, req.ID, err)
		return
	}
	cmd.Stdout, cmd.Stderr = devnull, devnull

	if err := cmd.Start(); err != nil {
		_ = devnull.Close()
		writeExecError(conn, req.ID, err)
		return
	}
	pid := cmd.Process.Pid
	s.trackProcess(netguard.ProcessInfo{
		// argv[0]/argv, not cmd.Args[0]/cmd.Args: cmd is the nsenter-wrapped
		// *exec.Cmd netguard.Engine.Command built (see linux.go's Command
		// doc comment) — cmd.Args[0] is always "nsenter", never the actual
		// target binary, which would make `vpnctl ps`/`kill <name>` useless.
		PID: pid, Name: argv[0], Type: string(rpc.ExecModeGUI),
		Command: argv, StartedAt: time.Now(),
	})
	go func() {
		_ = cmd.Wait()
		_ = devnull.Close()
		s.untrackProcess(pid)
	}()

	_ = writeExecStarted(conn, req.ID, pid)
}

// execPipes streams stdin/stdout/stderr over plain pipes (no PTY) for a
// blocking, non-interactive command.
func (s *Server) execPipes(conn net.Conn, req rpc.Request, cmd *exec.Cmd, argv []string) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		writeExecError(conn, req.ID, err)
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeExecError(conn, req.ID, err)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		writeExecError(conn, req.ID, err)
		return
	}

	if err := cmd.Start(); err != nil {
		writeExecError(conn, req.ID, err)
		return
	}
	pid := cmd.Process.Pid
	s.trackProcess(netguard.ProcessInfo{
		PID: pid, Name: argv[0], Type: string(rpc.ExecModeCLI),
		Command: argv, StartedAt: time.Now(),
	})
	defer s.untrackProcess(pid)

	if err := writeExecStarted(conn, req.ID, pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return
	}
	_ = conn.SetDeadline(time.Time{}) // no timeout once streaming — bounded only by the process itself or the connection dropping

	writeFrame := newFrameWriter(conn)

	var relayWG sync.WaitGroup
	relayWG.Add(2)
	go func() { defer relayWG.Done(); relayToFrames(stdout, rpc.FrameStdout, writeFrame) }()
	go func() { defer relayWG.Done(); relayToFrames(stderr, rpc.FrameStderr, writeFrame) }()

	// pipesDone fires once both stdout and stderr have hit EOF, which for a
	// plain (non-PTY) child only happens once the process has exited and
	// closed its end of both pipes. cmd.Wait() must not run until then: Wait
	// closes the parent's read end of StdoutPipe()/StderrPipe() as soon as
	// it sees the process exit, and racing that against relayToFrames'
	// still-in-flight Read() can silently drop whatever output was sitting
	// in the pipe buffer — for a fast command like `echo`, easily lost
	// before relayToFrames even gets scheduled. Go's own docs warn: "it is
	// incorrect to call Wait before all reads from the pipe have completed."
	pipesDone := make(chan struct{})
	go func() { relayWG.Wait(); close(pipesDone) }()

	// connDropped fires only once the connection itself actually
	// closes/errors — never on a clean local stdin EOF (e.g. `vpnctl run --
	// foo < /dev/null`), which relayStdin instead treats as "close the
	// pipe to the child, keep watching the connection" (see its doc
	// comment). Closing the connection is the cancellation signal for a
	// still-running process; there's no separate control frame for it.
	connDropped := make(chan struct{})
	go func() { relayStdin(conn, stdin); close(connDropped) }()

	select {
	case <-pipesDone:
	case <-connDropped:
		terminateProcess(cmd.Process, pipesDone)
		<-pipesDone
	}
	waitErr := cmd.Wait()
	_ = writeFrame(rpc.FrameExit, mustMarshalJSON(toExitMessage(waitErr)))
}

// execPTY allocates a real PTY on the daemon side and proxies raw bytes —
// needed for genuinely interactive full-screen programs, which have
// nothing to inherit a terminal from once there's a socket instead of a
// directly-inherited tty between vpnctl and the target process.
func (s *Server) execPTY(conn net.Conn, req rpc.Request, cmd *exec.Cmd, argv []string, rows, cols uint16) {
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		writeExecError(conn, req.ID, err)
		return
	}

	pid := cmd.Process.Pid
	s.trackProcess(netguard.ProcessInfo{
		PID: pid, Name: argv[0], Type: string(rpc.ExecModeTUI),
		Command: argv, StartedAt: time.Now(),
	})
	defer s.untrackProcess(pid)

	if err := writeExecStarted(conn, req.ID, pid); err != nil {
		_ = ptmx.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	writeFrame := newFrameWriter(conn)

	var relayWG sync.WaitGroup
	relayWG.Add(1)
	go func() { defer relayWG.Done(); relayToFrames(ptmx, rpc.FrameStdout, writeFrame) }()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	// connDropped fires only once the connection itself actually
	// closes/errors — never on a clean local stdin EOF (see relayPTYInput's
	// doc comment).
	connDropped := make(chan struct{})
	go func() { relayPTYInput(conn, ptmx); close(connDropped) }()

	var waitErr error
	select {
	case waitErr = <-done:
		// relayPTYInput is likely still blocked reading conn — force it to
		// stop before this function touches ptmx again below, or its
		// pty.Setsize/Write and our ptmx.Close race on the same fd (a real
		// race caught by `go test -race`, not just a hypothetical one: the
		// PTY's single fd is shared by both directions, unlike execPipes'
		// separate stdin/stdout/stderr pipes).
		_ = conn.SetReadDeadline(time.Now())
		<-connDropped // wait for relayPTYInput to actually observe the deadline and return before we touch ptmx
	case <-connDropped:
		waitErr = terminateAndWait(cmd.Process, done)
	}

	relayWG.Wait() // ptmx.Read unblocks on its own once the child (and its last fd to the PTY slave) is gone — no explicit close needed to make that happen
	_ = ptmx.Close()
	_ = writeFrame(rpc.FrameExit, mustMarshalJSON(toExitMessage(waitErr)))
}

// newFrameWriter serializes writes to conn — stdout/stderr relay goroutines
// and the final exit frame all write to the same connection concurrently,
// and net.Conn.Write isn't safe for that without external synchronization.
func newFrameWriter(conn net.Conn) func(rpc.FrameType, []byte) error {
	var mu sync.Mutex
	return func(t rpc.FrameType, payload []byte) error {
		mu.Lock()
		defer mu.Unlock()
		return rpc.WriteFrame(conn, t, payload)
	}
}

func relayToFrames(r io.Reader, t rpc.FrameType, write func(rpc.FrameType, []byte) error) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := write(t, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// relayStdin reads FrameStdin frames from conn and writes their payload to
// stdin. Returns true if the connection itself dropped (client is gone —
// the caller should kill the process), false on a clean stdin-EOF frame
// (the client just finished writing, the process may still be running).
// relayStdin reads FrameStdin frames from conn and writes their payload to
// stdin. A clean EOF frame (empty payload — the client's own local stdin
// ran out, e.g. `vpnctl run -- foo < /dev/null`, or under systemd-run/no
// controlling terminal, where stdin is /dev/null from the very start)
// closes stdin exactly once, matching normal Unix pipe semantics, but does
// NOT return: the client may still be attached and waiting for output long
// after its own stdin went away, so this keeps reading frames (ignoring
// any further FrameStdin) purely to keep watching the connection itself.
// Only returns once the connection actually closes/errors — that's the
// caller's real "the client is gone, kill the process" signal.
func relayStdin(conn net.Conn, stdin io.WriteCloser) {
	closed := false
	for {
		t, payload, err := rpc.ReadFrame(conn)
		if err != nil {
			if !closed {
				_ = stdin.Close()
			}
			return
		}
		if t != rpc.FrameStdin || closed {
			continue
		}
		if len(payload) == 0 {
			closed = true
			_ = stdin.Close()
			continue
		}
		if _, err := stdin.Write(payload); err != nil {
			closed = true
			_ = stdin.Close()
		}
	}
}

// relayPTYInput is relayStdin's PTY-mode counterpart: also handles
// FrameResize (SIGWINCH from the client's local terminal). Same "keep
// watching the connection past a clean stdin EOF" reasoning applies —
// there's no stdin handle of its own to close here (ptmx is one fd for
// both directions), so a clean EOF just stops forwarding further input.
func relayPTYInput(conn net.Conn, ptmx *os.File) {
	stdinOpen := true
	for {
		t, payload, err := rpc.ReadFrame(conn)
		if err != nil {
			return
		}
		switch t {
		case rpc.FrameStdin:
			if !stdinOpen {
				continue
			}
			if len(payload) == 0 {
				stdinOpen = false
				continue
			}
			if _, err := ptmx.Write(payload); err != nil {
				stdinOpen = false
			}
		case rpc.FrameResize:
			var rm rpc.ResizeMessage
			if json.Unmarshal(payload, &rm) == nil {
				_ = pty.Setsize(ptmx, &pty.Winsize{Rows: rm.Rows, Cols: rm.Cols})
			}
		}
	}
}

// terminateAndWait sends SIGTERM, giving the process up to terminateGrace
// to exit via done (already being waited on by the caller), escalating to
// SIGKILL if it's still running after that.
func terminateAndWait(proc *os.Process, done <-chan error) error {
	_ = proc.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		return err
	case <-time.After(terminateGrace):
		_ = proc.Signal(syscall.SIGKILL)
		return <-done
	}
}

// terminateProcess is execPipes' equivalent of terminateAndWait, adapted
// for the fact that execPipes can't watch a cmd.Wait() result channel
// without racing StdoutPipe()/StderrPipe() (see the pipesDone comment in
// execPipes) — it watches pipesDone instead, which closes once the
// process has exited and both pipes have hit EOF.
func terminateProcess(proc *os.Process, pipesDone <-chan struct{}) {
	_ = proc.Signal(syscall.SIGTERM)
	select {
	case <-pipesDone:
	case <-time.After(terminateGrace):
		_ = proc.Signal(syscall.SIGKILL)
	}
}

func toExitMessage(err error) rpc.ExitMessage {
	if err == nil {
		return rpc.ExitMessage{Code: 0}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return rpc.ExitMessage{Code: exitErr.ExitCode()}
	}
	return rpc.ExitMessage{Code: -1, Err: err.Error()}
}

func mustMarshalJSON(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}

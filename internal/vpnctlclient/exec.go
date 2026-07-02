package vpnctlclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/term"

	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// ExecOptions carries the GUI-mode-only fields (desktop-session env
// passthrough, privilege drop) — mirrors netguard.ExecOptions, but only the
// subset Exec's wire params (rpc.ExecParams) actually need; Dir isn't
// exposed since nothing using this client sets a working directory today.
type ExecOptions struct {
	Env     []string
	DropUID *int
	DropGID *int
}

// ExecResult is what Exec returns once the RPC completes: for cli/tui,
// once the process has exited (ExitCode meaningful); for gui, as soon as
// the daemon confirms it started (ExitCode always 0 — nothing is waited on,
// it's detached).
type ExecResult struct {
	PID      int
	ExitCode int
}

// Exec runs argv through the active profile via vpnctld, in one of three
// modes (see rpc.ExecMode):
//   - cli: blocks, relays os.Stdin/Stdout/Stderr over plain frames (no PTY)
//     — matches today's `vpnctl run` (no flag).
//   - tui: blocks, the daemon allocates a real PTY server-side (nothing
//     server-side has a terminal of its own to hand the process the way a
//     directly-inherited fd used to); this client puts the local terminal
//     into raw mode and forwards resize (SIGWINCH) — matches `vpnctl run
//     --tui`.
//   - gui: returns as soon as the daemon confirms the process started —
//     matches `vpnctl run --gui`.
func Exec(mode rpc.ExecMode, argv []string, opts ExecOptions) (ExecResult, error) {
	if len(argv) == 0 {
		return ExecResult{}, fmt.Errorf("no command given")
	}

	socketPath := SocketPath()
	conn, err := net.DialTimeout("unix", socketPath, dialTimeout)
	if err != nil {
		return ExecResult{}, fmt.Errorf("connecting to vpnctld at %s: %w (is the daemon running? see DAEMON_MIGRATION.md)", socketPath, err)
	}
	defer conn.Close()

	params := rpc.ExecParams{Mode: mode, Argv: argv, Env: opts.Env, DropUID: opts.DropUID, DropGID: opts.DropGID}
	var restoreTerm func()
	if mode == rpc.ExecModeTUI {
		fd := int(os.Stdin.Fd())
		if w, h, err := term.GetSize(fd); err == nil {
			params.Cols, params.Rows = uint16(w), uint16(h)
		}
		if term.IsTerminal(fd) {
			if oldState, err := term.MakeRaw(fd); err == nil {
				restoreTerm = func() { _ = term.Restore(fd, oldState) }
			}
		}
	}
	if restoreTerm != nil {
		defer restoreTerm()
	}

	data, err := json.Marshal(params)
	if err != nil {
		return ExecResult{}, fmt.Errorf("encoding request: %w", err)
	}
	req := rpc.Request{APIVersion: rpc.APIVersion, ID: atomic.AddUint64(&nextID, 1), Method: rpc.MethodExec, Params: data}
	if err := rpc.WriteMessage(conn, &req); err != nil {
		return ExecResult{}, fmt.Errorf("sending request to vpnctld: %w", err)
	}

	var resp rpc.Response
	if err := rpc.ReadMessage(conn, &resp); err != nil {
		return ExecResult{}, fmt.Errorf("reading response from vpnctld: %w", err)
	}
	if resp.Error != "" {
		return ExecResult{}, errors.New(resp.Error)
	}
	var started rpc.ExecStartedResult
	if err := json.Unmarshal(resp.Result, &started); err != nil {
		return ExecResult{}, fmt.Errorf("decoding response from vpnctld: %w", err)
	}

	if mode == rpc.ExecModeGUI {
		return ExecResult{PID: started.PID}, nil
	}

	code, err := relay(conn, mode == rpc.ExecModeTUI)
	return ExecResult{PID: started.PID, ExitCode: code}, err
}

// relay proxies conn<->os.Stdin/Stdout/Stderr until the daemon sends
// FrameExit, forwarding SIGWINCH as resize frames when isPTY (the daemon
// ignores FrameResize outside tui mode, and cli mode has no PTY winsize to
// report anyway).
func relay(conn net.Conn, isPTY bool) (int, error) {
	var writeMu sync.Mutex
	writeFrame := func(t rpc.FrameType, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return rpc.WriteFrame(conn, t, payload)
	}

	// os.Stdin -> conn, until EOF (signaled with an empty FrameStdin so the
	// daemon can close the remote stdin without treating it as a dropped
	// connection — see relayStdin/relayPTYInput's hardDrop distinction).
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if werr := writeFrame(rpc.FrameStdin, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				_ = writeFrame(rpc.FrameStdin, nil)
				return
			}
		}
	}()

	if isPTY {
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		go func() {
			for range winch {
				w, h, err := term.GetSize(int(os.Stdin.Fd()))
				if err != nil {
					continue
				}
				data, merr := json.Marshal(rpc.ResizeMessage{Rows: uint16(h), Cols: uint16(w)})
				if merr != nil {
					continue
				}
				if werr := writeFrame(rpc.FrameResize, data); werr != nil {
					return
				}
			}
		}()
	}

	for {
		ft, payload, err := rpc.ReadFrame(conn)
		if err != nil {
			return -1, fmt.Errorf("reading from vpnctld: %w", err)
		}
		switch ft {
		case rpc.FrameStdout:
			_, _ = os.Stdout.Write(payload)
		case rpc.FrameStderr:
			_, _ = os.Stderr.Write(payload)
		case rpc.FrameExit:
			var em rpc.ExitMessage
			if err := json.Unmarshal(payload, &em); err != nil {
				return -1, fmt.Errorf("decoding exit message: %w", err)
			}
			if em.Err != "" {
				return em.Code, errors.New(em.Err)
			}
			return em.Code, nil
		}
	}
}

package rpc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// MethodExec is handled differently from every other method: after the
// initial Request/Response handshake (same envelope as any other call),
// the connection switches from one-shot request/response into a
// bidirectional stream of Frames instead of closing — see WriteFrame/
// ReadFrame below. Every other method in methods.go stays request/response
// only.
const MethodExec = "Exec"

// ExecMode selects how the daemon runs the target process.
type ExecMode string

const (
	// ExecModeCLI streams stdin/stdout/stderr over plain pipes (no PTY) —
	// for blocking, non-interactive commands. Matches today's `vpnctl run`
	// (no --tui/--gui flag): it never allocated a real PTY either, it just
	// happened to inherit vpnctl's own terminal fds directly, which a
	// detached daemon with no tty of its own has nothing to inherit.
	ExecModeCLI ExecMode = "cli"
	// ExecModeTUI allocates a real PTY on the daemon side and proxies raw
	// bytes — needed for genuinely interactive full-screen programs (vim,
	// htop, ssh) once there's a socket, not an inherited terminal, between
	// vpnctl and the process using it.
	ExecModeTUI ExecMode = "tui"
	// ExecModeGUI launches detached (stdio to /dev/null) and returns as
	// soon as the process starts — the daemon replies with its PID and
	// closes the connection; there is nothing to stream.
	ExecModeGUI ExecMode = "gui"
)

// ExecParams is the initial (ordinary Request/Response-framed) payload for
// MethodExec.
type ExecParams struct {
	Mode ExecMode `json:"mode"`
	Argv []string `json:"argv"`
	// Env/DropUID/DropGID mirror netguard.ExecOptions, for the gui mode's
	// desktop-passthrough + privilege-drop (see internal/sysuser.ResolveGUIEnv,
	// used by both cmd/vpnctl/run.go's --gui path and internal/tui's own
	// GUI launcher to build these).
	Env     []string `json:"env,omitempty"`
	DropUID *int     `json:"drop_uid,omitempty"`
	DropGID *int     `json:"drop_gid,omitempty"`
	// Cols/Rows seed the PTY's initial size for tui mode.
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// ExecStartedResult is the Response.Result once the process has actually
// started (cmd.Start succeeded) — the point of no return after which the
// connection carries Frames instead of further Request/Response pairs.
type ExecStartedResult struct {
	PID int `json:"pid"`
}

// FrameType identifies what a Frame carries once a connection has switched
// into streaming mode after an accepted MethodExec.
type FrameType byte

const (
	// FrameStdin/FrameStdout/FrameStderr carry raw process bytes — for tui
	// mode (a single PTY), stderr is never sent separately since the PTY
	// combines them; FrameStdout carries everything the process wrote.
	FrameStdin FrameType = iota
	FrameStdout
	FrameStderr
	// FrameResize carries a JSON-encoded ResizeMessage (client's local
	// terminal changed size — SIGWINCH). Only meaningful for tui mode;
	// the daemon ignores it for cli.
	FrameResize
	// FrameExit carries a JSON-encoded ExitMessage and is always the last
	// frame the daemon sends before closing the connection.
	FrameExit
)

// maxFramePayload bounds a single stream frame — generous for a single
// read() of process output, small enough that a corrupt/hostile length
// prefix can't force an unbounded allocation (same reasoning as
// maxMessageSize for the request/response envelope).
const maxFramePayload = 1 << 20 // 1 MiB

// ResizeMessage is FrameResize's JSON payload.
type ResizeMessage struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// ExitMessage is FrameExit's JSON payload. Err is set (Code meaningless)
// when the process couldn't even be waited on; otherwise Code is the
// process's real exit code.
type ExitMessage struct {
	Code int    `json:"code"`
	Err  string `json:"err,omitempty"`
}

// WriteFrame writes one [1-byte type][4-byte big-endian length][payload]
// frame to w.
func WriteFrame(w io.Writer, t FrameType, payload []byte) error {
	if len(payload) > maxFramePayload {
		return fmt.Errorf("frame payload too large: %d bytes", len(payload))
	}
	header := make([]byte, 5)
	header[0] = byte(t)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing frame header: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("writing frame payload: %w", err)
	}
	return nil
}

// WriteJSONFrame is WriteFrame for a JSON-encoded control payload
// (ResizeMessage/ExitMessage).
func WriteJSONFrame(w io.Writer, t FrameType, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshaling frame payload: %w", err)
	}
	return WriteFrame(w, t, data)
}

// ReadFrame reads one frame from r.
func ReadFrame(r io.Reader) (FrameType, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(header[1:])
	if n > maxFramePayload {
		return 0, nil, fmt.Errorf("frame payload too large: %d bytes", n)
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, fmt.Errorf("reading frame payload: %w", err)
		}
	}
	return FrameType(header[0]), payload, nil
}

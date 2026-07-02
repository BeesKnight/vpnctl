package tui

import (
	"io"

	"github.com/BeesKnight/vpnctl/internal/rpc"
	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

// daemonExecCommand adapts vpnctlclient.Exec to bubbletea's tea.ExecCommand
// interface (Run() error / SetStdin(io.Reader) / SetStdout(io.Writer) /
// SetStderr(io.Writer)) — the same interface tea.ExecProcess's own
// wrapExecCommand satisfies for a plain *exec.Cmd, per
// charmbracelet/bubbletea's exec.go. tea.Exec (which tea.ExecProcess itself
// is just a thin wrapper around for *exec.Cmd specifically) accepts any
// type satisfying it, not just *exec.Cmd — bubbletea's Program.exec()
// releases the terminal (raw mode/alt-screen) before calling Run() and
// restores it after, regardless of what Run() actually does inside, which
// is exactly the terminal handling a PTY session with vpnctld needs.
//
// SetStdin/SetStdout/SetStderr are no-ops: vpnctlclient.Exec's relay
// already talks to the real os.Stdin/os.Stdout/os.Stderr directly (see
// internal/vpnctlclient/exec.go), which are exactly what bubbletea would
// otherwise be setting here (p.input/p.output default to the real
// terminal), so there's nothing to inject.
type daemonExecCommand struct {
	mode rpc.ExecMode
	argv []string
	opts vpnctlclient.ExecOptions
}

func (c *daemonExecCommand) SetStdin(io.Reader)  {}
func (c *daemonExecCommand) SetStdout(io.Writer) {}
func (c *daemonExecCommand) SetStderr(io.Writer) {}

func (c *daemonExecCommand) Run() error {
	_, err := vpnctlclient.Exec(c.mode, c.argv, c.opts)
	return err
}

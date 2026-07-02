package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// runScreenModel is the "Run" screen: type a command, enter takes over the
// terminal via tea.Exec (see execcmd.go's daemonExecCommand) and runs it
// through vpnctld with a real PTY allocated server-side (streaming output,
// TUI programs and all — this is the same mechanism used when launching a
// TUI/interactive program from inside vpnctl's own TUI), then returns
// control to vpnctl once the command exits.
type runScreenModel struct {
	input textinput.Model
}

func newRunScreen() runScreenModel {
	ti := textinput.New()
	ti.Placeholder = "curl https://example.com  (or htop, nmap -sV ..., anything)"
	ti.Prompt = "$ "
	return runScreenModel{input: ti}
}

type runFinishedMsg struct {
	cmd string
	err error
}

func (m Model) updateRunScreen(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.screen = screenMain
		m.run.input.Blur()
		return m, nil
	case "enter":
		command := strings.TrimSpace(m.run.input.Value())
		if command == "" {
			return m, nil
		}
		m.run.input.SetValue("")
		return m.execRunCommand(command)
	}
	var cmd tea.Cmd
	m.run.input, cmd = m.run.input.Update(msg)
	return m, cmd
}

// execRunCommand hands a daemonExecCommand to tea.Exec, which suspends
// vpnctl's own rendering, releases the real terminal to it (raw mode,
// alt-screen — full takeover), and resumes vpnctl once it exits.
// daemonExecCommand.Run() is what actually talks to vpnctld: the daemon
// allocates a PTY server-side and this client proxies it, since a detached
// daemon has no terminal of its own for the target process to inherit
// (see internal/vpnctld/exec.go's execPTY).
func (m Model) execRunCommand(command string) (tea.Model, tea.Cmd) {
	argv := strings.Fields(command)
	if len(argv) == 0 {
		return m, nil
	}

	cmd := &daemonExecCommand{mode: rpc.ExecModeTUI, argv: argv}
	return m, tea.Exec(cmd, func(err error) tea.Msg {
		return runFinishedMsg{cmd: command, err: err}
	})
}

func (m Model) viewRunScreen() string {
	title := titleStyle.Render("RUN — through active profile")
	body := fmt.Sprintf("%s\n\n%s", title, m.run.input.View())
	help := helpBarStyle.Render("enter run (full terminal takeover)  esc back")
	pane := activePaneStyle.Width(m.width - 2).Height(m.height - 4).Render(body)
	return pane + "\n" + help
}

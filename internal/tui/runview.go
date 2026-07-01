package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BeesKnight/vpnctl/internal/netguard"
)

// runScreenModel is the "Run" screen (spec §3.4.1/§4): type a command,
// enter takes over the terminal via tea.ExecProcess and runs it inside the
// active namespace with real stdio (streaming output, TUI programs and all —
// this is the same mechanism spec §3.4.2 calls for when launching a
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

// execRunCommand builds the command inside the active namespace and hands
// it to tea.ExecProcess, which suspends vpnctl's own rendering, gives the
// child direct access to the real terminal (raw mode, alt-screen — full
// takeover, not a pty-emulated pipe), and resumes vpnctl once it exits.
func (m Model) execRunCommand(command string) (tea.Model, tea.Cmd) {
	argv := strings.Fields(command)
	if len(argv) == 0 {
		return m, nil
	}

	ng := netguard.NewLinuxEngine(false)
	cmd, err := ng.Command(argv[0], argv[1:], netguard.ExecOptions{})
	if err != nil {
		return m, func() tea.Msg { return runFinishedMsg{cmd: command, err: err} }
	}

	return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
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

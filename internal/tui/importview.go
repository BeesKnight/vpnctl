package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BeesKnight/vpnctl/internal/importer"
)

// importScreenModel is the "Import" form (spec §3.2/§4): a single input
// that accepts either a subscription URL or a path to a WireGuard/AmneziaWG
// .conf file, dispatched by a simple heuristic (http(s):// vs. anything
// else). A raw pasted .conf isn't handled here (the CLI's
// `vpnctl import --wg <path>` covers scripting) — this form covers the two
// interactive cases the mockup calls for: paste a subscription link, or
// point at a file already on disk.
type importScreenModel struct {
	input textinput.Model
}

func newImportScreen() importScreenModel {
	ti := textinput.New()
	ti.Placeholder = "https://.../api/sub/xxx   or   /path/to/profile.conf"
	ti.Prompt = "> "
	return importScreenModel{input: ti}
}

type importDoneMsg struct {
	kind  string // "subscription" | "wireguard"
	names []string
	err   error
}

func importCmd(value string) tea.Cmd {
	return func() tea.Msg {
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			names, err := importer.ImportSubscription(value)
			return importDoneMsg{kind: "subscription", names: names, err: err}
		}
		name, err := importer.ImportWireGuardFile(value)
		var names []string
		if err == nil {
			names = []string{name}
		}
		return importDoneMsg{kind: "wireguard", names: names, err: err}
	}
}

func (m Model) updateImportScreen(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.screen = screenMain
		m.importScreen.input.Blur()
		return m, nil
	case "enter":
		value := strings.TrimSpace(m.importScreen.input.Value())
		if value == "" {
			return m, nil
		}
		m.message = "importing..."
		return m, importCmd(value)
	}
	var cmd tea.Cmd
	m.importScreen.input, cmd = m.importScreen.input.Update(msg)
	return m, cmd
}

func (m Model) viewImportScreen() string {
	title := titleStyle.Render("IMPORT — subscription URL or WireGuard/AmneziaWG .conf path")
	body := fmt.Sprintf("%s\n\n%s", title, m.importScreen.input.View())
	help := helpBarStyle.Render("enter import  esc back")
	pane := activePaneStyle.Width(m.width - 2).Height(m.height - 4).Render(body)
	return pane + "\n" + help
}

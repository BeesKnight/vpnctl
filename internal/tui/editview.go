package tui

import (
	"os"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"
)

type editDoneMsg struct{ err error }

// handleEdit opens the selected profile's underlying file in $EDITOR (spec
// §4's "e" key), taking over the terminal via tea.ExecProcess exactly like
// Run/Apps launches — $EDITOR is inherently an interactive foreground
// program, so this is the same mechanism, just with a fixed command instead
// of a typed or registry one.
func (m Model) handleEdit() (tea.Model, tea.Cmd) {
	if m.focus != focusProfiles {
		return m, nil
	}
	p, ok := m.selectedProfile()
	if !ok {
		return m, nil
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	cmd := exec.Command(editor, p.Path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
		return editDoneMsg{err: err}
	})
}

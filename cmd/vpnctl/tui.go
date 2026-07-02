package main

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/tui"
)

// runTUI no longer requires root: every network-affecting operation
// (activating a profile, run/test, apps, ps/kill) now goes through
// vpnctld over its socket, so the TUI itself is unprivileged.
func runTUI() error {
	if err := profile.EnsureDirs(); err != nil {
		return err
	}
	p := tea.NewProgram(tui.New(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

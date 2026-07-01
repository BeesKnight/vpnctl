package main

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BeesKnight/vpnctl/internal/actions"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/tui"
)

// runTUI requires root up front, same as every network-affecting CLI
// subcommand: nearly everything reachable from the main screen (activating
// a profile, run/test, apps, ps/kill) is a privileged operation, so failing
// fast here avoids confusing partial failures (e.g. a raw "permission
// denied" from sysctl) surfacing mid-session instead of a clear message
// before the TUI even starts.
func runTUI() error {
	if err := actions.RequireRoot(); err != nil {
		return err
	}
	if err := profile.EnsureDirs(); err != nil {
		return err
	}
	p := tea.NewProgram(tui.New(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

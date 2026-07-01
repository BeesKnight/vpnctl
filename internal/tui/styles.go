package tui

import "github.com/charmbracelet/lipgloss"

var (
	colorAccent = lipgloss.Color("212")
	colorMuted  = lipgloss.Color("241")
	colorGood   = lipgloss.Color("42")
	colorBad    = lipgloss.Color("196")
	colorBorder = lipgloss.Color("240")

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			Padding(0, 1)

	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	activePaneStyle = paneStyle.
			BorderForeground(colorAccent)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent)

	mutedStyle = lipgloss.NewStyle().Foreground(colorMuted)
	goodStyle  = lipgloss.NewStyle().Foreground(colorGood).Bold(true)
	badStyle   = lipgloss.NewStyle().Foreground(colorBad).Bold(true)

	helpBarStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			Padding(0, 1)

	errorStyle = lipgloss.NewStyle().Foreground(colorBad).Bold(true).Padding(0, 1)
)

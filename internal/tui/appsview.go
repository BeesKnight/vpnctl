package tui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BeesKnight/vpnctl/internal/apps"
	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/run"
)

type appItem struct{ a apps.App }

func (i appItem) FilterValue() string { return i.a.Name }

type appDelegate struct{}

func (appDelegate) Height() int                        { return 1 }
func (appDelegate) Spacing() int                       { return 0 }
func (appDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }
func (appDelegate) Render(w io.Writer, m list.Model, index int, it list.Item) {
	item, ok := it.(appItem)
	if !ok {
		return
	}
	width := m.Width()
	cursor := "  "
	selected := index == m.Index()
	if selected {
		cursor = "> "
	}
	tag := fmt.Sprintf("[%s]", item.a.Type)
	line := truncateLine(fmt.Sprintf("%s%-24s %s", cursor, item.a.Name, tag), width)

	style := lipgloss.NewStyle()
	if selected {
		style = style.Bold(true).Foreground(colorAccent)
	}
	fmt.Fprint(w, style.Render(line))
}

func newAppsList() list.Model {
	l := list.New(nil, appDelegate{}, 0, 0)
	l.Title = "APPS"
	l.Styles.Title = headerStyle
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetShowTitle(true)
	l.SetFilteringEnabled(true)
	l.Styles.PaginationStyle = mutedStyle
	return l
}

type appsLoadedMsg struct {
	apps []apps.App
	err  error
}

func loadAppsCmd() tea.Msg {
	list, err := apps.Load()
	return appsLoadedMsg{apps: list, err: err}
}

// launchApp dispatches based on the app's declared type: GUI
// apps launch detached (vpnctl keeps running, nothing to wait for); CLI/TUI
// apps take over the real terminal via tea.ExecProcess exactly like the Run
// screen, since both need real stdio, just with a known, pre-configured
// command instead of a typed one.
func (m Model) launchApp(a apps.App) (tea.Model, tea.Cmd) {
	ng := netguard.NewLinuxEngine(false)

	if a.Type == apps.TypeGUI {
		return m, func() tea.Msg {
			pid, err := run.GUI(ng, a.Command)
			return appLaunchedMsg{name: a.Name, pid: pid, err: err}
		}
	}

	cmd, err := ng.Command(a.Command[0], a.Command[1:], netguard.ExecOptions{})
	if err != nil {
		return m, func() tea.Msg { return runFinishedMsg{cmd: a.Name, err: err} }
	}
	return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
		return runFinishedMsg{cmd: a.Name, err: err}
	})
}

type appLaunchedMsg struct {
	name string
	pid  int
	err  error
}


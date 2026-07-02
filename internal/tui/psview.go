package tui

import (
	"fmt"
	"io"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

type processItem struct{ p netguard.ProcessInfo }

func (i processItem) FilterValue() string { return i.p.Name }

type processDelegate struct{}

func (processDelegate) Height() int                        { return 1 }
func (processDelegate) Spacing() int                       { return 0 }
func (processDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }
func (processDelegate) Render(w io.Writer, m list.Model, index int, it list.Item) {
	item, ok := it.(processItem)
	if !ok {
		return
	}
	width := m.Width()
	cursor := "  "
	selected := index == m.Index()
	if selected {
		cursor = "> "
	}
	uptime := time.Since(item.p.StartedAt).Round(time.Second)
	line := truncateLine(fmt.Sprintf("%spid %-8d %-20s [%s]  %s up", cursor, item.p.PID, item.p.Name, item.p.Type, uptime), width)

	style := lipgloss.NewStyle()
	if selected {
		style = style.Bold(true).Foreground(colorAccent)
	}
	fmt.Fprint(w, style.Render(line))
}

func newProcessList() list.Model {
	l := list.New(nil, processDelegate{}, 0, 0)
	l.Title = "RUNNING (through active profile)"
	l.Styles.Title = headerStyle
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetShowTitle(true)
	l.SetFilteringEnabled(false)
	return l
}

type processesLoadedMsg struct {
	procs []netguard.ProcessInfo
	err   error
}

func loadProcessesCmd() tea.Msg {
	procs, err := vpnctlclient.ListProcesses()
	return processesLoadedMsg{procs: procs, err: err}
}

type processKilledMsg struct {
	name string
	err  error
}

func killSelectedProcessCmd(target string) tea.Cmd {
	return func() tea.Msg {
		pi, err := vpnctlclient.KillProcess(target)
		if err != nil {
			return processKilledMsg{err: err}
		}
		return processKilledMsg{name: pi.Name}
	}
}


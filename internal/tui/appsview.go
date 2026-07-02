package tui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BeesKnight/vpnctl/internal/apps"
	"github.com/BeesKnight/vpnctl/internal/rpc"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
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

// launchApp dispatches based on the app's declared type: GUI apps launch
// detached through vpnctld (vpnctl keeps running, nothing to wait for,
// same as `vpnctl run --gui`); CLI/TUI apps take over the real terminal
// via tea.Exec exactly like the Run screen (see execcmd.go), since both
// need real stdio through a daemon-side PTY, just with a known,
// pre-configured command instead of a typed one.
func (m Model) launchApp(a apps.App) (tea.Model, tea.Cmd) {
	if a.Type == apps.TypeGUI {
		return m, func() tea.Msg {
			// sysuser.RealUIDGID/ResolveGUIEnv: same resolution
			// cmd/vpnctl/run.go's --gui mode uses — the daemon must never
			// run a GUI app as root.
			uid, gid, err := sysuser.RealUIDGID()
			if err != nil {
				return appLaunchedMsg{name: a.Name, err: fmt.Errorf("resolving real user for privilege drop: %w", err)}
			}
			opts := vpnctlclient.ExecOptions{Env: sysuser.ResolveGUIEnv(uid), DropUID: &uid, DropGID: &gid}
			result, err := vpnctlclient.Exec(rpc.ExecModeGUI, a.Command, opts)
			return appLaunchedMsg{name: a.Name, pid: result.PID, err: err}
		}
	}

	mode := rpc.ExecModeCLI
	if a.Type == apps.TypeTUI {
		mode = rpc.ExecModeTUI
	}
	cmd := &daemonExecCommand{mode: mode, argv: a.Command}
	return m, tea.Exec(cmd, func(err error) tea.Msg {
		return runFinishedMsg{cmd: a.Name, err: err}
	})
}

type appLaunchedMsg struct {
	name string
	pid  int
	err  error
}


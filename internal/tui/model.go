// Package tui is vpnctl's full-screen interactive interface, built on
// bubbletea/bubbles/lipgloss — profile list, live status, logs,
// apps and running-processes panels, all visible at once (as in the spec's
// mockup), plus dedicated Run/Import screens for the two actions that need
// a full-width input. Closing the TUI never tears down the active
// namespace: the namespace and engine process are independent OS state (see
// internal/netguard's ActiveState), so this package only ever reads/
// refreshes that state, never assumes it owns it.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BeesKnight/vpnctl/internal/actions"
	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

type screen int

const (
	screenMain screen = iota
	screenRun
	screenImport
)

// focusPane is which of the main screen's navigable panels currently has
// keyboard focus — mirrors the mockup's four simultaneous panels
// (Profiles/Status/Apps/Running), of which Profiles/Apps/Running are
// navigable lists and Status(+Logs) is read-only display.
type focusPane int

const (
	focusProfiles focusPane = iota
	focusApps
	focusRunning
)

// Model is vpnctl's top-level bubbletea model.
type Model struct {
	screen screen
	focus  focusPane

	list         list.Model
	appsList     list.Model
	psList       list.Model
	help         help.Model
	run          runScreenModel
	importScreen importScreenModel

	status     netguard.Status
	healthy    bool
	statusErr  error
	activating bool
	message    string // transient status-line message (e.g. test result, error)

	width, height int
	ready         bool
}

func New() Model {
	l := list.New(nil, profileDelegate{}, 0, 0)
	l.Title = "PROFILES"
	l.Styles.Title = headerStyle
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetShowTitle(true)
	l.SetFilteringEnabled(true)
	l.Styles.PaginationStyle = mutedStyle

	return Model{
		list:         l,
		appsList:     newAppsList(),
		psList:       newProcessList(),
		help:         help.New(),
		run:          newRunScreen(),
		importScreen: newImportScreen(),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(loadProfilesCmd, loadAppsCmd, loadProcessesCmd, refreshStatusCmd, tickCmd())
}

// ---- messages ----

type profilesLoadedMsg struct {
	profiles []profile.Profile
	err      error
}

type statusMsg struct {
	status  netguard.Status
	healthy bool
	err     error
}

type activateDoneMsg struct {
	profile profile.Profile
	status  netguard.Status
	err     error
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func loadProfilesCmd() tea.Msg {
	profiles, err := profile.LoadAll()
	return profilesLoadedMsg{profiles: profiles, err: err}
}

func refreshStatusCmd() tea.Msg {
	status, healthy, err := actions.CurrentStatus()
	return statusMsg{status: status, healthy: healthy, err: err}
}

func activateCmd(name string) tea.Cmd {
	return func() tea.Msg {
		p, status, _, err := actions.Activate(name)
		return activateDoneMsg{profile: p, status: status, err: err}
	}
}

// ---- update ----

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ready = true
		m.applySize()
		return m, nil

	case tickMsg:
		return m, tea.Batch(refreshStatusCmd, loadProcessesCmd, tickCmd())

	case profilesLoadedMsg:
		if msg.err != nil {
			m.message = errorStyle.Render("loading profiles: " + msg.err.Error())
			return m, nil
		}
		m.list.SetItems(buildProfileItems(msg.profiles))
		m.selectFirstProfile()
		return m, nil

	case statusMsg:
		m.statusErr = msg.err
		if msg.err == nil {
			m.status = msg.status
			m.healthy = msg.healthy
		}
		return m, nil

	case activateDoneMsg:
		m.activating = false
		if msg.err != nil {
			m.message = errorStyle.Render("activate failed: " + msg.err.Error())
			return m, nil
		}
		m.message = fmt.Sprintf("%s activated (%s:%d/%s)", msg.profile.DisplayName(), msg.status.ResolvedIP, msg.status.ResolvedPort, msg.status.Protocol)
		return m, refreshStatusCmd

	case testDoneMsg:
		if msg.err != nil {
			m.message = errorStyle.Render("test failed: " + msg.err.Error())
		} else if msg.result.ExitCode != 0 {
			m.message = errorStyle.Render(fmt.Sprintf("test failed (curl exit %d) — kill-switch held", msg.result.ExitCode))
		} else {
			m.message = fmt.Sprintf("test ok (%s)", msg.result.Elapsed.Round(time.Millisecond))
		}
		return m, nil

	case runFinishedMsg:
		m.screen = screenMain
		if msg.err != nil {
			m.message = errorStyle.Render(fmt.Sprintf("run %q: %v", msg.cmd, msg.err))
		} else {
			m.message = fmt.Sprintf("finished: %s", msg.cmd)
		}
		return m, tea.Batch(refreshStatusCmd, loadProcessesCmd)

	case appsLoadedMsg:
		if msg.err != nil {
			m.message = errorStyle.Render("loading apps.yaml: " + msg.err.Error())
			return m, nil
		}
		items := make([]list.Item, 0, len(msg.apps))
		for _, a := range msg.apps {
			items = append(items, appItem{a: a})
		}
		m.appsList.SetItems(items)
		return m, nil

	case appLaunchedMsg:
		if msg.err != nil {
			m.message = errorStyle.Render("launch failed: " + msg.err.Error())
		} else {
			m.message = fmt.Sprintf("launched %s detached, pid %d", msg.name, msg.pid)
		}
		return m, loadProcessesCmd

	case processesLoadedMsg:
		if msg.err != nil {
			m.message = errorStyle.Render("loading processes: " + msg.err.Error())
			return m, nil
		}
		items := make([]list.Item, 0, len(msg.procs))
		for _, p := range msg.procs {
			items = append(items, processItem{p: p})
		}
		m.psList.SetItems(items)
		return m, nil

	case processKilledMsg:
		if msg.err != nil {
			m.message = errorStyle.Render("kill failed: " + msg.err.Error())
		} else {
			m.message = fmt.Sprintf("killed %s", msg.name)
		}
		return m, loadProcessesCmd

	case importDoneMsg:
		m.screen = screenMain
		m.importScreen.input.SetValue("")
		m.importScreen.input.Blur()
		if msg.err != nil {
			m.message = errorStyle.Render("import failed: " + msg.err.Error())
			return m, nil
		}
		m.message = fmt.Sprintf("imported %d profile(s): %s", len(msg.names), strings.Join(msg.names, ", "))
		return m, loadProfilesCmd

	case editDoneMsg:
		if msg.err != nil {
			m.message = errorStyle.Render("edit failed: " + msg.err.Error())
		} else {
			m.message = "profile edited"
		}
		return m, loadProfilesCmd

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m *Model) applySize() {
	if !m.ready {
		return
	}
	leftW, rightW, rowH, _, _ := m.paneDimensions()

	m.list.SetSize(leftW, rowH)
	m.appsList.SetSize(leftW, rowH)
	m.psList.SetSize(rightW, rowH)
	m.run.input.Width = m.width - 8
	m.importScreen.input.Width = m.width - 8
}

func (m *Model) selectFirstProfile() {
	for i, it := range m.list.Items() {
		if pi, ok := it.(profileItem); ok && !pi.IsHeader() {
			m.list.Select(i)
			return
		}
	}
}

// skipHeaders moves the list cursor off a header item in the given
// direction (+1/-1), since headers aren't meant to be "selected".
func (m *Model) skipHeaders(dir int) {
	items := m.list.Items()
	if len(items) == 0 {
		return
	}
	idx := m.list.Index()
	for i := 0; i < len(items); i++ {
		if pi, ok := items[idx].(profileItem); !ok || !pi.IsHeader() {
			return
		}
		idx += dir
		if idx < 0 {
			idx = len(items) - 1
		}
		if idx >= len(items) {
			idx = 0
		}
		m.list.Select(idx)
	}
}

func (m Model) selectedProfile() (profile.Profile, bool) {
	if it, ok := m.list.SelectedItem().(profileItem); ok && !it.isHeader {
		return it.p, true
	}
	return profile.Profile{}, false
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenRun:
		return m.updateRunScreen(msg)
	case screenImport:
		return m.updateImportScreen(msg)
	}

	// While a list's filter input is active, let it consume keys first so
	// typing "firefox" doesn't get intercepted as a hotkey.
	if m.focusedListFiltering() {
		return m.updateFocusedList(msg)
	}

	switch {
	case key.Matches(msg, keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, keys.Help):
		m.help.ShowAll = !m.help.ShowAll
		return m, nil

	case key.Matches(msg, keys.Filter):
		return m.updateFocusedList(msg)

	case key.Matches(msg, keys.Reload):
		return m, tea.Batch(loadProfilesCmd, loadAppsCmd, loadProcessesCmd)

	case key.Matches(msg, keys.Tab):
		m.focus = (m.focus + 1) % 3
		return m, nil

	case key.Matches(msg, keys.Enter):
		return m.handleEnter()

	case key.Matches(msg, keys.Deactivate):
		if err := actions.Deactivate(); err != nil {
			m.message = errorStyle.Render("down: " + err.Error())
		} else {
			m.message = "profile deactivated"
		}
		return m, refreshStatusCmd

	case key.Matches(msg, keys.Test):
		return m, testCmd()

	case key.Matches(msg, keys.Run):
		m.screen = screenRun
		m.run.input.Focus()
		return m, nil

	case key.Matches(msg, keys.Import):
		m.screen = screenImport
		m.importScreen.input.Focus()
		return m, nil

	case key.Matches(msg, keys.Apps):
		m.focus = focusApps
		return m, nil

	case key.Matches(msg, keys.Ps):
		m.focus = focusRunning
		return m, nil

	case key.Matches(msg, keys.Edit):
		return m.handleEdit()

	case key.Matches(msg, keys.Kill) && m.focus == focusRunning:
		if it, ok := m.psList.SelectedItem().(processItem); ok {
			return m, killSelectedProcessCmd(fmt.Sprintf("%d", it.p.PID))
		}
		return m, nil

	case key.Matches(msg, keys.Up), key.Matches(msg, keys.Down):
		cmd := m.moveFocusedList(key.Matches(msg, keys.Down))
		return m, cmd
	}

	return m.updateFocusedList(msg)
}

// handleEnter dispatches "enter" based on which panel has focus: activate a
// profile, or launch an app.
func (m Model) handleEnter() (tea.Model, tea.Cmd) {
	switch m.focus {
	case focusProfiles:
		if p, ok := m.selectedProfile(); ok {
			m.activating = true
			m.message = fmt.Sprintf("activating %s...", p.DisplayName())
			return m, activateCmd(p.Name)
		}
	case focusApps:
		if it, ok := m.appsList.SelectedItem().(appItem); ok {
			return m.launchApp(it.a)
		}
	}
	return m, nil
}

func (m Model) focusedListFiltering() bool {
	switch m.focus {
	case focusProfiles:
		return m.list.FilterState() == list.Filtering
	case focusApps:
		return m.appsList.FilterState() == list.Filtering
	default:
		return false
	}
}

func (m Model) updateFocusedList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.focus {
	case focusProfiles:
		m.list, cmd = m.list.Update(msg)
	case focusApps:
		m.appsList, cmd = m.appsList.Update(msg)
	case focusRunning:
		m.psList, cmd = m.psList.Update(msg)
	}
	return m, cmd
}

func (m *Model) moveFocusedList(down bool) tea.Cmd {
	msg := tea.KeyMsg{Type: tea.KeyUp}
	if down {
		msg = tea.KeyMsg{Type: tea.KeyDown}
	}
	var cmd tea.Cmd
	switch m.focus {
	case focusProfiles:
		m.list, cmd = m.list.Update(msg)
		if down {
			m.skipHeaders(1)
		} else {
			m.skipHeaders(-1)
		}
	case focusApps:
		m.appsList, cmd = m.appsList.Update(msg)
	case focusRunning:
		m.psList, cmd = m.psList.Update(msg)
	}
	return cmd
}

type testDoneMsg struct {
	result actions.TestResult
	err    error
}

func testCmd() tea.Cmd {
	return func() tea.Msg {
		res, err := actions.TestConnectivity()
		return testDoneMsg{result: res, err: err}
	}
}

// ---- view ----

func (m Model) View() string {
	if !m.ready {
		return "loading..."
	}
	switch m.screen {
	case screenRun:
		return m.viewRunScreen()
	case screenImport:
		return m.viewImportScreen()
	default:
		return m.viewMain()
	}
}

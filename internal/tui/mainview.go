package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/BeesKnight/vpnctl/internal/netguard"
)

// viewMain renders all four panels at once (Profiles/Status/Apps/Running mockup), 
// with the currently-focused panel's border highlighted,
// matching the k9s/lazygit feel of "everything visible, tab moves focus"
// rather than modal full-screen sub-views.
func (m Model) viewMain() string {
	leftW, rightW, rowH, statusH, logsH := m.paneDimensions()

	profilesPane := m.paneStyle(focusProfiles, leftW, rowH).Render(m.list.View())
	statusPane := paneStyle.Width(rightW).Height(statusH).Render(m.viewStatus())
	logsPane := paneStyle.Width(rightW).Height(logsH).Render(m.viewLogs())
	topRight := lipgloss.JoinVertical(lipgloss.Left, statusPane, logsPane)
	top := lipgloss.JoinHorizontal(lipgloss.Top, profilesPane, topRight)

	appsPane := m.paneStyle(focusApps, leftW, rowH).Render(m.appsList.View())
	runningPane := m.paneStyle(focusRunning, rightW, rowH).Render(m.psList.View())
	bottom := lipgloss.JoinHorizontal(lipgloss.Top, appsPane, runningPane)

	body := lipgloss.JoinVertical(lipgloss.Left, top, bottom)
	return lipgloss.JoinVertical(lipgloss.Left, body, m.viewBottomBar())
}

// paneDimensions computes every pane's *content* (interior, border-excluded)
// width/height from the terminal size, shared by viewMain and applySize so
// the two can never drift apart. Each rendered box adds 2 rows (top+bottom
// border) and 2 columns (left+right border) beyond these content
// dimensions — the top-right column stacks two boxes (status, logs), so
// its two content heights must sum to rowH minus *both* boxes' border
// overhead (4 rows), not rowH itself.
func (m Model) paneDimensions() (leftW, rightW, rowH, statusH, logsH int) {
	leftW = m.width*2/5 - 4
	rightW = m.width - (leftW + 4) - 4

	// R is each row's total rendered height (border included). Single-box
	// rows (profiles, apps, running) get content height R-2. The top-right
	// column stacks two boxes (status, logs) inside that same R, so their
	// content heights must sum to R minus *both* boxes' border overhead (4).
	rowTotal := (m.height - 1) / 2
	rowH = rowTotal - 2

	rightColBudget := rowTotal - 4
	statusH = rightColBudget / 3
	if statusH < 3 {
		statusH = 3
	}
	logsH = rightColBudget - statusH
	if logsH < 3 {
		logsH = 3
	}
	return
}

// paneStyle returns the highlighted border style when pane is focused, the
// plain one otherwise.
func (m Model) paneStyle(pane focusPane, width, height int) lipgloss.Style {
	style := paneStyle
	if m.focus == pane {
		style = activePaneStyle
	}
	return style.Width(width).Height(height)
}

func (m Model) viewStatus() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("STATUS") + "\n")

	if m.statusErr != nil {
		b.WriteString(errorStyle.Render(m.statusErr.Error()))
		return b.String()
	}
	if !m.status.Active {
		b.WriteString(mutedStyle.Render("No active profile."))
		if m.message != "" {
			b.WriteString("\n" + m.message)
		}
		return b.String()
	}

	state := badStyle.Render("DOWN / NO ROUTE")
	if m.healthy {
		state = goodStyle.Render("UP")
	}
	if m.activating {
		state = mutedStyle.Render("activating...")
	}

	fmt.Fprintf(&b, "Active: %s (%s)\n", m.status.ProfileName, m.status.ProfileKind)
	fmt.Fprintf(&b, "State:  %s\n", state)
	fmt.Fprintf(&b, "netns:  %s (kill-switch ON)\n", m.status.Namespace)
	fmt.Fprintf(&b, "Server: %s:%d/%s", m.status.ResolvedIP, m.status.ResolvedPort, m.status.Protocol)
	if m.message != "" {
		b.WriteString("\n" + m.message)
	}
	return b.String()
}

func (m Model) viewLogs() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("LOGS") + "\n")

	state, err := netguard.LoadActiveState()
	if err != nil || state == nil || state.EngineLog == "" {
		b.WriteString(mutedStyle.Render("(no engine running)"))
		return b.String()
	}
	lines := tailFile(state.EngineLog, 6)
	if len(lines) == 0 {
		b.WriteString(mutedStyle.Render("(no output yet)"))
		return b.String()
	}
	b.WriteString(strings.Join(lines, "\n"))
	return b.String()
}

func (m Model) viewBottomBar() string {
	return helpBarStyle.Render(m.help.View(keys))
}

// tailFile returns the last n non-empty lines of path, best-effort (used
// for the TUI's live-ish log panel — refreshed on every status tick).
func tailFile(path string, n int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}

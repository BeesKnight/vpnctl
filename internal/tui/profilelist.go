package tui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

// profileItem is either a selectable profile row or a non-selectable
// section header ("[WG/AmneziaWG]", "[VLESS]", "[Hysteria2]" — see the TUI
// mockup). bubbles/list has no native concept of unselectable
// items, so headers are skipped explicitly by the cursor-movement logic in
// model.go rather than by the list widget itself.
type profileItem struct {
	p        profile.Profile
	isHeader bool
	header   string
}

func (i profileItem) IsHeader() bool { return i.isHeader }

func (i profileItem) FilterValue() string {
	if i.isHeader {
		return ""
	}
	return fmt.Sprintf("%s %s %s", i.p.Name, i.p.Country, i.p.Kind)
}

// buildProfileItems groups profiles the same way `vpnctl list` does
// (profile.Profile.Group/GroupLabel), inserting a header item before each
// new group.
func buildProfileItems(profiles []profile.Profile) []list.Item {
	items := make([]list.Item, 0, len(profiles))
	lastGroup := -1
	for _, p := range profiles {
		if g := p.Group(); g != lastGroup {
			items = append(items, profileItem{isHeader: true, header: "[" + p.GroupLabel() + "]"})
			lastGroup = g
		}
		items = append(items, profileItem{p: p})
	}
	return items
}

// profileDelegate renders each row compactly (one line, no bubbles default
// title/description padding) to match the density of the mockup, and
// highlights whichever profile is currently active in the namespace.
type profileDelegate struct {
	activeName string
}

func (d profileDelegate) Height() int                        { return 1 }
func (d profileDelegate) Spacing() int                        { return 0 }
func (d profileDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

// Render draws one compact line per row — cursor, name, and a kill-switch
// marker for whichever profile is currently active — matching the density
// of the mockup. Crucially, it truncates to the list's actual
// allotted width: an earlier version formatted name+kind+endpoint into a
// single ~60-column string regardless of width, which lipgloss then
// line-wrapped inside the narrower profiles pane, silently inflating the
// pane's rendered height beyond what the layout budgeted and pushing the
// top of the screen off into the terminal's scrollback.
func (d profileDelegate) Render(w io.Writer, m list.Model, index int, it list.Item) {
	item, ok := it.(profileItem)
	if !ok {
		return
	}
	width := m.Width()
	if item.isHeader {
		fmt.Fprint(w, headerStyle.Render(truncateLine(item.header, width)))
		return
	}

	cursor := "  "
	selected := index == m.Index()
	if selected {
		cursor = "> "
	}

	marker := ""
	if item.p.Name == d.activeName {
		marker = "  ●active"
	}

	line := truncateLine(cursor+item.p.DisplayName(), width-len([]rune(marker))) + marker

	style := lipgloss.NewStyle()
	switch {
	case selected:
		style = style.Bold(true).Foreground(colorAccent)
	case item.p.Name == d.activeName:
		style = style.Foreground(colorGood)
	}
	fmt.Fprint(w, style.Render(line))
}

// truncateLine hard-truncates a plain (unstyled) string to at most width
// runes, never wrapping onto a second line. Must be applied before any
// lipgloss styling — truncating already-styled (ANSI-wrapped) text by rune
// count would risk slicing through an escape sequence.
func truncateLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) > width {
		r = r[:width]
	}
	return string(r)
}

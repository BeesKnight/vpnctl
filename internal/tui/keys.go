package tui

import "github.com/charmbracelet/bubbles/key"

// keyMap is vpnctl's full hotkey surface. Bound to bubbles/help so
// the bottom bar and the "?" full-help screen render from one source of
// truth instead of two hand-maintained strings drifting apart.
type keyMap struct {
	Up         key.Binding
	Down       key.Binding
	Enter      key.Binding
	Tab        key.Binding
	Test       key.Binding
	Run        key.Binding
	Import     key.Binding
	Apps       key.Binding
	Ps         key.Binding
	Edit       key.Binding
	Kill       key.Binding
	Deactivate key.Binding
	Reload     key.Binding
	Filter     key.Binding
	Help       key.Binding
	Quit       key.Binding
}

var keys = keyMap{
	Up:         key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:       key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Enter:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "activate")),
	Tab:        key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "switch panel")),
	Test:       key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "test")),
	Run:        key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "run")),
	Import:     key.NewBinding(key.WithKeys("i"), key.WithHelp("i", "import")),
	Apps:       key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "apps")),
	Ps:         key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "processes")),
	Edit:       key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "edit")),
	Kill:       key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "kill process")),
	Deactivate: key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "down")),
	Reload:     key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "reload")),
	Filter:     key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Help:       key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	Quit:       key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}

// ShortHelp implements help.KeyMap: the single bottom line shown by default.
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Enter, k.Tab, k.Test, k.Run, k.Import, k.Apps, k.Ps, k.Deactivate, k.Help, k.Quit}
}

// FullHelp implements help.KeyMap: the expanded "?" screen.
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Enter, k.Tab, k.Filter},
		{k.Test, k.Run, k.Import, k.Apps, k.Ps, k.Edit, k.Kill},
		{k.Deactivate, k.Reload, k.Help, k.Quit},
	}
}

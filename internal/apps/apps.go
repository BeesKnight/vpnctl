// Package apps manages vpnctl's application registry (~/.config/vpnctl/
// apps.yaml), so the TUI's Apps panel can launch a
// pre-configured program (Firefox, Burp, htop, an nmap scan, ...) through
// the active profile with the correct launch mode (gui/tui/cli) already
// known, without the user re-typing a command or remembering flags.
package apps

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// Type is how an app must be launched — see internal/run for what each
// means in practice (blocking+streamed, terminal-takeover, or detached).
type Type string

const (
	TypeGUI Type = "gui"
	TypeTUI Type = "tui"
	TypeCLI Type = "cli"
)

// App is one entry in apps.yaml.
type App struct {
	Name    string   `yaml:"name"`
	Type    Type     `yaml:"type"`
	Command []string `yaml:"command"`
}

type registry struct {
	Apps []App `yaml:"apps"`
}

// defaultRegistry seeds a first-run apps.yaml so the Apps panel is never
// empty and doubles as a working example of the file format.
var defaultRegistry = registry{Apps: []App{
	{Name: "Firefox", Type: TypeGUI, Command: []string{"firefox"}},
	{Name: "htop", Type: TypeTUI, Command: []string{"htop"}},
	{Name: "curl ifconfig.me", Type: TypeCLI, Command: []string{"curl", "https://ifconfig.me"}},
}}

// ConfigPath returns ~/.config/vpnctl/apps.yaml (real user's home, even under sudo).
func ConfigPath() (string, error) {
	home, err := sysuser.RealHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "vpnctl", "apps.yaml"), nil
}

// Load reads the app registry, writing out defaultRegistry the first time
// the file doesn't exist yet.
func Load() ([]App, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := writeDefault(path); err != nil {
			return nil, fmt.Errorf("writing default apps.yaml: %w", err)
		}
		return append([]App(nil), defaultRegistry.Apps...), nil
	}
	var reg registry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return reg.Apps, nil
}

func writeDefault(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(defaultRegistry)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return sysuser.ChownToRealUserIfRoot(dir, path)
}

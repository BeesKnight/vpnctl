// Package profile reads, writes, and imports VPN/proxy profiles used by vpnctl.
package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// Family is the top-level profile category, mirroring the on-disk directory layout.
type Family string

const (
	FamilyWG    Family = "wg"
	FamilyProxy Family = "proxy"
)

// Kind identifies the concrete protocol of a profile.
type Kind string

const (
	KindWireGuard Kind = "wireguard"
	KindAmneziaWG Kind = "amneziawg"
	KindVLESS     Kind = "vless"
	KindHysteria2 Kind = "hysteria2"
	KindUnknown   Kind = "unknown"
)

// Profile is a single VPN/proxy configuration, as read from disk.
type Profile struct {
	Name    string // file name without extension, also the profile's unique id
	Family  Family
	Kind    Kind
	Server  string
	Port    int
	Country string
	Label   string // optional human-readable override from a sidecar meta.yaml
	Path    string // absolute path to the underlying .conf/.json file

	WG       *WireGuardConfig // set when Family == FamilyWG
	Outbound map[string]any   // set when Family == FamilyProxy (raw sing-box outbound object)

	// Backup names another profile to auto-activate on sustained
	// connectivity loss (see Meta.Backup / internal/vpnctld/failover.go).
	// Empty when not configured — auto-failover is opt-in per profile.
	Backup string
}

// DisplayName is what the TUI/list output should show for this profile.
func (p Profile) DisplayName() string {
	name := p.Name
	if p.Label != "" {
		name = p.Label
	}
	if p.Country != "" {
		return fmt.Sprintf("%s (%s)", name, p.Country)
	}
	return name
}

// Endpoint returns "server:port" for display purposes.
func (p Profile) Endpoint() string {
	if p.Server == "" {
		return ""
	}
	if p.Port == 0 {
		return p.Server
	}
	return fmt.Sprintf("%s:%d", p.Server, p.Port)
}

// Dir returns the base directory holding profiles: ~/.config/vpnctl/profiles.
// Resolves to the real user's home even when running under sudo, since
// profiles must belong to the human at the desktop, not root.
func Dir() (string, error) {
	home, err := sysuser.RealHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "vpnctl", "profiles"), nil
}

// EnsureDirs creates the profile directory tree if it doesn't exist yet.
// When running as root under sudo, newly created directories are chowned
// back to the real user so profiles remain user-owned, not root-owned.
func EnsureDirs() error {
	base, err := Dir()
	if err != nil {
		return err
	}
	configDir := filepath.Dir(base) // ~/.config/vpnctl
	dirs := []string{
		configDir,
		base,
		filepath.Join(base, string(FamilyWG)),
		filepath.Join(base, string(FamilyProxy)),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return sysuser.ChownToRealUserIfRoot(dirs...)
}

// LoadAll reads every profile under the profiles directory, grouped by family.
func LoadAll() ([]Profile, error) {
	base, err := Dir()
	if err != nil {
		return nil, err
	}
	return LoadAllFromDir(base)
}

// LoadAllFromDir is LoadAll against an explicit profiles base directory
// instead of resolving one from the current process's own real user. Only
// vpnctld's failover.go needs this: it runs as a single system-wide daemon
// with no "current user" of its own, but a specific target uid (whoever
// ran Activate, from SO_PEERCRED) whose profiles directory it needs to
// consult to resolve a backup profile by name — every other caller wants
// the calling process's own profiles and should keep using LoadAll/Find.
func LoadAllFromDir(base string) ([]Profile, error) {
	var out []Profile

	wgProfiles, err := loadWGDir(filepath.Join(base, string(FamilyWG)))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading wg profiles: %w", err)
	}
	out = append(out, wgProfiles...)

	proxyProfiles, err := loadProxyDir(filepath.Join(base, string(FamilyProxy)))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading proxy profiles: %w", err)
	}
	out = append(out, proxyProfiles...)

	sort.Slice(out, func(i, j int) bool {
		if gi, gj := out[i].Group(), out[j].Group(); gi != gj {
			return gi < gj
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Group buckets a profile for display purposes: WireGuard and AmneziaWG are
// shown together, VLESS and Hysteria2 each get their own section (see the
// TUI layout mockup in the spec).
func (p Profile) Group() int {
	switch {
	case p.Family == FamilyWG:
		return 0
	case p.Kind == KindVLESS:
		return 1
	case p.Kind == KindHysteria2:
		return 2
	default:
		return 3
	}
}

// GroupLabel is the section header to print/render above this profile's group.
func (p Profile) GroupLabel() string {
	switch p.Group() {
	case 0:
		return "WG/AmneziaWG"
	case 1:
		return "VLESS"
	case 2:
		return "Hysteria2"
	default:
		return "Other"
	}
}

// Find loads a single profile by name, searching both families.
func Find(name string) (Profile, error) {
	all, err := LoadAll()
	if err != nil {
		return Profile{}, err
	}
	return findIn(all, name)
}

// FindInDir is Find against an explicit profiles base directory — see
// LoadAllFromDir's doc comment for why this exists.
func FindInDir(base, name string) (Profile, error) {
	all, err := LoadAllFromDir(base)
	if err != nil {
		return Profile{}, err
	}
	return findIn(all, name)
}

func findIn(all []Profile, name string) (Profile, error) {
	for _, p := range all {
		if p.Name == name {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("profile %q not found", name)
}

func loadWGDir(dir string) ([]Profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Profile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		wg, err := ParseWireGuardFile(path)
		if err != nil {
			// Skip unparseable files rather than failing the whole list.
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".conf")
		meta := loadMeta(path)
		country := meta.Country
		if country == "" {
			country = guessCountry(name)
		}
		out = append(out, Profile{
			Name:    name,
			Family:  FamilyWG,
			Kind:    wg.Kind(),
			Server:  wg.Peer.Host(),
			Port:    wg.Peer.PortNum(),
			Country: country,
			Label:   meta.Label,
			Path:    path,
			WG:      wg,
			Backup:  meta.Backup,
		})
	}
	return out, nil
}

func loadProxyDir(dir string) ([]Profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Profile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		outbound, err := ParseOutboundFile(path)
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		kind := kindFromOutboundType(fmt.Sprint(outbound["type"]))
		server, _ := outbound["server"].(string)
		port := 0
		switch v := outbound["server_port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		}
		meta := loadMeta(path)
		country := meta.Country
		if country == "" {
			country = guessCountry(name)
		}
		out = append(out, Profile{
			Name:     name,
			Family:   FamilyProxy,
			Kind:     kind,
			Server:   server,
			Port:     port,
			Country:  country,
			Label:    meta.Label,
			Path:     path,
			Outbound: outbound,
			Backup:   meta.Backup,
		})
	}
	return out, nil
}

func kindFromOutboundType(t string) Kind {
	switch strings.ToLower(t) {
	case "vless":
		return KindVLESS
	case "hysteria2":
		return KindHysteria2
	default:
		return KindUnknown
	}
}

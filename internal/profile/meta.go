package profile

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Meta is an optional sidecar manifest (<profile-name>.yaml, next to the
// .conf/.json file) letting the user override auto-detected display fields.
type Meta struct {
	Country string `yaml:"country"`
	Label   string `yaml:"label"`
	// Backup, if set, names another profile vpnctld should auto-activate
	// if this one's health check detects sustained connectivity loss —
	// see internal/vpnctld/failover.go. Not validated at load time (the
	// named profile might not exist, or might itself be missing by the
	// time a failover actually happens) — Activate's own "profile not
	// found" error surfaces that at failover time instead, logged rather
	// than silently swallowed.
	Backup string `yaml:"backup"`
}

// loadMeta looks for a sidecar manifest next to profilePath and applies any
// overrides it contains. Absence of the file is not an error.
func loadMeta(profilePath string) Meta {
	metaPath := strings.TrimSuffix(profilePath, extOf(profilePath)) + ".yaml"
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return Meta{}
	}
	var m Meta
	if err := yaml.Unmarshal(data, &m); err != nil {
		return Meta{}
	}
	return m
}

func extOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i:]
		}
		if path[i] == '/' {
			break
		}
	}
	return ""
}

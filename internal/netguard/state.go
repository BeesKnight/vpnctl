package netguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// StateDir returns ~/.local/state/vpnctl (real user's home, even under sudo).
func StateDir() (string, error) {
	home, err := sysuser.RealHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "vpnctl"), nil
}

// EnsureStateDir creates the state directory (chowned to the real user when
// running as root under sudo) and returns its path.
func EnsureStateDir() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := sysuser.ChownToRealUserIfRoot(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// ProcessInfo tracks one process launched through the active profile
// (vpnctl run/run --tui/run --gui), for `vpnctl ps` / `vpnctl kill`.
type ProcessInfo struct {
	PID       int       `json:"pid"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // "cli" | "tui" | "gui"
	Command   []string  `json:"command"`
	StartedAt time.Time `json:"started_at"`
}

// ActiveState is the persisted record of the currently-active profile and
// namespace, read by `vpnctl status`/the TUI on startup so a session survives
// closing and reopening vpnctl (the namespace and engine process are
// detached from the vpnctl process that created them).
type ActiveState struct {
	ProfileName  string        `json:"profile_name"`
	ProfileKind  string        `json:"profile_kind"`
	Namespace    string        `json:"namespace"`
	ResolvedIP   string        `json:"resolved_ip"`
	ResolvedPort int           `json:"resolved_port"`
	Protocol     string        `json:"protocol"`
	EnginePID    int           `json:"engine_pid"`
	EngineKind   string        `json:"engine_kind"` // "awg-quick" | "sing-box"
	EngineLog    string        `json:"engine_log"`  // path to the engine's captured stdout/stderr
	HealthPID    int           `json:"health_pid"`  // detached health-check daemon (see internal/healthcheck)
	Since        time.Time     `json:"since"`
	Processes    []ProcessInfo `json:"processes"`
}

func activeStatePath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "active.json"), nil
}

// LoadActiveState returns nil (not an error) if no profile is active.
func LoadActiveState() (*ActiveState, error) {
	path, err := activeStatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s ActiveState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func SaveActiveState(s *ActiveState) error {
	dir, err := EnsureStateDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "active.json")
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return sysuser.ChownToRealUserIfRoot(path)
}

func ClearActiveState() error {
	path, err := activeStatePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// AddProcess records a newly-launched process (vpnctl run/run --tui/run
// --gui) against the active profile, for `vpnctl ps`/`vpnctl kill` and the
// "atomic switch" guard in cmdUse. Best-effort: not safe against concurrent
// vpnctl invocations racing on the same state file (acceptable for a
// single-operator pentest stand; see README known limitations).
func AddProcess(pi ProcessInfo) error {
	state, err := LoadActiveState()
	if err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("no active profile to track process against")
	}
	state.Processes = append(state.Processes, pi)
	return SaveActiveState(state)
}

// RemoveProcess drops a tracked process by PID once it exits. No-op if
// nothing is active or the PID isn't tracked.
func RemoveProcess(pid int) error {
	state, err := LoadActiveState()
	if err != nil || state == nil {
		return err
	}
	out := state.Processes[:0]
	for _, p := range state.Processes {
		if p.PID != pid {
			out = append(out, p)
		}
	}
	state.Processes = out
	return SaveActiveState(state)
}

// SysctlBackup records the value of every sysctl vpnctl has ever changed,
// captured the *first* time it changed it, so `postrm`/`vpnctl doctor
// --restore` can put the system back exactly as found rather than to some
// hardcoded default.
type SysctlBackup struct {
	Values map[string]string `json:"values"`
}

func sysctlBackupPath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sysctl_backup.json"), nil
}

func LoadSysctlBackup() (*SysctlBackup, error) {
	path, err := sysctlBackupPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SysctlBackup{Values: map[string]string{}}, nil
		}
		return nil, err
	}
	var b SysctlBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Values == nil {
		b.Values = map[string]string{}
	}
	return &b, nil
}

func SaveSysctlBackup(b *SysctlBackup) error {
	dir, err := EnsureStateDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "sysctl_backup.json")
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return sysuser.ChownToRealUserIfRoot(path)
}

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
	EngineKind   string        `json:"engine_kind"` // "awg-quick" | "sing-box" | "xray"
	EngineLog    string        `json:"engine_log"`  // path to the engine's captured stdout/stderr
	HelperPID    int           `json:"helper_pid"`  // tun2socks, for a Xray engine (0 otherwise)
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

// withStateLock serializes fn against every other withStateLock caller, in
// this process and every other, via an flock(2) on a dedicated lock file
// (never active.json itself, so a lock held mid-write can't itself block a
// plain read). This is what makes UpdateActiveState/WriteActiveState/
// ClearActiveStateLocked safe against concurrent vpnctl invocations and the
// detached health-check daemon racing to read-modify-write active.json —
// previously last-write-wins could silently drop a write (e.g. a health
// check's UpdateEndpoint clobbering a concurrent `run --gui`'s AddProcess).
func withStateLock(fn func() error) error {
	dir, err := EnsureStateDir()
	if err != nil {
		return err
	}
	lockPath := filepath.Join(dir, ".active.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("opening state lock: %w", err)
	}
	defer f.Close()
	// Chown to the real user (no-op unless root-under-sudo), same as every
	// other file this package writes: `vpnctl kill` (unlike `use`/`down`)
	// doesn't require root, since it targets a GUI process already running
	// as the real user — it still needs to open+flock this file, which fails
	// with EACCES if a prior root-owned run left it mode 0644 owned by root.
	_ = sysuser.ChownToRealUserIfRoot(lockPath)
	if err := flockExclusive(f); err != nil {
		return fmt.Errorf("locking state: %w", err)
	}
	defer funlock(f)
	return fn()
}

// writeFileAtomic writes via a temp file + rename in the same directory, so
// a concurrent unlocked LoadActiveState can never observe a torn/partial
// write (rename is atomic; a plain os.WriteFile truncate-then-write is not).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// UpdateActiveState is the single serialized read-modify-write entry point
// for active.json. mutate receives the currently active state (nil if no
// profile is active) and returns the state to persist — or nil to clear the
// active state entirely (equivalent to ClearActiveState). Every caller that
// needs to load, change, and save active.json should go through this
// instead of LoadActiveState+SaveActiveState directly, so it can't
// interleave with another such sequence.
func UpdateActiveState(mutate func(*ActiveState) (*ActiveState, error)) error {
	return withStateLock(func() error {
		state, err := LoadActiveState()
		if err != nil {
			return err
		}
		next, err := mutate(state)
		if err != nil {
			return err
		}
		if next == nil {
			return ClearActiveState()
		}
		return SaveActiveState(next)
	})
}

// WriteActiveState replaces the active state outright under the same lock
// as UpdateActiveState, for the one caller (Setup) that creates a brand new
// active.json rather than merging into an existing one.
func WriteActiveState(s *ActiveState) error {
	return withStateLock(func() error {
		return SaveActiveState(s)
	})
}

// ClearActiveStateLocked clears the active state under the same lock as
// UpdateActiveState/WriteActiveState, so Teardown's final clear can't race a
// concurrent AddProcess/RemoveProcess resurrecting a stale active.json right
// after teardown intended to remove it for good.
func ClearActiveStateLocked() error {
	return withStateLock(func() error {
		return ClearActiveState()
	})
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
	if err := writeFileAtomic(path, data, 0o644); err != nil {
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
// "atomic switch" guard in cmdUse. Serialized via UpdateActiveState against
// every other vpnctl invocation and the health-check daemon, so a
// concurrent RemoveProcess/UpdateEndpoint can no longer silently clobber
// this write (or vice versa).
func AddProcess(pi ProcessInfo) error {
	return UpdateActiveState(func(state *ActiveState) (*ActiveState, error) {
		if state == nil {
			return nil, fmt.Errorf("no active profile to track process against")
		}
		state.Processes = append(state.Processes, pi)
		return state, nil
	})
}

// RemoveProcess drops a tracked process by PID once it exits. No-op if
// nothing is active or the PID isn't tracked.
func RemoveProcess(pid int) error {
	return UpdateActiveState(func(state *ActiveState) (*ActiveState, error) {
		if state == nil {
			return nil, nil
		}
		out := state.Processes[:0]
		for _, p := range state.Processes {
			if p.PID != pid {
				out = append(out, p)
			}
		}
		state.Processes = out
		return state, nil
	})
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
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return err
	}
	return sysuser.ChownToRealUserIfRoot(path)
}

// ClearSysctlBackupValue removes key from the backup once its original
// value has actually been restored to the live system (see
// LinuxEngine.restoreIPForward), so a second, later teardown doesn't
// re-apply an already-restored value and sysctl_backup.json doesn't linger
// on disk forever recording values that no longer need restoring. Deletes
// the file entirely once no keys are left, rather than leaving an empty
// backup behind. Serialized under the same lock as
// UpdateActiveState/WriteActiveState/ClearActiveStateLocked, since a second
// concurrent teardown (e.g. `prerm` racing a stray `vpnctl down`) could
// otherwise interleave its own load-modify-save here too.
func ClearSysctlBackupValue(key string) error {
	return withStateLock(func() error {
		backup, err := LoadSysctlBackup()
		if err != nil {
			return err
		}
		if _, known := backup.Values[key]; !known {
			return nil
		}
		delete(backup.Values, key)
		if len(backup.Values) == 0 {
			path, err := sysctlBackupPath()
			if err != nil {
				return err
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		return SaveSysctlBackup(backup)
	})
}

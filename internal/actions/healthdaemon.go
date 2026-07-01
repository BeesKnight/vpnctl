package actions

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/BeesKnight/vpnctl/internal/netguard"
)

// HealthCheckDaemonArg is the hidden subcommand cmd/vpnctl dispatches to
// internal/healthcheck.Run — not listed in `vpnctl help`, only ever invoked
// by spawnHealthCheckDaemon itself.
const HealthCheckDaemonArg = "__healthcheck-daemon"

// spawnHealthCheckDaemon launches a detached copy of the vpnctl binary
// running just the health-check loop (spec §3.3's periodic re-resolve),
// fully independent of the `vpnctl use` process that started it and of
// whether the TUI is ever opened — the daemon exits on its own once it
// notices the active profile is gone (see internal/healthcheck.Run).
func spawnHealthCheckDaemon() (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolving vpnctl's own path: %w", err)
	}

	dir, err := netguard.EnsureStateDir()
	if err != nil {
		return 0, err
	}
	logsDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return 0, err
	}
	logFile, err := os.OpenFile(filepath.Join(logsDir, "healthcheck.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, err
	}
	defer logFile.Close()

	cmd := exec.Command(self, HealthCheckDaemonArg)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting health-check daemon: %w", err)
	}
	return cmd.Process.Pid, nil
}

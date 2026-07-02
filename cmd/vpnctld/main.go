// Command vpnctld is the privileged daemon that owns the netns, iptables
// kill-switch, and tunnel engine process for the whole machine. vpnctl
// (the CLI/TUI) talks to it over a Unix socket instead of touching
// networking directly — see internal/vpnctld and DAEMON_MIGRATION.md for
// what's implemented so far and what's still pending.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/BeesKnight/vpnctl/internal/rpc"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
	"github.com/BeesKnight/vpnctl/internal/vpnctld"
)

// defaultStateDir is where vpnctld keeps its own operational state (sysctl
// backup, generated engine configs, logs) via internal/netguard.StateDir.
// That function was built for the old per-invoking-user CLI model (real
// user's home directory, so each user's session was tracked separately);
// vpnctld is a single system-wide process with no "invoking user" of its
// own, so it points VPNCTL_STATE_HOME (see internal/sysuser.RealHome,
// added in the Part A prerm fix) at a fixed system directory instead of
// letting it fall through to $HOME — which a systemd-run/systemd.service
// environment doesn't set at all, and would otherwise fail outright with
// "$HOME is not defined" the moment Setup tries to read/write it.
const defaultStateDir = "/var/lib/vpnctld"

func main() {
	socketPath := flag.String("socket", rpc.DefaultSocketPath, "Unix socket path to listen on")
	stateDir := flag.String("state-dir", defaultStateDir, "directory for vpnctld's own operational state (sysctl backup, engine configs, logs)")
	flag.Parse()

	logger := log.New(os.Stderr, "vpnctld: ", log.LstdFlags)

	if !sysuser.IsRoot() {
		logger.Fatal("must run as root (network namespace/iptables changes) — vpnctld is meant to run as a systemd service, see DAEMON_MIGRATION.md")
	}

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		logger.Fatalf("creating state dir %s: %v", *stateDir, err)
	}
	os.Setenv("VPNCTL_STATE_HOME", *stateDir)

	ln, err := listen(*socketPath)
	if err != nil {
		logger.Fatalf("listening on %s: %v", *socketPath, err)
	}
	defer os.Remove(*socketPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := vpnctld.New(logger)
	logger.Printf("listening on %s", *socketPath)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, ln) }()

	select {
	case <-ctx.Done():
		logger.Print("received shutdown signal, tearing down any active profile...")
	case err := <-serveErr:
		if err != nil {
			logger.Printf("listener stopped unexpectedly: %v", err)
		}
	}

	srv.Shutdown()
	logger.Print("stopped")
}

// listen binds the daemon's Unix socket, clearing a stale socket file left
// behind by a previous instance that didn't exit cleanly (e.g. killed
// rather than stopped) — bind would otherwise fail with "address already
// in use" even though nothing is actually listening anymore.
func listen(path string) (net.Listener, error) {
	ln, err := net.Listen("unix", path)
	if err == nil {
		return ln, nil
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, err
	}
	if _, dialErr := net.Dial("unix", path); dialErr == nil {
		return nil, fmt.Errorf("another vpnctld is already listening on %s", path)
	}
	if rmErr := os.Remove(path); rmErr != nil {
		return nil, fmt.Errorf("removing stale socket %s: %w", path, rmErr)
	}
	return net.Listen("unix", path)
}

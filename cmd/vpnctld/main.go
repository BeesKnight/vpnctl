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
	"os/user"
	"strconv"
	"syscall"
	"time"

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

// defaultSocketGroup is the system group given access to the control
// socket (root:vpnctl 0660) so unprivileged vpnctl clients can reach the
// daemon without opening the socket to every local user (0666) — see
// packaging/postinst, which creates this group and adds the invoking user
// to it. Applied by the daemon itself right after it binds the socket
// (rather than by postinst chown-ing it after the fact) so there's no
// window where a client started right after `systemctl start vpnctld`
// could race a not-yet-applied chown.
const defaultSocketGroup = "vpnctl"

func main() {
	socketPath := flag.String("socket", rpc.DefaultSocketPath, "Unix socket path to listen on")
	stateDir := flag.String("state-dir", defaultStateDir, "directory for vpnctld's own operational state (sysctl backup, engine configs, logs)")
	socketGroup := flag.String("socket-group", defaultSocketGroup, "system group given read/write access to the control socket (root:<group> 0660); empty leaves the socket root-only")
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

	if *socketGroup != "" {
		if err := chownSocketToGroup(*socketPath, *socketGroup); err != nil {
			logger.Printf("warning: could not set socket group ownership to %q: %v (socket left root-only; non-root vpnctl clients will fail until this is fixed — see packaging/postinst)", *socketGroup, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := vpnctld.New(logger)
	logger.Printf("listening on %s", *socketPath)
	sdNotify("READY=1")
	go runWatchdog(ctx, logger, *socketPath)

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

	sdNotify("STOPPING=1")
	srv.Shutdown()
	logger.Print("stopped")
}

// chownSocketToGroup sets the control socket to root:<group> 0660 so
// members of that group (see defaultSocketGroup) can reach the daemon
// without root. Called once, right after net.Listen binds the socket file.
func chownSocketToGroup(path, groupName string) error {
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("looking up group %q: %w", groupName, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parsing gid %q for group %q: %w", g.Gid, groupName, err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("chown: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return nil
}

// sdNotify sends a systemd service notification (see sd_notify(3)) if
// running under systemd with Type=notify — a plain datagram write to the
// socket named by $NOTIFY_SOCKET, no library dependency needed for just
// READY=1/STOPPING=1. A no-op (silently) anywhere else, including when run
// by hand outside systemd, where $NOTIFY_SOCKET is unset.
func sdNotify(state string) {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(state))
}

// runWatchdog pings systemd's watchdog (WATCHDOG=1) on a timer if running
// under a unit with WatchdogSec= set ($WATCHDOG_USEC present) — pairs with
// packaging/vpnctld.service's WatchdogSec, so systemd restarts vpnctld if
// it ever genuinely wedges (e.g. deadlocks on Server.mu) rather than just
// sitting there unresponsive with a live PID.
//
// Deliberately does more than prove "some goroutine got scheduled": each
// tick dials the daemon's own socket and does a real Ping RPC round trip
// before reporting healthy, so a hang anywhere in the accept/dispatch path
// (not just this goroutine specifically) withholds the watchdog ping and
// lets systemd's timeout actually catch it.
func runWatchdog(ctx context.Context, logger *log.Logger, socketPath string) {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return // not running under a unit with WatchdogSec= set
	}
	// systemd's own documented convention: ping at roughly half the
	// configured timeout, so a single missed/slow tick doesn't immediately
	// trip a restart.
	interval := time.Duration(usec) * time.Microsecond / 2
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if selfPingHealthy(socketPath) {
				sdNotify("WATCHDOG=1")
			} else {
				logger.Print("watchdog: self-ping failed, withholding WATCHDOG=1 this tick")
			}
		}
	}
}

// selfPingHealthy does a real Ping RPC round trip against the daemon's own
// socket, exercising the same accept/dispatch path a real client would.
func selfPingHealthy(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := rpc.Request{APIVersion: rpc.APIVersion, Method: rpc.MethodPing}
	if err := rpc.WriteMessage(conn, &req); err != nil {
		return false
	}
	var resp rpc.Response
	if err := rpc.ReadMessage(conn, &resp); err != nil {
		return false
	}
	return resp.Error == ""
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

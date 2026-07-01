// Package healthcheck closes the one limitation the bash prototype called
// out explicitly (spec §3.3): it periodically re-resolves the active
// profile's server hostname and, if the IP changed, rewrites the
// point-to-point iptables/NAT rules in place — without ever dropping the
// kill-switch or requiring the TUI to be open. It runs as its own detached
// daemon process (see internal/actions.spawnHealthCheckDaemon), because the
// engine (awg-quick exits immediately once the interface is up; sing-box
// has no built-in re-resolve) and the CLI invocation that ran `vpnctl use`
// both come and go independently of how long a profile stays active.
package healthcheck

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

// DefaultInterval is how often the daemon re-resolves the active server's
// hostname. Overridable via $VPNCTL_HEALTHCHECK_INTERVAL (seconds) — spec
// §3.3 calls for this to be configurable.
const DefaultInterval = 30 * time.Second

// Interval reads the configured health-check interval.
func Interval() time.Duration {
	if v := os.Getenv("VPNCTL_HEALTHCHECK_INTERVAL"); v != "" {
		var secs int
		if _, err := fmt.Sscanf(v, "%d", &secs); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return DefaultInterval
}

// Run loops until the active profile disappears (namespace torn down via
// `vpnctl down`/switching profiles), re-resolving and updating the
// point-to-point firewall rule on every tick if the server's IP changed.
// Meant to be the entire body of the detached daemon process — logs to
// stderr (redirected to a file by the caller) rather than returning errors
// for transient resolution failures, since a single failed DNS lookup isn't
// fatal and shouldn't kill the daemon.
func Run(interval time.Duration) error {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	logger.Printf("health-check daemon started, interval=%s", interval)

	ng := netguard.NewLinuxEngine(false)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		state, err := netguard.LoadActiveState()
		if err != nil {
			logger.Printf("loading active state: %v", err)
			continue
		}
		if state == nil {
			logger.Printf("no active profile — exiting")
			return nil
		}

		p, err := profile.Find(state.ProfileName)
		if err != nil {
			logger.Printf("profile %q no longer found: %v", state.ProfileName, err)
			continue
		}

		changed, newIP, err := ng.UpdateEndpoint(p)
		if err != nil {
			logger.Printf("re-resolve/update failed: %v", err)
			continue
		}
		if changed {
			logger.Printf("server IP changed, kill-switch rules updated: now %s", newIP)
		}
	}
	return nil
}

// Package healthcheck holds the configuration for the periodic re-resolve
// that keeps a profile's point-to-point kill-switch rule pointed at the
// right IP if the server's hostname resolves differently mid-session (see
// internal/vpnctld's healthCheckLoop, which does the actual ticking —
// in-process and in-memory now that vpnctld owns the active profile for as
// long as it stays up, rather than a detached daemon re-reading
// active.json).
package healthcheck

import (
	"fmt"
	"os"
	"time"
)

// DefaultInterval is how often the active server's hostname is re-resolved.
// Overridable via $VPNCTL_HEALTHCHECK_INTERVAL (seconds).
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

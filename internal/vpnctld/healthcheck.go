package vpnctld

import (
	"context"
	"time"

	"github.com/BeesKnight/vpnctl/internal/healthcheck"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

// healthCheckLoop is the in-process replacement for internal/healthcheck.Run
// (which loops until active.json disappears, re-resolving the server
// hostname and rewriting the kill-switch's point-to-point rule in place if
// it changed): same ticker, same single UpdateEndpoint call per tick, same
// $VPNCTL_HEALTHCHECK_INTERVAL config (reuses healthcheck.Interval(), which
// has no file-state coupling of its own). The differences are exactly what
// no longer needing a detached process buys: p is already in memory instead
// of re-read from active.json every tick, and ctx cancellation (from
// Deactivate or daemon shutdown) replaces polling for "state went away".
func (s *Server) healthCheckLoop(ctx context.Context, p profile.Profile) {
	interval := healthcheck.Interval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Printf("health-check started for %q, interval=%s", p.Name, interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.active == nil {
				s.mu.Unlock()
				return
			}
			changed, newIP, err := s.ng.UpdateEndpoint(p)
			if err != nil {
				s.mu.Unlock()
				s.logger.Printf("health-check: re-resolve/update failed: %v", err)
				continue
			}
			if changed && s.active != nil {
				s.active.status.ResolvedIP = newIP
			}
			s.mu.Unlock()

			if changed {
				s.logger.Printf("health-check: server IP changed, kill-switch rules updated: now %s", newIP)
			}
		}
	}
}

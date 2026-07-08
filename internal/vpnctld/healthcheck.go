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
//
// Also watches handle.Healthy() (the same check handleStatus reports on
// demand) and fires a desktop notification (notify.go) on an actual
// healthy<->unhealthy transition — once per transition, not every tick, so
// a tunnel that's been down for an hour doesn't spam notifications once
// per health-check interval the whole time.
//
// If p.Backup is set (profile.Meta.Backup, opt-in per profile) and health
// stays down for failoverThreshold consecutive ticks, auto-failover
// (failover.go) deactivates p and activates the backup — at which point
// this specific goroutine's job is done and it returns; Activate started a
// fresh healthCheckLoop for the backup profile, with its own independent
// failedOver/unhealthyStreak state.
func (s *Server) healthCheckLoop(ctx context.Context, p profile.Profile, activatedByUID, activatedByGID uint32) {
	interval := healthcheck.Interval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Printf("health-check started for %q, interval=%s", p.Name, interval)
	wasHealthy := true // Activate already confirmed the engine came up cleanly before starting this loop
	unhealthyStreak := 0

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
			healthy, herr := s.active.handle.Healthy()
			if herr != nil {
				healthy = false
			}
			s.mu.Unlock()

			if changed {
				s.logger.Printf("health-check: server IP changed, kill-switch rules updated: now %s", newIP)
			}
			if healthy != wasHealthy {
				s.logger.Printf("health-check: %q transitioned to healthy=%v", p.Name, healthy)
				s.notifyHealthChange(activatedByUID, activatedByGID, p.Name, healthy)
				wasHealthy = healthy
			}

			if healthy {
				unhealthyStreak = 0
				continue
			}
			unhealthyStreak++
			if p.Backup == "" || unhealthyStreak < failoverThreshold {
				continue
			}
			s.logger.Printf("health-check: %q unhealthy for %d consecutive checks, failing over to backup %q", p.Name, unhealthyStreak, p.Backup)
			if err := s.triggerFailover(p, activatedByUID, activatedByGID); err != nil {
				s.logger.Printf("health-check: failover from %q to %q failed: %v", p.Name, p.Backup, err)
				unhealthyStreak = 0 // don't retry every single tick — wait for another full streak before trying again
				continue
			}
			return // this profile is no longer active; the backup's own healthCheckLoop has taken over
		}
	}
}

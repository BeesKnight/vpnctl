package vpnctld

import (
	"fmt"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// notifyHealthChange fires a best-effort desktop notification (notify-send)
// at whoever ran Activate for the current profile (identified by
// SO_PEERCRED at Activate time — see activeState.activatedByUID/GID, not
// anything self-reported) when its health status flips. Reuses
// sysuser.ResolveGUIEnv, the same DISPLAY/DBUS_SESSION_BUS_ADDRESS
// passthrough already built for launching GUI apps through the tunnel —
// notify-send talks to the user's D-Bus session over a Unix socket, so
// which network namespace it runs in doesn't matter, only whose desktop
// session it can reach.
//
// Silently no-ops on any failure (uid 0 — activated by root directly, with
// no desktop session to target; notify-send not installed; no reachable
// desktop session): a failed notification must never be treated as a
// health-check error in its own right, and healthCheckLoop's own
// re-resolve/rule-update logic doesn't depend on this succeeding.
func (s *Server) notifyHealthChange(uid, gid uint32, profileName string, healthy bool) {
	if uid == 0 {
		return
	}

	s.mu.Lock()
	ng := s.ng
	s.mu.Unlock()

	summary := fmt.Sprintf("vpnctl: %s is down", profileName)
	urgency := "critical"
	if healthy {
		summary = fmt.Sprintf("vpnctl: %s recovered", profileName)
		urgency = "normal"
	}

	dropUID, dropGID := int(uid), int(gid)
	opts := netguard.ExecOptions{
		Env:       sysuser.ResolveGUIEnv(dropUID),
		DropToUID: &dropUID,
		DropToGID: &dropGID,
	}
	cmd, err := ng.Command("notify-send", []string{"-u", urgency, "-a", "vpnctl", summary}, opts)
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	go func() { _ = cmd.Wait() }() // reap so it doesn't linger as a zombie; nothing else to do with the result
}

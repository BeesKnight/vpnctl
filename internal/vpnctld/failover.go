package vpnctld

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// failoverThreshold is how many consecutive unhealthy health-check ticks
// are required before auto-failover triggers (see healthCheckLoop) — a
// single transient blip (a slow handshake, one dropped health probe)
// shouldn't switch the active profile out from under someone; only a
// genuinely sustained outage should.
const failoverThreshold = 2

// homeDirForUID resolves a uid to its home directory — a var, not a direct
// call in triggerFailover, so tests can substitute a temp directory
// without needing a real system account to exist at a specific uid.
var homeDirForUID = func(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// triggerFailover deactivates the current profile and activates its
// configured backup (profile.Meta.Backup / profile.Profile.Backup),
// resolved from the same uid that originally ran Activate — learned from
// SO_PEERCRED at Activate time (activeState.activatedByUID/GID), never
// anything self-reported.
//
// The daemon otherwise never reads any user's ~/.config/vpnctl/profiles
// itself (see profileFromParams's doc comment) — every other Activate is
// client-initiated, with the client already having resolved and sent the
// full profile over the wire. A background health-check failover has no
// live client connection to ask, so this is the one deliberate exception:
// it looks up the activating uid's home directory and reads that specific
// user's profiles directory to resolve the backup by name, never anyone
// else's.
func (s *Server) triggerFailover(current profile.Profile, activatedByUID, activatedByGID uint32) error {
	home, err := homeDirForUID(activatedByUID)
	if err != nil {
		return fmt.Errorf("looking up uid %d: %w", activatedByUID, err)
	}
	base := filepath.Join(home, ".config", "vpnctl", "profiles")
	backup, err := profile.FindInDir(base, current.Backup)
	if err != nil {
		return fmt.Errorf("resolving backup profile %q for uid %d: %w", current.Backup, activatedByUID, err)
	}
	params, err := activateParamsFor(backup)
	if err != nil {
		return err
	}

	s.mu.Lock()
	deactivateErr := s.deactivateLocked()
	s.mu.Unlock()
	if deactivateErr != nil {
		s.logger.Printf("failover: deactivating %q before switching to backup: %v (continuing anyway)", current.Name, deactivateErr)
	}

	peer := peerIdentity{UID: activatedByUID, GID: activatedByGID}
	if _, err := s.handleActivate(params, peer); err != nil {
		return fmt.Errorf("activating backup %q: %w", backup.Name, err)
	}
	return nil
}

// activateParamsFor builds the same rpc.ActivateParams a real client would
// send for this profile (mirrors vpnctlclient.Activate's own construction)
// — triggerFailover calls handleActivate directly rather than over the
// wire (it's a server-internal call, not a real client connection), but
// the params it builds must be identical to what a client would have sent.
func activateParamsFor(p profile.Profile) (rpc.ActivateParams, error) {
	params := rpc.ActivateParams{Name: p.Name, Kind: string(p.Kind), Family: string(p.Family), Backup: p.Backup}
	switch p.Family {
	case profile.FamilyWG:
		if p.WG == nil {
			return rpc.ActivateParams{}, fmt.Errorf("profile %q has no parsed WireGuard config", p.Name)
		}
		params.WGRaw = p.WG.Raw
	case profile.FamilyProxy:
		params.Outbound = p.Outbound
	}
	return params, nil
}

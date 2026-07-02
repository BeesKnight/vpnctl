package profile

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// SetTLSInsecure toggles skip-certificate-verification on a single
// already-imported VLESS/Hysteria2 profile's tls block, rewriting its
// on-disk JSON in place. Deliberately scoped to one profile at a time
// rather than a global default: most servers present a valid certificate,
// and silently skipping verification for all of them would trade away a
// real security property just to accommodate the few that don't. This is
// the explicit, per-profile opt-in for a server whose certificate a
// subscription doesn't (or can't) verify — the operator has to name the
// profile, so it can never apply somewhere it wasn't asked to.
func SetTLSInsecure(p Profile, insecure bool) error {
	if p.Family != FamilyProxy {
		return fmt.Errorf("%q is not a VLESS/Hysteria2 profile — no tls block to set", p.Name)
	}
	tls, ok := p.Outbound["tls"].(map[string]any)
	if !ok {
		tls = map[string]any{}
	}
	tls["insecure"] = insecure
	p.Outbound["tls"] = tls

	data, err := json.MarshalIndent(p.Outbound, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p.Path, data, 0o644); err != nil {
		return err
	}
	return sysuser.ChownToRealUserIfRoot(p.Path)
}

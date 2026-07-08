package main

import (
	"fmt"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

// cmdInsecure toggles TLS certificate verification for one already-imported
// VLESS/Hysteria2 profile — for the case where a server's own certificate
// doesn't verify (self-signed, wrong CA, etc.) and the subscription that
// produced the profile didn't already set insecure=1 in its URI. Per-profile
// and explicit on purpose: it never changes any other profile's behavior.
//
// For VLESS this dials the server to fetch and pin its certificate rather
// than skipping verification outright — Xray-core (VLESS's engine) removed
// the plain "skip verification" option entirely; see
// profile.SetTLSInsecure's doc comment for why. Hysteria2 (sing-box) still
// supports skipping verification directly.
func cmdInsecure(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vpnctl insecure <profile> [off]")
	}
	name := args[0]
	insecure := true
	if len(args) > 1 && args[1] == "off" {
		insecure = false
	}

	p, err := profile.Find(name)
	if err != nil {
		return err
	}
	if err := profile.SetTLSInsecure(p, insecure); err != nil {
		return err
	}

	switch {
	case !insecure:
		fmt.Printf("%s: TLS certificate verification re-enabled.\n", p.DisplayName())
	case p.Kind == profile.KindVLESS:
		fmt.Printf("%s: fetched and pinned the server's current certificate — this profile now trusts exactly that certificate, not any certificate.\n", p.DisplayName())
	default:
		fmt.Printf("%s: TLS certificate verification disabled for this profile only.\n", p.DisplayName())
	}
	return nil
}

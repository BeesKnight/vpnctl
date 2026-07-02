package main

import (
	"fmt"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

// cmdInsecure toggles TLS certificate verification for one already-imported
// VLESS/Hysteria2 profile — for the case where a server's own certificate
// doesn't verify (self-signed, wrong CA, etc.) and the subscription that
// produced the profile didn't already set insecure=1/allowInsecure=1 in its
// URI. Per-profile and explicit on purpose: it never changes any other
// profile's behavior.
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

	if insecure {
		fmt.Printf("%s: TLS certificate verification disabled for this profile only.\n", p.DisplayName())
	} else {
		fmt.Printf("%s: TLS certificate verification re-enabled.\n", p.DisplayName())
	}
	return nil
}

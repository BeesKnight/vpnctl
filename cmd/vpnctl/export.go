package main

import (
	"fmt"
	"os"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

// cmdExport is the counterpart to `vpnctl import`: prints (or writes, with
// --out) the profile's underlying config file verbatim.
//
// For WireGuard/AmneziaWG profiles this is a complete, directly
// re-importable .conf — the exact symmetric opposite of `vpnctl import
// --wg`. For proxy profiles it's the internal sing-box outbound JSON
// vpnctl generated at import time, *not* a reconstructed vless://Zhysteria2://
// link: rebuilding an exact subscription URI from the stored outbound
// object (transport type, TLS/Reality fields, etc. all vary per profile)
// is real reverse-parsing work with a lot of surface area to get subtly
// wrong, so it's deliberately not attempted here — the JSON is still a
// complete, honest copy of the profile's config, just not the original
// shareable string.
func cmdExport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vpnctl export <profile> [--out <path>]")
	}
	name := args[0]
	outPath := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--out" && i+1 < len(args) {
			outPath = args[i+1]
			i++
		}
	}

	if err := profile.EnsureDirs(); err != nil {
		return fmt.Errorf("ensuring profile dirs: %w", err)
	}
	p, err := profile.Find(name)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(p.Path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", p.Path, err)
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, data, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}
		fmt.Printf("exported %s to %s\n", p.DisplayName(), outPath)
		return nil
	}

	if p.Family == profile.FamilyProxy {
		fmt.Fprintln(os.Stderr, "note: this is the internal sing-box outbound JSON, not a shareable vless://Zhysteria2:// link — vpnctl doesn't reconstruct the original subscription URI")
	}
	os.Stdout.Write(data)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		fmt.Println()
	}
	return nil
}

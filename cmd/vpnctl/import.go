package main

import (
	"fmt"
	"strings"

	"github.com/BeesKnight/vpnctl/internal/importer"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

func cmdImport(args []string) error {
	if err := profile.EnsureDirs(); err != nil {
		return err
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: vpnctl import --sub <url> | --wg <path>")
	}

	switch args[0] {
	case "--sub":
		names, err := importer.ImportSubscription(args[1])
		if err != nil {
			return err
		}
		fmt.Printf("imported %d profile(s): %s\n", len(names), strings.Join(names, ", "))
		return nil
	case "--wg":
		name, err := importer.ImportWireGuardFile(args[1])
		if err != nil {
			return err
		}
		fmt.Printf("imported profile %q\n", name)
		return nil
	default:
		return fmt.Errorf("usage: vpnctl import --sub <url> | --wg <path>")
	}
}

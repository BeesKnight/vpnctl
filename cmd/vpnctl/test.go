package main

import (
	"fmt"
	"time"

	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

func cmdTest(args []string) error {
	fmt.Println("Testing connectivity through the active profile...")
	result, err := vpnctlclient.TestConnectivity()
	if err != nil {
		return err
	}
	// vpnctld captures curl's output and returns it whole rather than
	// streaming it live (curl already runs -s -S, so there was no progress
	// meter to preserve) — print it here so the IP/http_status line curl
	// would have printed itself is still visible.
	fmt.Print(result.Output)
	if result.ExitCode != 0 {
		return fmt.Errorf("connectivity test failed (curl exit %d) — kill-switch held, no leak to the real network occurred", result.ExitCode)
	}
	fmt.Printf("(completed in %s)\n", time.Duration(result.ElapsedMS)*time.Millisecond)
	return nil
}

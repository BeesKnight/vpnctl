package main

import (
	"fmt"
	"time"

	"github.com/BeesKnight/vpnctl/internal/actions"
)

func cmdTest(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	fmt.Println("Testing connectivity through the active profile...")
	result, err := actions.TestConnectivity()
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("connectivity test failed (curl exit %d) — kill-switch held, no leak to the real network occurred", result.ExitCode)
	}
	fmt.Printf("(completed in %s)\n", result.Elapsed.Round(time.Millisecond))
	return nil
}

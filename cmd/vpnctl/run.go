package main

import (
	"fmt"
	"os"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/run"
)

func cmdRun(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}

	mode := run.TypeCLI
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
		switch a {
		case "--tui":
			mode = run.TypeTUI
		case "--gui":
			mode = run.TypeGUI
		default:
			return fmt.Errorf("usage: vpnctl run [--tui|--gui] -- <command...>")
		}
	}
	if sepIdx == -1 {
		return fmt.Errorf("usage: vpnctl run [--tui|--gui] -- <command...>")
	}
	argv := args[sepIdx+1:]
	if len(argv) == 0 {
		return fmt.Errorf("usage: vpnctl run [--tui|--gui] -- <command...>")
	}

	ng := netguard.NewLinuxEngine(false)

	switch mode {
	case run.TypeGUI:
		pid, err := run.GUI(ng, argv)
		if err != nil {
			return err
		}
		fmt.Printf("launched %s detached through the active profile, pid %d\n", argv[0], pid)
		return nil
	case run.TypeTUI:
		code, err := run.TUI(ng, argv)
		if err != nil {
			return err
		}
		os.Exit(code)
	default:
		code, err := run.CLI(ng, argv)
		if err != nil {
			return err
		}
		os.Exit(code)
	}
	return nil
}

package main

import (
	"fmt"
	"os"

	"github.com/BeesKnight/vpnctl/internal/rpc"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

// cmdRun goes through vpnctld's Exec RPC (internal/vpnctlclient.Exec)
// instead of building an *exec.Cmd in this process — unlike use/down/
// status/test/ps/kill, this needed real design work (see
// DAEMON_MIGRATION.md and internal/vpnctld/exec.go's doc comments): a
// detached daemon has no terminal of its own for --tui to inherit the way
// this process's own terminal used to be inherited directly, so the daemon
// allocates a real PTY and this client proxies it over the socket instead.
// No sudo needed any more than use/down/status/test/ps/kill do.
func cmdRun(args []string) error {
	mode := rpc.ExecModeCLI
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
		switch a {
		case "--tui":
			mode = rpc.ExecModeTUI
		case "--gui":
			mode = rpc.ExecModeGUI
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

	opts := vpnctlclient.ExecOptions{}
	if mode == rpc.ExecModeGUI {
		// sysuser.RealUIDGID handles both "invoked directly as the desktop
		// user" (the new, sudo-free normal case) and "invoked via sudo"
		// (still supported, e.g. a user not yet added to the socket's
		// access group) — either way, the daemon must never run a GUI app
		// as root.
		uid, gid, err := sysuser.RealUIDGID()
		if err != nil {
			return fmt.Errorf("resolving real user for privilege drop: %w", err)
		}
		opts.Env = sysuser.ResolveGUIEnv(uid)
		opts.DropUID, opts.DropGID = &uid, &gid
	}

	result, err := vpnctlclient.Exec(mode, argv, opts)
	if err != nil {
		return err
	}
	if mode == rpc.ExecModeGUI {
		fmt.Printf("launched %s detached through the active profile, pid %d\n", argv[0], result.PID)
		return nil
	}
	os.Exit(result.ExitCode)
	return nil
}

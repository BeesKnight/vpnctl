// Command vpnctl is an interactive (and scriptable) launcher for VPN/proxy
// profiles with a kernel-level kill-switch
package main

import (
	"fmt"
	"os"

)

func main() {
	if len(os.Args) < 2 {
		if err := runTUI(); err != nil {
			fmt.Fprintln(os.Stderr, "vpnctl:", err)
			os.Exit(1)
		}
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "list", "ls":
		err = cmdList(args)
	case "use":
		err = cmdUse(args)
	case "down":
		err = cmdDown(args)
	case "status":
		err = cmdStatus(args)
	case "test":
		err = cmdTest(args)
	case "run":
		err = cmdRun(args)
	case "import":
		err = cmdImport(args)
	case "insecure":
		err = cmdInsecure(args)
	case "ps":
		err = cmdPs(args)
	case "kill":
		err = cmdKill(args)
	case "doctor":
		err = cmdDoctor(args)
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "vpnctl: unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnctl:", err)
		if code, ok := err.(interface{ ExitCode() int }); ok {
			os.Exit(code.ExitCode())
		}
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`vpnctl - VPN/proxy profile launcher with kernel-level kill-switch

Usage:
  vpnctl                       launch interactive TUI, via vpnctld — no sudo needed
  vpnctl list                  list all profiles
  vpnctl use <profile>         activate a profile, via vpnctld — no sudo needed
  vpnctl down                  deactivate the active profile, via vpnctld — no sudo needed
  vpnctl status                show active profile / kill-switch state, via vpnctld
  vpnctl test                  test external connectivity through the active profile, via vpnctld
  vpnctl run -- <cmd...>       run a CLI command through the active profile (blocking), via vpnctld — no sudo needed
  vpnctl run --tui -- <cmd...> run an interactive TUI program (terminal takeover), via vpnctld — no sudo needed
  vpnctl run --gui -- <cmd...> run a GUI program detached, through the active profile, via vpnctld — no sudo needed
  vpnctl ps                    list processes launched through the active profile, via vpnctld
  vpnctl kill <pid|name>       kill a process launched through the active profile, via vpnctld
  vpnctl import --sub <url>    import profiles from a subscription link
  vpnctl import --wg <path>    import a WireGuard/AmneziaWG .conf file
  vpnctl insecure <profile>    disable TLS certificate verification for one VLESS/Hysteria2 profile
  vpnctl insecure <profile> off  re-enable TLS certificate verification for it
  vpnctl doctor                check system dependencies and configuration
  vpnctl help                  show this message

Every command above, including the bare TUI, talks to the vpnctld daemon
(must be running — see DAEMON_MIGRATION.md) and needs no sudo, only access
to its socket.`)
}

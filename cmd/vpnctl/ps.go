package main

import (
	"fmt"
	"time"

	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

func cmdPs(args []string) error {
	procs, err := vpnctlclient.ListProcesses()
	if err != nil {
		return err
	}
	if len(procs) == 0 {
		fmt.Println("No processes running through the active profile.")
		return nil
	}
	fmt.Printf("%-8s %-24s %-5s %s\n", "PID", "NAME", "TYPE", "UPTIME")
	for _, p := range procs {
		fmt.Printf("%-8d %-24s %-5s %s\n", p.PID, p.Name, p.Type, time.Since(p.StartedAt).Round(time.Second))
	}
	return nil
}

func cmdKill(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vpnctl kill <pid|name>")
	}
	pi, err := vpnctlclient.KillProcess(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("killed %s (pid %d)\n", pi.Name, pi.PID)
	return nil
}

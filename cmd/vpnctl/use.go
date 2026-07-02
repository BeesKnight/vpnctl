package main

import (
	"fmt"

	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

func cmdUse(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vpnctl use <profile>")
	}

	fmt.Printf("Activating %s...\n", args[0])
	p, result, err := vpnctlclient.Activate(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s (%s): namespace %s up, kill-switch ON, allowed only to %s:%d/%s\n",
		p.DisplayName(), p.Kind, result.Status.Namespace, result.Status.ResolvedIP, result.Status.ResolvedPort, result.Status.Protocol)
	fmt.Printf("Engine (%s) is up. Logs: %s\n", result.EngineKind, result.EngineLog)
	return nil
}

func cmdDown(args []string) error {
	if err := vpnctlclient.Deactivate(); err != nil {
		return fmt.Errorf("tearing down: %w", err)
	}
	fmt.Println("Namespace torn down, kill-switch removed, sysctl restored.")
	return nil
}

func cmdStatus(args []string) error {
	result, err := vpnctlclient.Status()
	if err != nil {
		return err
	}
	status := result.Status
	if !status.Active {
		fmt.Println("No active profile.")
		return nil
	}

	health := "DOWN / NO ROUTE"
	if result.Healthy {
		health = "UP"
	}
	fmt.Printf("Active:     %s (%s)\n", status.ProfileName, status.ProfileKind)
	fmt.Printf("State:      %s\n", health)
	fmt.Printf("Namespace:  %s (kill-switch ON)\n", status.Namespace)
	fmt.Printf("Endpoint:   %s:%d/%s\n", status.ResolvedIP, status.ResolvedPort, status.Protocol)
	fmt.Printf("Since:      %s\n", status.Since.Format("2006-01-02 15:04:05"))
	return nil
}

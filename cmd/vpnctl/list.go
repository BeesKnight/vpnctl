package main

import (
	"fmt"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

func cmdList(args []string) error {
	if err := profile.EnsureDirs(); err != nil {
		return fmt.Errorf("ensuring profile dirs: %w", err)
	}
	profiles, err := profile.LoadAll()
	if err != nil {
		return err
	}
	if len(profiles) == 0 {
		dir, _ := profile.Dir()
		fmt.Printf("no profiles found in %s\n", dir)
		return nil
	}

	lastGroup := -1
	for _, p := range profiles {
		if g := p.Group(); g != lastGroup {
			fmt.Printf("[%s]\n", p.GroupLabel())
			lastGroup = g
		}
		fmt.Printf("  %-24s %-12s %s\n", p.DisplayName(), p.Kind, p.Endpoint())
	}
	return nil
}

// cmdCompleteProfiles prints one profile name per line with no decoration
// — see main.go's "__complete_profiles" case. Deliberately never returns
// an error to the shell: a completion function invoking this mid-keystroke
// shouldn't ever print a Go error to the terminal, just offer no matches.
func cmdCompleteProfiles(_ []string) error {
	if err := profile.EnsureDirs(); err != nil {
		return nil
	}
	profiles, err := profile.LoadAll()
	if err != nil {
		return nil
	}
	for _, p := range profiles {
		fmt.Println(p.Name)
	}
	return nil
}

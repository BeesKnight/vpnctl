package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

// benchResult is one profile's outcome — ok/elapsed for a successful test,
// err for anything that kept it from completing (activation failure, the
// connectivity test itself failing, or a non-2xx/timeout).
type benchResult struct {
	name      string
	ok        bool
	elapsedMS int64
	err       string
}

// cmdBench activates every profile in turn, runs the same connectivity
// test `vpnctl test` does, deactivates, and reports a ranked table —
// useful when there are many candidate profiles (several countries/
// providers) and picking one by hand means guessing.
//
// vpnctld is a single system-wide daemon with exactly one active-profile
// slot (see DAEMON_MIGRATION.md's "Модель демона") — profiles can't be
// benchmarked concurrently, this is inherently sequential and, for a large
// profile set, inherently slow (each iteration pays real namespace/
// engine setup and teardown cost, not just the connectivity probe itself).
func cmdBench(args []string) error {
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

	// bench needs the daemon's one active-profile slot for itself; whatever
	// was active before is deactivated for the duration and reactivated
	// afterward (best-effort — if that reactivation fails, this says so
	// loudly rather than silently leaving the user on a different profile
	// than the one they started with).
	initial, err := vpnctlclient.Status()
	if err != nil {
		return fmt.Errorf("checking current status: %w", err)
	}
	if initial.Status.Active {
		fmt.Printf("deactivating currently active profile %q for the duration of the benchmark...\n", initial.Status.ProfileName)
		if err := vpnctlclient.Deactivate(); err != nil {
			return fmt.Errorf("deactivating current profile before benchmarking: %w", err)
		}
	}

	results := make([]benchResult, 0, len(profiles))
	for _, p := range profiles {
		fmt.Printf("[%d/%d] testing %s...\n", len(results)+1, len(profiles), p.DisplayName())
		results = append(results, benchOne(p))
	}

	if initial.Status.Active {
		fmt.Printf("restoring previously active profile %q...\n", initial.Status.ProfileName)
		if _, _, err := vpnctlclient.Activate(initial.Status.ProfileName); err != nil {
			fmt.Printf("WARNING: could not restore %q: %v — no profile is active now, run `vpnctl use %s` manually\n", initial.Status.ProfileName, err, initial.Status.ProfileName)
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].ok != results[j].ok {
			return results[i].ok // successful results first
		}
		return results[i].elapsedMS < results[j].elapsedMS
	})

	fmt.Println("\nResults (fastest first):")
	for i, r := range results {
		if r.ok {
			fmt.Printf("%2d. %-30s %6s\n", i+1, r.name, time.Duration(r.elapsedMS)*time.Millisecond)
		} else {
			fmt.Printf("%2d. %-30s FAILED — %s\n", i+1, r.name, r.err)
		}
	}
	return nil
}

// benchOne activates a single profile, runs one connectivity test, and
// deactivates regardless of the test's outcome — a failed test must never
// leave a broken profile active and block the rest of the benchmark.
func benchOne(p profile.Profile) benchResult {
	if _, _, err := vpnctlclient.Activate(p.Name); err != nil {
		return benchResult{name: p.Name, err: fmt.Sprintf("activating: %v", err)}
	}
	defer vpnctlclient.Deactivate()

	result, err := vpnctlclient.TestConnectivity()
	if err != nil {
		return benchResult{name: p.Name, err: fmt.Sprintf("testing: %v", err)}
	}
	if result.ExitCode != 0 {
		return benchResult{name: p.Name, err: fmt.Sprintf("curl exit %d", result.ExitCode)}
	}
	return benchResult{name: p.Name, ok: true, elapsedMS: result.ElapsedMS}
}

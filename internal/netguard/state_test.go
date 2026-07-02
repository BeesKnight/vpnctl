//go:build linux

package netguard

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

// TestUpdateActiveStateSerializesConcurrentWrites is the regression test for
// the historical race (A2): concurrent AddProcess calls used to
// read-modify-write active.json with no locking, so last-write-wins could
// silently drop a process a `run --gui`/`run --tui` had just registered.
// With UpdateActiveState holding an flock for the duration of each
// load-mutate-save cycle, every one of these concurrent writers must survive.
func TestUpdateActiveStateSerializesConcurrentWrites(t *testing.T) {
	withTempHome(t)

	if err := WriteActiveState(&ActiveState{ProfileName: "switz", ProfileKind: "amneziawg"}); err != nil {
		t.Fatalf("WriteActiveState: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pi := ProcessInfo{PID: i + 1, Name: fmt.Sprintf("proc-%d", i), Type: "cli"}
			if err := AddProcess(pi); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("AddProcess: %v", err)
	}

	state, err := LoadActiveState()
	if err != nil || state == nil {
		t.Fatalf("LoadActiveState after concurrent AddProcess: err=%v state=%v", err, state)
	}
	if len(state.Processes) != n {
		t.Fatalf("expected all %d concurrent AddProcess calls to be recorded, got %d", n, len(state.Processes))
	}

	seen := map[int]bool{}
	for _, p := range state.Processes {
		if seen[p.PID] {
			t.Errorf("duplicate PID %d recorded", p.PID)
		}
		seen[p.PID] = true
	}
}

func TestClearSysctlBackupValueRemovesKeyAndDeletesEmptyFile(t *testing.T) {
	withTempHome(t)

	backup := &SysctlBackup{Values: map[string]string{
		ipForwardKey: "0",
		"other.key":  "1",
	}}
	if err := SaveSysctlBackup(backup); err != nil {
		t.Fatalf("SaveSysctlBackup: %v", err)
	}

	if err := ClearSysctlBackupValue(ipForwardKey); err != nil {
		t.Fatalf("ClearSysctlBackupValue: %v", err)
	}
	got, err := LoadSysctlBackup()
	if err != nil {
		t.Fatalf("LoadSysctlBackup: %v", err)
	}
	if _, known := got.Values[ipForwardKey]; known {
		t.Errorf("expected %q to be removed from the backup", ipForwardKey)
	}
	if got.Values["other.key"] != "1" {
		t.Errorf("expected unrelated key to survive, got %v", got.Values)
	}

	if err := ClearSysctlBackupValue("other.key"); err != nil {
		t.Fatalf("ClearSysctlBackupValue: %v", err)
	}
	path, err := sysctlBackupPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Errorf("expected sysctl_backup.json to be removed once empty, but it still exists")
	}
}

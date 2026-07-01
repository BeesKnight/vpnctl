package sysuser

import "testing"

func TestRealHomeRespectsHOMEWhenNotUnderSudo(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("HOME", "/tmp/some-test-home")

	home, err := RealHome()
	if err != nil {
		t.Fatalf("RealHome: %v", err)
	}
	if home != "/tmp/some-test-home" {
		t.Errorf("expected RealHome to respect $HOME when not under sudo, got %q", home)
	}
}

func TestRanViaSudoReflectsSudoUserEnv(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	if RanViaSudo() {
		t.Error("expected RanViaSudo false with no SUDO_USER set")
	}
	t.Setenv("SUDO_USER", "someone")
	if !RanViaSudo() {
		t.Error("expected RanViaSudo true with SUDO_USER set")
	}
}

func TestChownToRealUserIfRootIsNoopWhenNotRoot(t *testing.T) {
	t.Setenv("SUDO_USER", "someone")
	dir := t.TempDir()
	// IsRoot() is false in the test process (not running as root), so this
	// must be a no-op regardless of $SUDO_USER — never attempt a chown
	// that would fail/be meaningless for a non-privileged process.
	if err := ChownToRealUserIfRoot(dir); err != nil {
		t.Errorf("expected no-op (nil) when not root, got %v", err)
	}
}

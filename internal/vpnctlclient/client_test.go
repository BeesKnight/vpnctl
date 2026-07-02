package vpnctlclient

import (
	"context"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/vpnctld"
)

const testWGConf = `[Interface]
PrivateKey = SAVkWKIFdAR0QBebdR9Ri4xIwSmCFHEzox/iYdW/kGg=
Address = 10.31.27.189/32

[Peer]
PublicKey = yzgmEGOF1GSTtsPNl3gHz9kD9gjA+1nreDXWRxN0SjI=
AllowedIPs = 0.0.0.0/0
Endpoint = 185.130.44.10:51820
`

// fakeSucceedingEngine mirrors internal/vpnctld's own test helper of the
// same name/purpose: a netguard.Engine whose Command() never runs the real
// target binary, so Activate can genuinely succeed without awg-quick/
// sing-box/xray installed or real networking touched.
type fakeSucceedingEngine struct {
	mu     sync.Mutex
	active bool
}

func (e *fakeSucceedingEngine) Setup(p profile.Profile) (netguard.Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = true
	return netguard.Status{ProfileName: p.Name, ProfileKind: string(p.Kind), Namespace: "vpnctl0", ResolvedIP: "185.130.44.10", ResolvedPort: 51820, Protocol: "udp"}, nil
}
func (e *fakeSucceedingEngine) Teardown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = false
	return nil
}
func (e *fakeSucceedingEngine) Status() (netguard.Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return netguard.Status{Active: e.active}, nil
}
func (e *fakeSucceedingEngine) UpdateEndpoint(profile.Profile) (bool, string, error) {
	return false, "", nil
}
func (e *fakeSucceedingEngine) Command(name string, args []string, opts netguard.ExecOptions) (*exec.Cmd, error) {
	return exec.Command("true"), nil
}
func (e *fakeSucceedingEngine) Recorded() []string { return nil }

// startTestDaemon starts a real vpnctld server on a temp socket and points
// $VPNCTL_SOCKET at it, so SocketPath()/call() exercise the exact path a
// real `vpnctl` invocation would.
func startTestDaemon(t *testing.T) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "vpnctld.sock")
	t.Setenv("VPNCTL_SOCKET", sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listening on %s: %v", sockPath, err)
	}
	srv := vpnctld.NewWithEngine(&fakeSucceedingEngine{}, log.New(os.Stderr, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func withProfile(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
	if err := profile.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	base, _ := profile.Dir()
	path := filepath.Join(base, "wg", "switz.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(testWGConf), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSocketPathRespectsEnvOverride(t *testing.T) {
	t.Setenv("VPNCTL_SOCKET", "/tmp/custom.sock")
	if got := SocketPath(); got != "/tmp/custom.sock" {
		t.Errorf("expected env override, got %q", got)
	}
}

func TestCallAgainstUnreachableSocketReportsClearError(t *testing.T) {
	t.Setenv("VPNCTL_SOCKET", filepath.Join(t.TempDir(), "nothing-listening.sock"))
	_, err := Status()
	if err == nil {
		t.Fatal("expected an error when nothing is listening on the socket")
	}
}

func TestActivateResolvesProfileAndActivatesThroughDaemon(t *testing.T) {
	withProfile(t)
	startTestDaemon(t)

	p, result, err := Activate("switz")
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if p.Name != "switz" {
		t.Errorf("expected resolved profile name 'switz', got %q", p.Name)
	}
	if result.Status.ResolvedIP != "185.130.44.10" {
		t.Errorf("expected resolved IP 185.130.44.10, got %q", result.Status.ResolvedIP)
	}

	status, err := Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Status.Active || status.Status.ProfileName != "switz" {
		t.Errorf("expected active profile 'switz' after Activate, got %+v", status.Status)
	}

	if err := Deactivate(); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	status, err = Status()
	if err != nil {
		t.Fatalf("Status after Deactivate: %v", err)
	}
	if status.Status.Active {
		t.Error("expected Active=false after Deactivate")
	}
}

func TestGetLogTailReturnsEmptyWithNothingActive(t *testing.T) {
	withProfile(t)
	startTestDaemon(t)

	text, err := GetLogTail(5)
	if err != nil {
		t.Fatalf("GetLogTail: %v", err)
	}
	if text != "" {
		t.Errorf("expected empty log tail with nothing active, got %q", text)
	}
}

func TestActivateUnknownProfileFailsBeforeContactingDaemon(t *testing.T) {
	withProfile(t)
	// Deliberately don't start a daemon — if Activate tries to resolve a
	// nonexistent profile before dialing, this must fail on profile.Find
	// with no socket error at all.
	t.Setenv("VPNCTL_SOCKET", filepath.Join(t.TempDir(), "unused.sock"))
	if _, _, err := Activate("does-not-exist"); err == nil {
		t.Fatal("expected an error resolving a nonexistent profile")
	}
}

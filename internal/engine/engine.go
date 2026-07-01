// Package engine manages the awg-quick, sing-box, and Xray-core subprocesses
// that actually move traffic once netguard has locked a namespace down. It
// never touches ip/iptables itself — every command it runs inside the
// namespace goes through the netguard.Engine.Command seam. Xray-core has no
// native TUN inbound (unlike sing-box), so a VLESS tunnel pairs it with
// tun2socks (see xray.go); addressing/routing the resulting vpnctl-tun
// device is tun2socks's own job via its `-tun-post-up` hook, not something
// this package does by hand.
package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
)

// Handle represents a running tunnel engine inside the active namespace:
// an awg-quick-managed WireGuard/AmneziaWG interface (no persistent
// foreground process — health is measured by handshake age), a sing-box
// process (a genuine long-running foreground process with a native TUN
// inbound), or a Xray-core process paired with a tun2socks helper (Xray has
// no native TUN inbound of its own — see xray.go).
type Handle interface {
	// Healthy reports whether the tunnel is actually passing traffic right
	// now, not just whether a process happens to be alive.
	Healthy() (bool, error)
	// Stop gracefully brings the engine down (awg-quick down / SIGTERM+wait),
	// including any helper process (e.g. tun2socks).
	Stop() error
	// LogPath is where the engine's stdout/stderr is captured for the TUI's
	// live log panel.
	LogPath() string
	// PID is the OS process id of the engine, or 0 when not applicable
	// (awg-quick's own process exits once the interface is configured).
	PID() int
	// HelperPID is the OS process id of a second, engine-owned process this
	// Handle also needs stopped/tracked (tun2socks, for Xray), or 0 when
	// there isn't one.
	HelperPID() int
	Kind() string
}

// Start brings up the engine appropriate for the profile's family/kind
// inside the already-locked-down namespace (netguard.Setup must have run
// first). VLESS always runs through Xray-core (the protocol's reference
// implementation, with the widest transport support — including xhttp,
// which sing-box's official build doesn't ship); Hysteria2 always runs
// through sing-box (Xray-core has no Hysteria2 support). This is a fixed
// rule by profile kind, not a per-profile/per-transport guess, so there is
// no "which engine understands this particular config" edge case to debug.
func Start(ng netguard.Engine, p profile.Profile) (Handle, error) {
	status, err := ng.Status()
	if err != nil {
		return nil, err
	}
	if !status.Active {
		return nil, fmt.Errorf("namespace not active: call netguard Setup first")
	}

	switch p.Family {
	case profile.FamilyWG:
		return startWireGuard(ng, p, status)
	case profile.FamilyProxy:
		switch p.Kind {
		case profile.KindVLESS:
			return startXray(ng, p, status)
		case profile.KindHysteria2:
			return startSingBox(ng, p, status)
		default:
			return nil, fmt.Errorf("unsupported proxy kind %q", p.Kind)
		}
	default:
		return nil, fmt.Errorf("unknown profile family %q", p.Family)
	}
}

// Stop brings down the engine described by state. Unlike Handle.Stop, this
// does not need the Handle returned by the original Start call — it works
// from the well-known on-disk config path (WireGuard) or tracked PID
// (sing-box/Xray), so a later, freshly-invoked `vpnctl down` can stop an
// engine that was started by a process which has since exited (engines are
// deliberately detached from the vpnctl process/TUI that launched them).
func Stop(ng netguard.Engine, state *netguard.ActiveState) error {
	switch profile.Kind(state.ProfileKind) {
	case profile.KindWireGuard, profile.KindAmneziaWG:
		return stopWireGuard(ng, profile.Kind(state.ProfileKind))
	default:
		if err := stopByPID(state.EnginePID); err != nil {
			return err
		}
		return stopByPID(state.HelperPID)
	}
}

// Healthy reports engine health purely from on-disk state, for the same
// cross-process reason as Stop. For engines with a helper process (Xray's
// tun2socks), both must be alive — if tun2socks dies, traffic stops moving
// even though Xray itself is still running.
func Healthy(ng netguard.Engine, state *netguard.ActiveState) (bool, error) {
	switch profile.Kind(state.ProfileKind) {
	case profile.KindWireGuard, profile.KindAmneziaWG:
		return wgHandshakeHealthy(ng)
	default:
		healthy := pidAlive(state.EnginePID)
		if state.HelperPID != 0 {
			healthy = healthy && pidAlive(state.HelperPID)
		}
		return healthy, nil
	}
}

func logDir() (string, error) {
	dir, err := netguard.EnsureStateDir()
	if err != nil {
		return "", err
	}
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		return "", err
	}
	return logs, nil
}

func openLog(name string) (path string, f *os.File, err error) {
	dir, err := logDir()
	if err != nil {
		return "", nil, err
	}
	path = filepath.Join(dir, name+".log")
	f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", nil, err
	}
	return path, f, nil
}

// Package netguard is the single seam through which vpnctl touches the
// operating system's network isolation primitives (network namespaces,
// veth, iptables). No other package may call exec.Command("ip", ...) or
// exec.Command("iptables", ...) directly — everything routes through the
// Engine interface below, so a future Windows port only requires a new
// implementation file (see linux.go's `//go:build linux` tag).
package netguard

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

// Engine sets up (and guarantees the teardown of) a default-DROP network
// namespace dedicated to a single active profile, and gives other packages
// a way to run commands inside it without themselves touching ip/iptables.
type Engine interface {
	// Setup tears down any previous namespace and creates a fresh one with
	// a default-DROP kill-switch, permitting traffic only to the profile's
	// resolved server IP/port. The engine process itself (awg-quick/sing-box)
	// is started separately (see internal/engine); Setup only prepares the
	// isolation the engine process will run inside of.
	Setup(p profile.Profile) (Status, error)

	// Teardown removes the namespace, veth pair, and every iptables rule
	// this engine added, and restores any sysctl values it changed.
	// Safe to call when nothing is active.
	Teardown() error

	// Status reports the current namespace/kill-switch state.
	Status() (Status, error)

	// UpdateEndpoint re-resolves the active profile's server hostname and,
	// if the IP changed, rewrites the point-to-point iptables/NAT rules in
	// place without tearing down the namespace or dropping the kill-switch.
	UpdateEndpoint(p profile.Profile) (changed bool, newIP string, err error)

	// Command builds an *exec.Cmd that executes inside the isolated
	// namespace. Stdio is left unset for the caller to wire (blocking
	// stream, terminal takeover, or detached — see internal/run).
	Command(name string, args []string, opts ExecOptions) (*exec.Cmd, error)

	// Recorded returns the ip/iptables commands issued so far. Always
	// populated; only interesting when the engine was built with dry-run.
	Recorded() []string
}

// protocolFor returns the transport protocol netguard must point-permit for
// this profile's kind: WireGuard/AmneziaWG and Hysteria2 both tunnel over
// UDP (Hysteria2 is QUIC-based); VLESS runs over TCP.
func protocolFor(k profile.Kind) string {
	switch k {
	case profile.KindWireGuard, profile.KindAmneziaWG, profile.KindHysteria2:
		return "udp"
	default:
		return "tcp"
	}
}

// resolveIP resolves host to a single IPv4/IPv6 address. If host is already
// an IP literal, it's returned unchanged (no DNS lookup performed) — this
// matters because once the kill-switch is up, the namespace typically can't
// reach a DNS resolver at all, so hostnames must be resolved from the host
// side before the point-to-point ACCEPT rule is written.
func resolveIP(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", host, err)
	}
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			return parsed.String(), nil
		}
	}
	return ips[0], nil
}

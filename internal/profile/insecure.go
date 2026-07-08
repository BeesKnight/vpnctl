package profile

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// certFetchTimeout bounds the one-time bootstrap TLS dial SetTLSInsecure
// makes to a VLESS server to learn its certificate (see pinVLESSCert) —
// generous since this only ever runs once, interactively, from `vpnctl
// insecure <profile>`.
const certFetchTimeout = 8 * time.Second

// SetTLSInsecure toggles skip-certificate-verification on a single
// already-imported VLESS/Hysteria2 profile's tls block, rewriting its
// on-disk JSON in place. Deliberately scoped to one profile at a time
// rather than a global default: most servers present a valid certificate,
// and silently skipping verification for all of them would trade away a
// real security property just to accommodate the few that don't. This is
// the explicit, per-profile opt-in for a server whose certificate a
// subscription doesn't (or can't) verify — the operator has to name the
// profile, so it can never apply somewhere it wasn't asked to.
//
// VLESS and Hysteria2 diverge here: sing-box (Hysteria2's engine) still
// honors a plain tls.insecure boolean, but Xray-core (VLESS's engine, see
// internal/engine/xray.go) removed that entirely — as of a recent release,
// setting it makes Xray refuse to start at all ("The feature allowInsecure
// has been removed and migrated to pinnedPeerCertSha256"), which used to
// mean any VLESS profile toggled insecure was completely broken (confirmed
// live: Xray failed to bind its own SOCKS inbound, so tun2socks had
// nothing to connect to, and every connection through the profile just
// timed out with no clear error pointing at the actual cause). Xray's
// replacement mechanism pins to one specific certificate's hash rather
// than skipping verification against any certificate — arguably a real
// security improvement over the old blanket "insecure" bit, not just a
// workaround — so for VLESS this dials the server once to learn that
// certificate and stores its hash instead of a boolean.
func SetTLSInsecure(p Profile, insecure bool) error {
	if p.Family != FamilyProxy {
		return fmt.Errorf("%q is not a VLESS/Hysteria2 profile — no tls block to set", p.Name)
	}
	tlsBlock, ok := p.Outbound["tls"].(map[string]any)
	if !ok {
		tlsBlock = map[string]any{}
	}

	if !insecure {
		delete(tlsBlock, "insecure")
		delete(tlsBlock, "pinned_cert_sha256")
		p.Outbound["tls"] = tlsBlock
		return writeOutbound(p)
	}

	if p.Kind == KindVLESS {
		if reality, ok := tlsBlock["reality"].(map[string]any); ok {
			if enabled, _ := reality["enabled"].(bool); enabled {
				return fmt.Errorf("%q uses Reality, which authenticates via its own public/private keypair, not certificate trust — there is nothing for \"insecure\" to skip here", p.Name)
			}
		}
		pin, err := fetchPeerCertSHA256(p.Server, p.Port)
		if err != nil {
			return fmt.Errorf("fetching %s:%d's certificate to pin it (Xray-core no longer supports blanket \"insecure\", see SetTLSInsecure's doc comment): %w", p.Server, p.Port, err)
		}
		tlsBlock["pinned_cert_sha256"] = pin
		delete(tlsBlock, "insecure") // superseded by the pin for VLESS; never emitted to Xray now anyway (see applyTLSStreamSettings)
	} else {
		tlsBlock["insecure"] = true
	}

	tlsBlock["enabled"] = true // dialing implies the server does speak TLS; make sure applyTLSStreamSettings's/sing-box's own "enabled" gate doesn't no-op the pin/insecure flag we just set
	p.Outbound["tls"] = tlsBlock
	return writeOutbound(p)
}

func writeOutbound(p Profile) error {
	data, err := json.MarshalIndent(p.Outbound, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p.Path, data, 0o644); err != nil {
		return err
	}
	return sysuser.ChownToRealUserIfRoot(p.Path)
}

// fetchPeerCertSHA256 dials host:port with TLS, itself skipping
// verification just for this one bootstrap handshake — this call never
// carries any user traffic, it exists purely to learn what certificate the
// server presents so it can be pinned exactly, the same hash algorithm
// Xray-core's own pinnedPeerCertSha256 verification uses
// (sha256 of the leaf certificate's raw DER bytes, hex-encoded).
func fetchPeerCertSHA256(host string, port int) (string, error) {
	d := &net.Dialer{Timeout: certFetchTimeout}
	conn, err := tls.DialWithDialer(d, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // deliberate: this is the one-time bootstrap that lets us stop trusting blindly afterward
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("server presented no certificate")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

package profile

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// amneziaFields are the obfuscation parameters unique to AmneziaWG configs.
// Their presence in [Interface] is what distinguishes AmneziaWG from plain WireGuard.
var amneziaFields = []string{
	"Jc", "Jmin", "Jmax",
	"S1", "S2", "S3", "S4",
	"H1", "H2", "H3", "H4",
	"I1", "I2", "I3",
}

// WGPeer holds the [Peer] section of a WireGuard/AmneziaWG config.
type WGPeer struct {
	fields map[string]string
}

// Get returns a raw field from [Peer], case-sensitive to the on-disk key.
func (p WGPeer) Get(key string) string { return p.fields[key] }

// Host returns the peer's endpoint host, stripped of port.
func (p WGPeer) Host() string {
	host, _, err := net.SplitHostPort(p.fields["Endpoint"])
	if err != nil {
		return p.fields["Endpoint"]
	}
	return host
}

// PortNum returns the peer's endpoint port, or 0 if absent/unparseable.
func (p WGPeer) PortNum() int {
	_, port, err := net.SplitHostPort(p.fields["Endpoint"])
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}

// DNSServers returns the nameserver IPs from [Interface]'s DNS field
// (comma-separated; some entries may be search domains rather than IPs —
// those are skipped, since only IPs are valid `nameserver` lines). Used to
// populate the namespace's own resolv.conf (see netguard's per-namespace
// DNS handling) instead of ever letting awg-quick manage the *host's*
// resolvconf/NetworkManager/systemd-resolved.
func (c *WireGuardConfig) DNSServers() []string {
	raw := ""
	for k, v := range c.Interface {
		if strings.EqualFold(k, "DNS") {
			raw = v
			break
		}
	}
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if ip := net.ParseIP(part); ip != nil {
			out = append(out, part)
		}
	}
	return out
}

// WireGuardConfig is a parsed WireGuard or AmneziaWG .conf file.
// The Raw content is preserved verbatim, since it's what actually gets
// handed to awg-quick — the struct only exists for display/validation.
type WireGuardConfig struct {
	Interface map[string]string
	Peer      WGPeer
	Raw       string
}

// Kind reports whether this config carries AmneziaWG obfuscation fields.
func (c *WireGuardConfig) Kind() Kind {
	for _, k := range amneziaFields {
		for ifaceKey := range c.Interface {
			if strings.EqualFold(ifaceKey, k) {
				return KindAmneziaWG
			}
		}
	}
	return KindWireGuard
}

// ParseWireGuardFile reads and parses a WireGuard/AmneziaWG .conf file from disk.
func ParseWireGuardFile(path string) (*WireGuardConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseWireGuard(string(data))
}

// ParseWireGuard parses WireGuard/AmneziaWG INI-style config text.
// Unknown keys (including all Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I3 obfuscation
// fields) are preserved as opaque key/value pairs rather than rejected.
func ParseWireGuard(content string) (*WireGuardConfig, error) {
	cfg := &WireGuardConfig{
		Interface: map[string]string{},
		Peer:      WGPeer{fields: map[string]string{}},
		Raw:       content,
	}

	section := ""
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch section {
		case "interface":
			cfg.Interface[key] = val
		case "peer":
			cfg.Peer.fields[key] = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(cfg.Peer.fields) == 0 {
		return nil, fmt.Errorf("no [Peer] section found")
	}
	if _, ok := cfg.Peer.fields["Endpoint"]; !ok {
		return nil, fmt.Errorf("[Peer] section missing Endpoint")
	}
	return cfg, nil
}

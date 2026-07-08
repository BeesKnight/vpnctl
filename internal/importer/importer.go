package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

// maxSubscriptionBytes bounds how much of a subscription response
// ImportSubscription will read. A real subscription is a short list of
// vless://Zhysteria2:// URIs — nothing legitimate needs more than a few
// hundred KB — but the URL is arbitrary user input pointing at a server
// vpnctl doesn't control, and a compromised or malicious subscription
// endpoint returning gigabytes with no Content-Length set would otherwise
// have io.ReadAll grow an unbounded buffer and OOM the calling process.
const maxSubscriptionBytes = 4 << 20 // 4 MiB

// ImportSubscription downloads url and imports every profile found in it
// (see ImportSubscriptionBody).
func ImportSubscription(url string) ([]string, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching subscription: HTTP %d", resp.StatusCode)
	}
	// Read one byte past the cap so an exactly-at-the-limit legitimate
	// response isn't mistaken for a truncated/oversized one, but a
	// genuinely larger body still gets rejected instead of silently
	// truncated and mis-parsed.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading subscription body: %w", err)
	}
	if len(body) > maxSubscriptionBytes {
		return nil, fmt.Errorf("subscription response too large (over %d bytes) — refusing to read further", maxSubscriptionBytes)
	}
	return ImportSubscriptionBody(body)
}

// ImportSubscriptionBody decodes a subscription body, parses every
// vless://Zhysteria2:// URI it contains, and writes one profile per entry
// under profiles/proxy/. Unknown schemes are skipped rather than failing
// the whole import; only if *nothing* could be imported is an error
// returned. Returns the profile names written.
func ImportSubscriptionBody(body []byte) ([]string, error) {
	uris, err := ParseSubscription(body)
	if err != nil {
		return nil, err
	}

	base, err := profile.Dir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(base, string(profile.FamilyProxy))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	var names []string
	var errs []string
	for _, uri := range uris {
		var name string
		var outbound map[string]any
		var perr error
		switch {
		case strings.HasPrefix(uri, "vless://"):
			name, outbound, perr = ParseVLESS(uri)
		case strings.HasPrefix(uri, "hysteria2://"), strings.HasPrefix(uri, "hy2://"):
			name, outbound, perr = ParseHysteria2(uri)
		default:
			continue
		}
		if perr != nil {
			errs = append(errs, perr.Error())
			continue
		}

		name = uniqueName(dir, name, ".json")
		data, err := json.MarshalIndent(outbound, "", "  ")
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		_ = sysuser.ChownToRealUserIfRoot(path)
		names = append(names, name)
	}

	if len(names) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("no profiles imported: %s", strings.Join(errs, "; "))
		}
		return nil, fmt.Errorf("no vless:// or hysteria2:// URIs found in subscription")
	}
	return names, nil
}

// ImportWireGuardFile validates a WireGuard/AmneziaWG .conf file at path
// and copies it into profiles/wg/.
func ImportWireGuardFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return ImportWireGuardText(base, string(data))
}

// ImportWireGuardText validates raw WireGuard/AmneziaWG config text
// (Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I3 obfuscation fields included) and writes it
// under profiles/wg/<name>.conf.
func ImportWireGuardText(name, content string) (string, error) {
	if _, err := profile.ParseWireGuard(content); err != nil {
		return "", fmt.Errorf("invalid WireGuard config: %w", err)
	}

	base, err := profile.Dir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, string(profile.FamilyWG))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	name = uniqueName(dir, sanitizeName(name), ".conf")
	path := filepath.Join(dir, name+".conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	if err := sysuser.ChownToRealUserIfRoot(path); err != nil {
		return "", err
	}
	return name, nil
}

// uniqueName appends "-2", "-3", ... to base until dir/base+ext doesn't
// already exist, so importing never silently overwrites an existing profile.
func uniqueName(dir, base, ext string) string {
	if base == "" {
		base = "profile"
	}
	name := base
	for i := 2; ; i++ {
		if _, err := os.Stat(filepath.Join(dir, name+ext)); os.IsNotExist(err) {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
}

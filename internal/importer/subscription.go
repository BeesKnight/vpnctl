// Package importer turns subscription links and raw WireGuard/AmneziaWG
// configs into profiles under ~/.config/vpnctl/profiles.
package importer

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ParseSubscription decodes a subscription body (base64, optionally with a
// trailing newline/whitespace) into individual server URIs, one per
// non-empty line. Falls back to treating the body as plain text (already
// one URI per line) if it isn't valid base64 — some subscription servers
// skip the encoding step despite the format's name.
func ParseSubscription(body []byte) ([]string, error) {
	decoded, err := decodeBase64Flexible(body)
	if err != nil {
		decoded = body
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(decoded)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("subscription body contained no URIs")
	}
	return out, nil
}

// decodeBase64Flexible tries every base64 flavor real-world subscription
// services emit (standard/URL-safe, padded/unpadded).
func decodeBase64Flexible(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if out, err := enc.DecodeString(s); err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("not valid base64")
}

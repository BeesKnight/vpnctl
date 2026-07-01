package importer

import (
	"fmt"
	"net/url"
	"strconv"
)

// ParseHysteria2 parses a hysteria2:// (or hy2://) URI into a sing-box
// outbound JSON object, plus a suggested profile name from the fragment.
func ParseHysteria2(raw string) (name string, outbound map[string]any, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, fmt.Errorf("parsing hysteria2 URI: %w", err)
	}
	if u.Scheme != "hysteria2" && u.Scheme != "hy2" {
		return "", nil, fmt.Errorf("not a hysteria2:// URI")
	}
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if password == "" {
		return "", nil, fmt.Errorf("hysteria2 URI missing password")
	}
	host := u.Hostname()
	if host == "" {
		return "", nil, fmt.Errorf("hysteria2 URI missing host")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return "", nil, fmt.Errorf("hysteria2 URI missing/invalid port: %w", err)
	}

	q := u.Query()
	outbound = map[string]any{
		"type":        "hysteria2",
		"server":      host,
		"server_port": port,
		"password":    password,
	}

	tls := map[string]any{"enabled": true, "server_name": firstNonEmpty(q.Get("sni"), host)}
	if q.Get("insecure") == "1" {
		tls["insecure"] = true
	}
	outbound["tls"] = tls

	if obfsType := q.Get("obfs"); obfsType != "" {
		obfs := map[string]any{"type": obfsType}
		if pw := q.Get("obfs-password"); pw != "" {
			obfs["password"] = pw
		}
		outbound["obfs"] = obfs
	}

	name = sanitizeName(u.Fragment)
	if name == "" {
		name = host
	}
	return name, outbound, nil
}

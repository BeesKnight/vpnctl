package importer

import (
	"fmt"
	"net/url"
	"strconv"
)

// ParseVLESS parses a vless:// URI (as emitted by v2ray/xray-style
// subscriptions) into a sing-box outbound JSON object, plus a suggested
// profile name taken from the URI's fragment (#remark).
func ParseVLESS(raw string) (name string, outbound map[string]any, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, fmt.Errorf("parsing vless URI: %w", err)
	}
	if u.Scheme != "vless" {
		return "", nil, fmt.Errorf("not a vless:// URI")
	}
	if u.User == nil || u.User.Username() == "" {
		return "", nil, fmt.Errorf("vless URI missing uuid")
	}
	host := u.Hostname()
	if host == "" {
		return "", nil, fmt.Errorf("vless URI missing host")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return "", nil, fmt.Errorf("vless URI missing/invalid port: %w", err)
	}

	q := u.Query()
	outbound = map[string]any{
		"type":        "vless",
		"server":      host,
		"server_port": port,
		"uuid":        u.User.Username(),
	}
	if flow := q.Get("flow"); flow != "" {
		outbound["flow"] = flow
	}

	if security := q.Get("security"); security != "none" {
		tls := map[string]any{"enabled": true}
		sni := firstNonEmpty(q.Get("sni"), q.Get("host"), host)
		tls["server_name"] = sni
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			tls["insecure"] = true
		}
		if fp := q.Get("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if security == "reality" {
			reality := map[string]any{"enabled": true}
			if pbk := q.Get("pbk"); pbk != "" {
				reality["public_key"] = pbk
			}
			if sid := q.Get("sid"); sid != "" {
				reality["short_id"] = sid
			}
			tls["reality"] = reality
		}
		outbound["tls"] = tls
	}

	switch netType := q.Get("type"); netType {
	case "ws":
		transport := map[string]any{"type": "ws"}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if hostHeader := q.Get("host"); hostHeader != "" {
			transport["headers"] = map[string]any{"Host": hostHeader}
		}
		outbound["transport"] = transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if svc := q.Get("serviceName"); svc != "" {
			transport["service_name"] = svc
		}
		outbound["transport"] = transport
	case "xhttp", "splithttp":
		// xhttp (formerly SplitHTTP) is a Xray-core-native transport with no
		// sing-box equivalent — see internal/engine/xray.go, which is the
		// only consumer of this shape. host/mode are plain fields here
		// (rather than an HTTP header, unlike ws/http) because that's how
		// Xray-core's own xhttpSettings represents them.
		transport := map[string]any{"type": "xhttp"}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if hostHeader := q.Get("host"); hostHeader != "" {
			transport["host"] = hostHeader
		}
		if mode := q.Get("mode"); mode != "" {
			transport["mode"] = mode
		}
		outbound["transport"] = transport
	case "http", "h2":
		transport := map[string]any{"type": "http"}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if hostHeader := q.Get("host"); hostHeader != "" {
			transport["headers"] = map[string]any{"Host": hostHeader}
		}
		outbound["transport"] = transport
	case "", "tcp", "raw":
		// no transport block needed — plain TCP
	default:
		transport := map[string]any{"type": netType}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if hostHeader := q.Get("host"); hostHeader != "" {
			transport["headers"] = map[string]any{"Host": hostHeader}
		}
		outbound["transport"] = transport
	}

	name = sanitizeName(u.Fragment)
	if name == "" {
		name = host
	}
	return name, outbound, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

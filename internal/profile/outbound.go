package profile

import (
	"encoding/json"
	"fmt"
	"os"
)

// ParseOutboundFile reads a sing-box outbound segment (VLESS/Hysteria2) from disk.
func ParseOutboundFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseOutbound(data)
}

// ParseOutbound parses a raw sing-box outbound JSON object.
func ParseOutbound(data []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid outbound json: %w", err)
	}
	t, ok := m["type"].(string)
	if !ok || t == "" {
		return nil, fmt.Errorf("outbound json missing 'type' field")
	}
	if _, ok := m["server"].(string); !ok {
		return nil, fmt.Errorf("outbound json missing 'server' field")
	}
	return m, nil
}

// Package rpc is the wire protocol between vpnctl (client) and vpnctld (the
// privileged daemon that owns netns/iptables/engine state): a
// length-prefixed JSON envelope over a Unix domain socket, one request per
// connection — a fresh dial/send/recv/close per call, mirroring vpnctl's
// existing one-process-per-invocation model rather than a persistent
// multiplexed session.
package rpc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// APIVersion is the current protocol version. The daemon rejects any
// request whose Request.APIVersion doesn't match its own, rather than
// guessing at a request shape it wasn't built to understand.
const APIVersion = "1"

// DefaultSocketPath is where vpnctld listens and vpnctl dials by default.
// A single shared constant so the two binaries can't drift apart on it.
const DefaultSocketPath = "/run/vpnctl.sock"

// maxMessageSize bounds a single framed message, so a corrupt or hostile
// length prefix can't force an unbounded allocation.
const maxMessageSize = 16 << 20 // 16 MiB

// Request is one client->daemon call. Params is the method-specific
// payload; handlers unmarshal it into the concrete params type for Method.
type Request struct {
	APIVersion string          `json:"api_version"`
	ID         uint64          `json:"id"`
	Method     string          `json:"method"`
	Params     json.RawMessage `json:"params,omitempty"`
}

// Response is one daemon->client reply. Exactly one of Result/Error is set.
type Response struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// WriteMessage frames v (a *Request or *Response) as [4-byte big-endian
// length][JSON] and writes it to w.
func WriteMessage(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}
	if len(data) > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes", len(data))
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("writing message length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing message body: %w", err)
	}
	return nil
}

// ReadMessage reads one length-prefixed JSON message from r and unmarshals
// it into v (a *Request or *Response). A clean close before any bytes
// arrive surfaces as io.EOF, same as a bare io.Reader would.
func ReadMessage(r io.Reader, v any) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("reading message body: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("unmarshaling message: %w", err)
	}
	return nil
}

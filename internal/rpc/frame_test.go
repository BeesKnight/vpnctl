package rpc

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestWriteReadMessageRoundTrip(t *testing.T) {
	req := Request{
		APIVersion: APIVersion,
		ID:         42,
		Method:     MethodStatus,
		Params:     json.RawMessage(`{"foo":"bar"}`),
	}

	var buf bytes.Buffer
	if err := WriteMessage(&buf, &req); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	var got Request
	if err := ReadMessage(&buf, &got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got.APIVersion != req.APIVersion || got.ID != req.ID || got.Method != req.Method {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, req)
	}
	if string(got.Params) != string(req.Params) {
		t.Errorf("params mismatch: got %s, want %s", got.Params, req.Params)
	}
}

func TestReadMessageEOFOnCleanClose(t *testing.T) {
	var buf bytes.Buffer // empty: simulates a connection closed before any bytes arrive
	var got Request
	if err := ReadMessage(&buf, &got); err != io.EOF {
		t.Errorf("expected io.EOF on empty reader, got %v", err)
	}
}

func TestWriteMessageRejectsOversizedPayload(t *testing.T) {
	huge := make([]byte, maxMessageSize+1)
	resp := Response{ID: 1, Result: json.RawMessage(huge)}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, &resp); err == nil {
		t.Fatal("expected an error writing an oversized message, got nil")
	}
}

func TestMultipleMessagesOnSameStream(t *testing.T) {
	var buf bytes.Buffer
	for i := uint64(0); i < 3; i++ {
		if err := WriteMessage(&buf, &Request{APIVersion: APIVersion, ID: i, Method: MethodPing}); err != nil {
			t.Fatalf("WriteMessage %d: %v", i, err)
		}
	}
	for i := uint64(0); i < 3; i++ {
		var got Request
		if err := ReadMessage(&buf, &got); err != nil {
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		if got.ID != i {
			t.Errorf("message %d: expected ID %d, got %d", i, i, got.ID)
		}
	}
}

package rpc

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, FrameStdout, []byte("hello")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	ft, payload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if ft != FrameStdout {
		t.Errorf("expected FrameStdout, got %v", ft)
	}
	if string(payload) != "hello" {
		t.Errorf("expected %q, got %q", "hello", payload)
	}
}

func TestWriteReadFrameEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, FrameStdin, nil); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	ft, payload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if ft != FrameStdin || len(payload) != 0 {
		t.Errorf("expected empty FrameStdin, got type=%v payload=%q", ft, payload)
	}
}

func TestWriteJSONFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := ResizeMessage{Rows: 24, Cols: 80}
	if err := WriteJSONFrame(&buf, FrameResize, want); err != nil {
		t.Fatalf("WriteJSONFrame: %v", err)
	}
	ft, payload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if ft != FrameResize {
		t.Errorf("expected FrameResize, got %v", ft)
	}
	var got ResizeMessage
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if got != want {
		t.Errorf("expected %+v, got %+v", want, got)
	}
}

func TestMultipleFramesOnSameStream(t *testing.T) {
	var buf bytes.Buffer
	frames := []struct {
		t FrameType
		p []byte
	}{
		{FrameStdout, []byte("line 1\n")},
		{FrameStdout, []byte("line 2\n")},
		{FrameExit, mustJSON(t, ExitMessage{Code: 0})},
	}
	for _, f := range frames {
		if err := WriteFrame(&buf, f.t, f.p); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for _, want := range frames {
		gotType, gotPayload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if gotType != want.t || string(gotPayload) != string(want.p) {
			t.Errorf("expected type=%v payload=%q, got type=%v payload=%q", want.t, want.p, gotType, gotPayload)
		}
	}
}

func TestReadFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	huge := make([]byte, maxFramePayload+1)
	if err := WriteFrame(&buf, FrameStdout, huge); err == nil {
		t.Fatal("expected WriteFrame to reject an oversized payload")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	return data
}

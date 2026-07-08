package main

import "testing"

func TestLastNonEmptyLine(t *testing.T) {
	cases := map[string]string{
		"a\nb\nc\n": "c",
		"a\nb\nc":   "c",
		"a\n\n\n":   "a",
		"":          "",
		"\n\n":      "",
	}
	for in, want := range cases {
		if got := lastNonEmptyLine(in); got != want {
			t.Errorf("lastNonEmptyLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogsNewSuffixFindsOnlyWhatsNew(t *testing.T) {
	text := "line1\nline2\nline3\nline4\n"
	suffix, ok := logsNewSuffix(text, "line2")
	if !ok {
		t.Fatal("expected ok=true, anchor is present")
	}
	if suffix != "line3\nline4\n" {
		t.Errorf("got suffix %q", suffix)
	}
}

func TestLogsNewSuffixNoNewLines(t *testing.T) {
	text := "line1\nline2\n"
	suffix, ok := logsNewSuffix(text, "line2")
	if !ok {
		t.Fatal("expected ok=true, anchor is present as the last line")
	}
	if suffix != "" {
		t.Errorf("expected no new content, got %q", suffix)
	}
}

func TestLogsNewSuffixAnchorFellOutOfWindow(t *testing.T) {
	text := "line5\nline6\nline7\n"
	_, ok := logsNewSuffix(text, "line2")
	if ok {
		t.Error("expected ok=false when the anchor line isn't present in the new tail at all")
	}
}

func TestLogsNewSuffixEmptyAnchor(t *testing.T) {
	_, ok := logsNewSuffix("line1\nline2\n", "")
	if ok {
		t.Error("expected ok=false for an empty anchor (nothing printed yet)")
	}
}

func TestLogsNewSuffixPicksLastOccurrenceOfDuplicateAnchor(t *testing.T) {
	// A log line's text can legitimately repeat (e.g. the same "handshake
	// completed" message twice) — the diff must anchor on the *last*
	// occurrence, or it would re-print everything after the first
	// duplicate as if it were new.
	text := "start\nping\nmiddle\nping\nend\n"
	suffix, ok := logsNewSuffix(text, "ping")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if suffix != "end\n" {
		t.Errorf("got suffix %q, want %q", suffix, "end\n")
	}
}

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

// defaultLogLines/followLogLines/followPollInterval tune `vpnctl logs`:
// a short tail for a one-shot look, a wider tail while following so a
// burst of engine output between polls is still likely to overlap with
// what was already printed (see logsNewSuffix).
const (
	defaultLogLines    = 20
	followLogLines     = 500
	followPollInterval = 1 * time.Second
)

// cmdLogs prints the active engine's recent log output, matching what the
// TUI's LOGS pane already shows via the same GetLogTail RPC — `-f`/
// `--follow` polls it repeatedly and prints only newly-appeared lines,
// tail(1)-style. There is no dedicated streaming RPC for this: GetLogTail
// already existed (built for the TUI's 2-second-tick refresh), and reusing
// it here is simpler than building a second, parallel streaming protocol
// alongside Exec's for what's fundamentally the same "poll a file tail"
// operation vpnctld already does.
func cmdLogs(args []string) error {
	follow := false
	for _, a := range args {
		if a == "-f" || a == "--follow" {
			follow = true
		}
	}

	text, err := vpnctlclient.GetLogTail(defaultLogLines)
	if err != nil {
		return err
	}
	if text == "" {
		fmt.Println("(no engine running or no output yet)")
	} else {
		fmt.Println(text)
	}
	if !follow {
		return nil
	}

	lastLine := lastNonEmptyLine(text)
	for {
		time.Sleep(followPollInterval)
		text, err := vpnctlclient.GetLogTail(followLogLines)
		if err != nil {
			// Transient (daemon restart, no active profile right now) —
			// `vpnctl logs -f` is meant to sit and wait, not bail the
			// moment the tunnel is briefly down between profile switches.
			continue
		}
		if text == "" {
			continue
		}
		if suffix, ok := logsNewSuffix(text, lastLine); ok {
			if suffix != "" {
				fmt.Print(suffix)
			}
		} else if text != "" {
			// lastLine fell out of the tail window entirely (too much was
			// written between polls) — print what's available now rather
			// than silently missing it; a possible duplicate line or two
			// is the acceptable cost of a best-effort follow.
			fmt.Println(text)
		}
		lastLine = lastNonEmptyLine(text)
	}
}

// lastNonEmptyLine returns the last non-blank line of s, used as the
// anchor for finding where already-printed content ends in the next poll.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

// logsNewSuffix finds the last occurrence of anchor in text's lines and
// returns everything after it, newline-joined. ok is false if anchor
// (empty, or genuinely not found) can't anchor a diff — the caller falls
// back to printing the whole tail in that case.
func logsNewSuffix(text, anchor string) (suffix string, ok bool) {
	if anchor == "" {
		return "", false
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	idx := -1
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] == anchor {
			idx = i
			break
		}
	}
	if idx == -1 {
		return "", false
	}
	rest := lines[idx+1:]
	if len(rest) == 0 {
		return "", true
	}
	return strings.Join(rest, "\n") + "\n", true
}

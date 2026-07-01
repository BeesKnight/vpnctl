package netguard

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner executes (or, in dry-run mode, merely records) the shell commands
// netguard needs to set up network isolation. This is the seam that lets
// unit tests assert on the exact iptables/ip invocations without touching
// the host's real networking.
type Runner interface {
	// Run executes name(args...), discarding stdout, returning combined
	// output on error for diagnostics.
	Run(name string, args ...string) error
	// Output executes name(args...) and returns its stdout.
	Output(name string, args ...string) (string, error)
	// Recorded returns the commands executed so far, formatted as shell
	// command lines. Always available, but only interesting in dry-run mode.
	Recorded() []string
}

// execRunner runs commands for real via os/exec.
type execRunner struct {
	log []string
}

func (r *execRunner) Run(name string, args ...string) error {
	r.log = append(r.log, formatCmd(name, args))
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", formatCmd(name, args), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (r *execRunner) Output(name string, args ...string) (string, error) {
	r.log = append(r.log, formatCmd(name, args))
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w: %s", formatCmd(name, args), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func (r *execRunner) Recorded() []string { return r.log }

// dryRunRunner never touches the host: it only records what would have run.
// Used by `--dry-run` flags and by unit tests validating rule generation.
type dryRunRunner struct {
	log []string
}

func (r *dryRunRunner) Run(name string, args ...string) error {
	r.log = append(r.log, formatCmd(name, args))
	return nil
}

func (r *dryRunRunner) Output(name string, args ...string) (string, error) {
	r.log = append(r.log, formatCmd(name, args))
	return "", nil
}

func (r *dryRunRunner) Recorded() []string { return r.log }

func formatCmd(name string, args []string) string {
	parts := append([]string{name}, args...)
	for i, p := range parts {
		if strings.ContainsAny(p, " \t\"'") {
			parts[i] = fmt.Sprintf("%q", p)
		}
	}
	return strings.Join(parts, " ")
}

// NewRunner returns the real or dry-run command runner. Also honors the
// VPNCTL_DRY_RUN=1 environment variable so any subcommand can be exercised
// in dry-run mode without a code change (used by tests/CI).
func NewRunner(dryRun bool) Runner {
	if dryRun || os.Getenv("VPNCTL_DRY_RUN") == "1" {
		return &dryRunRunner{}
	}
	return &execRunner{}
}

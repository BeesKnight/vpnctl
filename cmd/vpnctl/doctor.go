package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
	"github.com/BeesKnight/vpnctl/internal/vpnctlclient"
)

type checkResult struct {
	name string
	ok   bool
	info string
	// fix, if non-nil, is a self-contained remediation this specific
	// check knows how to apply — only set for failures doctor can safely
	// resolve itself without root-owned package installs (that duplicate
	// logic belongs in postinst/install.sh, not here — see runFixes).
	// Returns a short description of what it did, or an error.
	fix func() (string, error)
}

// cmdDoctor is vpnctl's brew-doctor/flutter-doctor-style self-check: every
// system dependency and permission the network layer needs, printed as a
// checklist so a failure is immediately actionable rather than surfacing as
// a confusing mid-operation error. `vpnctl doctor --fix` additionally
// applies whichever failing checks are safely self-fixable (see
// checkResult.fix) and re-checks afterward.
func cmdDoctor(args []string) error {
	fixMode := false
	for _, a := range args {
		if a == "--fix" {
			fixMode = true
		}
	}

	results := runDoctorChecks()

	if fixMode {
		fixed := false
		for _, r := range results {
			if r.ok || r.fix == nil {
				continue
			}
			desc, err := r.fix()
			if err != nil {
				fmt.Printf("[fix] %-28s failed: %v\n", r.name, err)
				continue
			}
			fmt.Printf("[fix] %-28s %s\n", r.name, desc)
			fixed = true
		}
		if fixed {
			fmt.Println()
			results = runDoctorChecks() // re-check: report the post-fix state below, not the stale pre-fix one
		}
	}

	allOK := true
	unfixedFailures := false
	for _, r := range results {
		mark := "✓"
		if !r.ok {
			mark = "✗"
			allOK = false
			if r.fix == nil {
				unfixedFailures = true
			}
		}
		if r.info != "" {
			fmt.Printf("[%s] %-28s %s\n", mark, r.name, r.info)
		} else {
			fmt.Printf("[%s] %s\n", mark, r.name)
		}
	}

	fmt.Println()
	if allOK {
		fmt.Println("All checks passed — vpnctl is ready to use.")
		return nil
	}
	if !fixMode && !unfixedFailures {
		fmt.Println("Some checks failed — see above. Run `vpnctl doctor --fix` to attempt automatic repair.")
	} else {
		fmt.Println("Some checks failed — see above. Run the installer again or install the missing pieces manually.")
	}
	os.Exit(1)
	return nil
}

func runDoctorChecks() []checkResult {
	var results []checkResult

	results = append(results, checkBinary("ip", "iproute2")...)
	results = append(results, checkBinary("iptables", "iptables")...)
	results = append(results, checkBinary("nsenter", "util-linux")...)
	results = append(results, checkBinary("unshare", "util-linux")...)
	results = append(results, checkBinary("setpriv", "util-linux")...)
	results = append(results, checkBinary("jq", "jq")...)
	results = append(results, checkBinary("curl", "curl")...)
	results = append(results, checkEngineBinary("sing-box", "Hysteria2 profiles")...)
	results = append(results, checkEngineBinary("xray", "VLESS profiles")...)
	results = append(results, checkEngineBinary("tun2socks", "VLESS profiles' TUN mode (paired with xray)")...)
	results = append(results, checkAWG()...)
	results = append(results, checkVpnctld())
	results = append(results, checkStaleWireGuardSocket())

	results = append(results, checkResult{
		// Purely informational since the daemon migration: vpnctl itself
		// (as opposed to vpnctld) has never needed root for anything,
		// running as root isn't wrong either, so neither state is a real
		// failure — this used to be `ok: sysuser.IsRoot()`, which made
		// `vpnctl doctor` report overall failure (exit 1) for the correct,
		// recommended way of running it (as a regular "vpnctl"-group
		// member) ever since Phase 3 of DAEMON_MIGRATION.md removed the
		// TUI's own RequireRoot() call.
		name: "root/sudo",
		ok:   true,
		info: rootInfo(),
	})

	results = append(results, checkNetns())
	results = append(results, checkSysctl())
	results = append(results, checkDirs()...)

	return results
}

func checkBinary(name, pkg string) []checkResult {
	path, err := exec.LookPath(name)
	if err != nil {
		return []checkResult{{name: name, ok: false, info: fmt.Sprintf("not found (install package %q)", pkg)}}
	}
	return []checkResult{{name: name, ok: true, info: path}}
}

func checkEngineBinary(name, usedFor string) []checkResult {
	path, err := exec.LookPath(name)
	if err != nil {
		return []checkResult{{name: name, ok: false, info: fmt.Sprintf("not found — needed for %s (see README/install.sh)", usedFor)}}
	}
	return []checkResult{{name: name, ok: true, info: path}}
}

func checkAWG() []checkResult {
	check := func(name string) checkResult {
		if path, err := exec.LookPath(name); err == nil {
			return checkResult{name: name, ok: true, info: path}
		}
		return checkResult{name: name, ok: false, info: "not found — needed for AmneziaWG profiles (see README/install.sh)"}
	}
	results := []checkResult{
		check("awg-quick"),
		check("awg"),
		check("amneziawg-go"),
	}
	if path, err := exec.LookPath("wg-quick"); err == nil {
		results = append(results, checkResult{name: "wg-quick", ok: true, info: path + " (plain WireGuard fallback)"})
	}
	return results
}

// checkVpnctld reports whether the daemon is reachable at all — every
// vpnctl subcommand (including the bare TUI, since Phase 3 of
// DAEMON_MIGRATION.md) needs it; a clear, upfront "daemon unreachable"
// here is more useful than each of those commands separately failing to
// connect. --fix tries `systemctl start vpnctld` — the one dependency
// failure here that doesn't need installing anything, just starting what's
// already on disk, so it's safe to attempt without root-owned downloads.
func checkVpnctld() checkResult {
	if _, err := vpnctlclient.Status(); err != nil {
		return checkResult{
			name: "vpnctld",
			ok:   false,
			info: fmt.Sprintf("not reachable at %s — every vpnctl command needs it running (%v)", vpnctlclient.SocketPath(), err),
			fix: func() (string, error) {
				if _, err := exec.LookPath("systemctl"); err != nil {
					return "", fmt.Errorf("no systemctl on this system — start vpnctld manually")
				}
				out, err := exec.Command("systemctl", "start", "vpnctld").CombinedOutput()
				if err != nil {
					return "", fmt.Errorf("systemctl start vpnctld: %v: %s", err, out)
				}
				return "ran `systemctl start vpnctld`", nil
			},
		}
	}
	return checkResult{name: "vpnctld", ok: true, info: "reachable at " + vpnctlclient.SocketPath()}
}

// checkStaleWireGuardSocket flags the exact failure mode behind the A1
// prerm bug: a leftover /var/run/wireguard/vpnctl-wg.sock from an
// amneziawg-go/wg-quick process that never exited makes the next
// `awg-quick up` fail with "UAPI listen error: unix socket in use", with no
// obvious cause from that error alone. If a profile is genuinely active
// right now, the socket is expected and not a problem.
func checkStaleWireGuardSocket() checkResult {
	sockPath := "/var/run/wireguard/" + netguard.WireGuardInterface + ".sock"
	info, err := os.Lstat(sockPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return checkResult{name: "WireGuard UAPI socket", ok: true, info: "no stale socket at " + sockPath}
	}

	result, err := vpnctlclient.Status()
	if err != nil {
		// vpnctld unreachable: can't confirm either way, so this isn't
		// treated as a hard failure — see checkVpnctld for that.
		return checkResult{name: "WireGuard UAPI socket", ok: true, info: fmt.Sprintf("socket exists at %s, but vpnctld isn't reachable to confirm whether it's expected", sockPath)}
	}
	if result.Status.Active {
		return checkResult{name: "WireGuard UAPI socket", ok: true, info: sockPath + " (in use by the active profile)"}
	}
	return checkResult{
		name: "WireGuard UAPI socket",
		ok:   false,
		info: fmt.Sprintf("stale socket at %s with no active profile — a previous amneziawg-go/awg-quick process likely didn't exit; `awg-quick up` will fail with \"UAPI listen error: unix socket in use\" until it's removed (`vpnctl down`, or `rm` it by hand if that doesn't help)", sockPath),
		fix: func() (string, error) {
			// Re-confirm immediately before removing: --fix runs after the
			// initial check pass, and this file's whole point is a
			// namespace/kill-switch socket a concurrent `vpnctl use` could
			// have legitimately created in between.
			if result, err := vpnctlclient.Status(); err == nil && result.Status.Active {
				return "", fmt.Errorf("a profile is now active, socket is legitimate — not removing")
			}
			if err := os.Remove(sockPath); err != nil {
				return "", err
			}
			return "removed stale socket at " + sockPath, nil
		},
	}
}

func rootInfo() string {
	if sysuser.IsRoot() {
		if sysuser.RanViaSudo() {
			return "running as root via sudo (not required — every vpnctl command talks to vpnctld over its socket and needs no sudo of its own)"
		}
		return "running as root (not required by vpnctl itself — only vpnctld, the daemon, needs it)"
	}
	return "not root, and that's fine — every vpnctl command (including the bare TUI) talks to vpnctld over its socket and needs no sudo, only membership in the 'vpnctl' group"
}

func checkNetns() checkResult {
	if err := exec.Command("ip", "netns", "list").Run(); err != nil {
		return checkResult{name: "network namespaces", ok: false, info: fmt.Sprintf("`ip netns list` failed: %v", err)}
	}
	return checkResult{name: "network namespaces", ok: true, info: "ip netns available"}
}

func checkSysctl() checkResult {
	if _, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil {
		return checkResult{name: "sysctl net.ipv4.ip_forward", ok: false, info: err.Error()}
	}
	return checkResult{name: "sysctl net.ipv4.ip_forward", ok: true, info: "readable"}
}

func checkDirs() []checkResult {
	var out []checkResult
	if dir, err := profile.Dir(); err != nil {
		out = append(out, checkResult{name: "profiles dir", ok: false, info: err.Error()})
	} else {
		out = append(out, checkResult{name: "profiles dir", ok: true, info: dir})
	}
	if dir, err := netguard.StateDir(); err != nil {
		out = append(out, checkResult{name: "state dir", ok: false, info: err.Error()})
	} else {
		out = append(out, checkResult{name: "state dir", ok: true, info: dir})
	}
	return out
}

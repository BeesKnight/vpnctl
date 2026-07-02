package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/sysuser"
)

type checkResult struct {
	name string
	ok   bool
	info string
}

// cmdDoctor is vpnctl's brew-doctor/flutter-doctor-style self-check: every
// system dependency and permission the network layer needs, printed as a
// checklist so a failure is immediately actionable rather than surfacing as
// a confusing mid-operation error.
func cmdDoctor(args []string) error {
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
	results = append(results, checkStaleWireGuardSocket())

	results = append(results, checkResult{
		name: "root/sudo",
		ok:   sysuser.IsRoot(),
		info: rootInfo(),
	})

	results = append(results, checkNetns())
	results = append(results, checkSysctl())
	results = append(results, checkDirs()...)

	allOK := true
	for _, r := range results {
		mark := "✓"
		if !r.ok {
			mark = "✗"
			allOK = false
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
	fmt.Println("Some checks failed — see above. Run the installer again or install the missing pieces manually.")
	os.Exit(1)
	return nil
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

	active := false
	if status, err := netguard.NewLinuxEngine(false).Status(); err == nil {
		active = status.Active
	}
	if active {
		return checkResult{name: "WireGuard UAPI socket", ok: true, info: sockPath + " (in use by the active profile)"}
	}
	return checkResult{
		name: "WireGuard UAPI socket",
		ok:   false,
		info: fmt.Sprintf("stale socket at %s with no active profile — a previous amneziawg-go/awg-quick process likely didn't exit; `awg-quick up` will fail with \"UAPI listen error: unix socket in use\" until it's removed (`vpnctl down`, or `rm` it by hand if that doesn't help)", sockPath),
	}
}

func rootInfo() string {
	if sysuser.IsRoot() {
		if sysuser.RanViaSudo() {
			return "running as root via sudo"
		}
		return "running as root"
	}
	return "not root — network operations (use/down/run/test) need sudo"
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

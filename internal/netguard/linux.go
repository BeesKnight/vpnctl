//go:build linux

package netguard

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BeesKnight/vpnctl/internal/profile"
)

// Namespace is the single, fixed network namespace vpnctl ever creates. Only
// one profile is ever active at a time, so switching profiles recreates this
// namespace rather than allocating a new name per profile — that keeps
// teardown/purge trivial to reason about (there is never more than one of
// these to clean up) and matches the "atomic switch" behavior documented in
// cmdUse: switching profiles while commands are running inside the old
// namespace is refused rather than silently killing them.
const Namespace = "vpnctl0"

const (
	vethHost   = "vpnctl-h0"
	vethNS     = "vpnctl-n0"
	hostIP     = HostIP
	nsIP       = NamespaceIP
	subnetCIDR = "10.200.200.0/24"
	hostCIDR   = hostIP + "/24"
	nsCIDR     = nsIP + "/24"

	ipForwardKey = "net.ipv4.ip_forward"
	ruleComment  = "vpnctl"
)

// defaultDNSServers back a namespace's resolv.conf when the profile doesn't
// specify its own (proxy profiles, or a WireGuard config with no DNS line):
// without *some* working resolver inside the namespace, hostname-based
// commands (`vpnctl test`, `vpnctl run -- curl ...`) can't resolve anything,
// since the kill-switch means the namespace has no route to whatever
// resolver the host itself uses.
var defaultDNSServers = []string{"1.1.1.1", "8.8.8.8"}

// resolvConfDir/resolvConfPath follow the standard `/etc/netns/<name>/`
// convention iproute2 itself uses for `ip netns exec` — this is what lets
// Command's mount-namespace wrapping (see below) hand every process run
// inside the namespace its own resolvers without ever touching the host's
// /etc/resolv.conf, regardless of whether the host manages that file via
// NetworkManager, systemd-resolved, plain resolvconf, or anything else.
func resolvConfDir() string  { return "/etc/netns/" + Namespace }
func resolvConfPath() string { return resolvConfDir() + "/resolv.conf" }

// dnsServersFor picks the nameservers a profile's namespace should resolve
// through: the WireGuard/AmneziaWG config's own DNS line when present,
// falling back to defaultDNSServers otherwise (proxy profiles have no DNS
// field of their own, and a WG profile may simply omit one).
func dnsServersFor(p profile.Profile) []string {
	if p.WG != nil {
		if servers := p.WG.DNSServers(); len(servers) > 0 {
			return servers
		}
	}
	return defaultDNSServers
}

// writeNetnsResolvConf writes the namespace-scoped resolv.conf. This file
// alone doesn't do anything by itself (plain `nsenter --net=` doesn't consult
// it the way `ip netns exec` would) - Command wraps every namespace invocation
// to bind-mount it over /etc/resolv.conf inside a private mount namespace, so
// it's this file, not the host's, that every namespaced process resolves
// through.
func writeNetnsResolvConf(servers []string) error {
	if len(servers) == 0 {
		servers = defaultDNSServers
	}
	if err := os.MkdirAll(resolvConfDir(), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	for _, s := range servers {
		b.WriteString("nameserver " + s + "\n")
	}
	return os.WriteFile(resolvConfPath(), []byte(b.String()), 0o644)
}

// LinuxEngine is the Linux implementation of Engine: network namespaces,
// veth pairs, and iptables, driven entirely through the Runner seam so it
// can be exercised in dry-run mode by tests.
type LinuxEngine struct {
	runner Runner
	dryRun bool
}

// NewLinuxEngine builds the Linux Engine. When dryRun is true (or
// VPNCTL_DRY_RUN=1 is set), no command actually executes — every ip/iptables
// invocation is only recorded, retrievable via Recorded() — and no real
// filesystem changes are made outside of state under $HOME either (see
// writeNetnsResolvConf).
func NewLinuxEngine(dryRun bool) *LinuxEngine {
	dryRun = dryRun || os.Getenv("VPNCTL_DRY_RUN") == "1"
	return &LinuxEngine{runner: NewRunner(dryRun), dryRun: dryRun}
}

func (e *LinuxEngine) Recorded() []string { return e.runner.Recorded() }

// Setup implements Engine.
func (e *LinuxEngine) Setup(p profile.Profile) (Status, error) {
	if p.Server == "" {
		return Status{}, fmt.Errorf("profile %q has no server endpoint", p.Name)
	}
	if p.Port == 0 {
		return Status{}, fmt.Errorf("profile %q has no server port", p.Name)
	}

	resolvedIP, err := resolveIP(p.Server)
	if err != nil {
		return Status{}, fmt.Errorf("resolving server for profile %q: %w", p.Name, err)
	}
	proto := protocolFor(p.Kind)

	// Idempotent clean slate: never layer a new namespace/ruleset on top of
	// a previous one. If a prior Setup died halfway through, this clears it.
	if err := e.teardownNetwork(); err != nil {
		return Status{}, fmt.Errorf("clearing previous namespace: %w", err)
	}

	if err := e.ensureIPForward(); err != nil {
		return Status{}, fmt.Errorf("enabling ip_forward: %w", err)
	}

	if err := e.createNamespace(); err != nil {
		_ = e.teardownNetwork()
		return Status{}, fmt.Errorf("creating namespace: %w", err)
	}

	if !e.dryRun {
		if err := writeNetnsResolvConf(dnsServersFor(p)); err != nil {
			_ = e.teardownNetwork()
			return Status{}, fmt.Errorf("writing namespace resolv.conf: %w", err)
		}
	}

	if err := e.lockdownNamespace(resolvedIP, p.Port, proto); err != nil {
		_ = e.teardownNetwork()
		return Status{}, fmt.Errorf("applying kill-switch: %w", err)
	}

	if err := e.allowHostForwarding(resolvedIP, p.Port, proto); err != nil {
		_ = e.teardownNetwork()
		return Status{}, fmt.Errorf("configuring host NAT: %w", err)
	}

	status := Status{
		Active:        true,
		ProfileName:   p.Name,
		ProfileKind:   string(p.Kind),
		Namespace:     Namespace,
		KillSwitch:    true,
		ResolvedIP:    resolvedIP,
		ResolvedPort:  p.Port,
		Protocol:      proto,
		Since:         time.Now(),
		EngineHealthy: false, // the awg-quick/sing-box process isn't started yet
	}

	state := &ActiveState{
		ProfileName:  p.Name,
		ProfileKind:  string(p.Kind),
		Namespace:    Namespace,
		ResolvedIP:   resolvedIP,
		ResolvedPort: p.Port,
		Protocol:     proto,
		Since:        status.Since,
	}
	if err := SaveActiveState(state); err != nil {
		return Status{}, fmt.Errorf("saving state: %w", err)
	}

	return status, nil
}

func (e *LinuxEngine) createNamespace() error {
	if err := e.runner.Run("ip", "netns", "add", Namespace); err != nil {
		return err
	}
	if err := e.runner.Run("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS); err != nil {
		return err
	}
	if err := e.runner.Run("ip", "link", "set", vethNS, "netns", Namespace); err != nil {
		return err
	}
	if err := e.runner.Run("ip", "addr", "add", hostCIDR, "dev", vethHost); err != nil {
		return err
	}
	if err := e.runner.Run("ip", "link", "set", vethHost, "up"); err != nil {
		return err
	}
	if err := e.nsExecRun("ip", "addr", "add", nsCIDR, "dev", vethNS); err != nil {
		return err
	}
	if err := e.nsExecRun("ip", "link", "set", vethNS, "up"); err != nil {
		return err
	}
	if err := e.nsExecRun("ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	if err := e.nsExecRun("ip", "route", "add", "default", "via", hostIP); err != nil {
		return err
	}
	return nil
}

// lockdownNamespace applies the default-DROP kill-switch inside the
// namespace, with a single point-to-point ACCEPT for the profile's resolved
// server IP:port — this is the fail-closed guarantee from spec §5: nothing
// else can ever leave the namespace, on purpose or by engine failure.
func (e *LinuxEngine) lockdownNamespace(serverIP string, port int, proto string) error {
	run := func(args ...string) error { return e.nsExecRun("iptables", args...) }

	if err := run("-F"); err != nil {
		return err
	}
	if err := run("-P", "INPUT", "DROP"); err != nil {
		return err
	}
	if err := run("-P", "OUTPUT", "DROP"); err != nil {
		return err
	}
	if err := run("-P", "FORWARD", "DROP"); err != nil {
		return err
	}
	if err := run("-A", "INPUT", "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := run("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := run("-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := run("-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	portStr := strconv.Itoa(port)
	if err := run("-A", "OUTPUT", "-p", proto, "-d", serverIP, "--dport", portStr, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := run("-A", "INPUT", "-p", proto, "-s", serverIP, "--sport", portStr, "-j", "ACCEPT"); err != nil {
		return err
	}
	return nil
}

// allowHostForwarding permits the host to route+NAT only the profile's
// resolved server IP:port from the namespace's subnet — a point allow, never
// a general "forward everything from this namespace" rule. Rules are
// inserted (not appended) so they take priority ahead of any pre-existing
// restrictive host firewall rules, and tagged with a comment so teardown can
// remove exactly these rules and nothing else the host admin configured.
func (e *LinuxEngine) allowHostForwarding(serverIP string, port int, proto string) error {
	portStr := strconv.Itoa(port)
	tag := []string{"-m", "comment", "--comment", ruleComment}

	fwdOut := append([]string{"-I", "FORWARD", "1", "-s", subnetCIDR, "-d", serverIP,
		"-p", proto, "--dport", portStr, "-j", "ACCEPT"}, tag...)
	if err := e.hostIptables(fwdOut...); err != nil {
		return err
	}

	fwdIn := append([]string{"-I", "FORWARD", "1", "-d", subnetCIDR, "-s", serverIP,
		"-p", proto, "--sport", portStr, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}, tag...)
	if err := e.hostIptables(fwdIn...); err != nil {
		return err
	}

	nat := append([]string{"-t", "nat", "-A", "POSTROUTING", "-s", subnetCIDR, "-d", serverIP, "-j", "MASQUERADE"}, tag...)
	return e.hostIptables(nat...)
}

// removeHostForwarding deletes exactly the host rules Setup added for the
// given server IP/port, leaving any other iptables configuration on the
// host untouched. Matches by re-issuing the identical rule with -D.
func (e *LinuxEngine) removeHostForwarding(serverIP string, port int, proto string) error {
	if serverIP == "" {
		return nil
	}
	portStr := strconv.Itoa(port)
	tag := []string{"-m", "comment", "--comment", ruleComment}

	_ = e.hostIptables(append([]string{"-D", "FORWARD", "-s", subnetCIDR, "-d", serverIP,
		"-p", proto, "--dport", portStr, "-j", "ACCEPT"}, tag...)...)
	_ = e.hostIptables(append([]string{"-D", "FORWARD", "-d", subnetCIDR, "-s", serverIP,
		"-p", proto, "--sport", portStr, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}, tag...)...)
	_ = e.hostIptables(append([]string{"-t", "nat", "-D", "POSTROUTING", "-s", subnetCIDR, "-d", serverIP, "-j", "MASQUERADE"}, tag...)...)
	return nil
}

func (e *LinuxEngine) hostIptables(args ...string) error {
	return e.runner.Run("iptables", args...)
}

// Teardown implements Engine.
func (e *LinuxEngine) Teardown() error {
	state, _ := LoadActiveState()

	if state != nil {
		killTrackedProcesses(state)
		_ = e.removeHostForwarding(state.ResolvedIP, state.ResolvedPort, state.Protocol)
	}

	if err := e.teardownNetwork(); err != nil {
		return err
	}

	if err := e.restoreIPForward(); err != nil {
		return fmt.Errorf("restoring ip_forward: %w", err)
	}

	return ClearActiveState()
}

// teardownNetwork removes the namespace and veth pair. Idempotent: missing
// resources are not an error, since Setup calls this unconditionally first.
func (e *LinuxEngine) teardownNetwork() error {
	exists, err := e.namespaceExists()
	if err != nil {
		return err
	}
	if exists {
		if err := e.runner.Run("ip", "netns", "del", Namespace); err != nil {
			return err
		}
	}
	// Deleting the namespace also deletes the ns-side veth end (and, since
	// veth interfaces are paired, the host-side end with it). This is a
	// belt-and-suspenders cleanup in case the host-side end lingered.
	_ = e.runner.Run("ip", "link", "del", vethHost)
	if !e.dryRun {
		_ = os.RemoveAll(resolvConfDir())
	}
	return nil
}

func (e *LinuxEngine) namespaceExists() (bool, error) {
	out, err := e.runner.Output("ip", "netns", "list")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == Namespace {
			return true, nil
		}
	}
	return false, nil
}

// Status implements Engine.
func (e *LinuxEngine) Status() (Status, error) {
	exists, err := e.namespaceExists()
	if err != nil {
		return Status{}, err
	}
	state, err := LoadActiveState()
	if err != nil {
		return Status{}, err
	}
	if !exists || state == nil {
		return Status{Active: false}, nil
	}

	healthy := state.EnginePID != 0 && processAlive(state.EnginePID)

	return Status{
		Active:        true,
		ProfileName:   state.ProfileName,
		ProfileKind:   state.ProfileKind,
		Namespace:     state.Namespace,
		KillSwitch:    true,
		ResolvedIP:    state.ResolvedIP,
		ResolvedPort:  state.ResolvedPort,
		Protocol:      state.Protocol,
		Since:         state.Since,
		EngineHealthy: healthy,
	}, nil
}

// UpdateEndpoint implements Engine. Called periodically by the health-check
// (spec §3.3) to re-resolve the server hostname and, if it changed, swap the
// point-to-point ACCEPT/NAT rules in place without ever dropping the
// kill-switch or tearing down the namespace.
func (e *LinuxEngine) UpdateEndpoint(p profile.Profile) (bool, string, error) {
	state, err := LoadActiveState()
	if err != nil {
		return false, "", err
	}
	if state == nil {
		return false, "", fmt.Errorf("no active profile")
	}

	newIP, err := resolveIP(p.Server)
	if err != nil {
		return false, "", fmt.Errorf("resolving server: %w", err)
	}
	if newIP == state.ResolvedIP {
		return false, state.ResolvedIP, nil
	}

	proto := protocolFor(p.Kind)

	// Remove the old point-to-point rules (both namespace and host) before
	// installing new ones — never have both old and new open at once for
	// longer than this call, and never have neither open (fail-closed means
	// a health-check race must err on "namespace still locked", not "briefly
	// wide open").
	_ = e.nsExecRun("iptables", "-D", "OUTPUT", "-p", proto, "-d", state.ResolvedIP, "--dport", strconv.Itoa(state.ResolvedPort), "-j", "ACCEPT")
	_ = e.nsExecRun("iptables", "-D", "INPUT", "-p", proto, "-s", state.ResolvedIP, "--sport", strconv.Itoa(state.ResolvedPort), "-j", "ACCEPT")
	if err := e.removeHostForwarding(state.ResolvedIP, state.ResolvedPort, proto); err != nil {
		return false, "", err
	}

	if err := e.nsExecRun("iptables", "-A", "OUTPUT", "-p", proto, "-d", newIP, "--dport", strconv.Itoa(p.Port), "-j", "ACCEPT"); err != nil {
		return false, "", err
	}
	if err := e.nsExecRun("iptables", "-A", "INPUT", "-p", proto, "-s", newIP, "--sport", strconv.Itoa(p.Port), "-j", "ACCEPT"); err != nil {
		return false, "", err
	}
	if err := e.allowHostForwarding(newIP, p.Port, proto); err != nil {
		return false, "", err
	}

	state.ResolvedIP = newIP
	state.ResolvedPort = p.Port
	state.Protocol = proto
	if err := SaveActiveState(state); err != nil {
		return false, "", err
	}
	return true, newIP, nil
}

// netnsPath is where `ip netns add` creates the bind-mounted namespace
// handle, which nsenter needs to join it.
func netnsPath() string { return "/var/run/netns/" + Namespace }

// dnsShimScript runs inside a private, per-invocation mount namespace (see
// Command) as root, before any privilege drop: it bind-mounts the
// namespace's own resolv.conf over /etc/resolv.conf — scoped to this one
// process tree only, thanks to --propagation private, so it can never leak
// back to the host's real /etc/resolv.conf no matter what manages that file
// there (NetworkManager, systemd-resolved, plain resolvconf, ...) — then
// drops to the requested uid/gid (if any) and execs the real target,
// replacing itself so the PID Go already captured keeps pointing at the
// right process throughout every exec() in this chain.
const dnsShimScript = `r="$1"; u="$2"; g="$3"; shift 3
if ! mount --bind "$r" /etc/resolv.conf 2>/dev/null; then
	echo "vpnctl: could not mount namespace resolv.conf" >&2
	exit 125
fi
if [ -n "$u" ]; then
	exec setpriv --reuid "$u" --regid "$g" --clear-groups -- "$@"
fi
exec "$@"`

// Command implements Engine. Refuses to build a command unless the
// namespace actually exists — there is no fallback path that could run a
// command in the host's default (unrestricted) namespace by mistake.
//
// Uses nsenter rather than `ip netns exec`: nsenter setns()s and then
// execve()s the target directly, replacing itself, so the PID Go sees via
// cmd.Process.Pid *is* the target process's real PID. `ip netns exec` forks
// and keeps running as a supervising parent instead, which would leave our
// PID-based health-check/stop/ps/kill tracking pointed at the wrong process.
//
// Every invocation is additionally wrapped in `unshare --mount --propagation
// private` plus a small shell shim (dnsShimScript) that bind-mounts this
// namespace's own resolv.conf over /etc/resolv.conf before exec'ing the real
// target — plain nsenter --net= doesn't get iproute2's /etc/netns/<name>/
// auto-mount behavior the way `ip netns exec` does, so this replicates it by
// hand. The uid/gid drop (opts.DropToUID/GID) happens inside the shim via
// setpriv, *after* the bind-mount, rather than via nsenter's own
// --setuid/--setgid: creating a mount namespace requires CAP_SYS_ADMIN, which
// a dropped-to-uid process wouldn't have anymore.
func (e *LinuxEngine) Command(name string, args []string, opts ExecOptions) (*exec.Cmd, error) {
	exists, err := e.namespaceExists()
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no active profile: namespace %q does not exist", Namespace)
	}

	uidStr, gidStr := "", ""
	if opts.DropToUID != nil {
		uidStr = strconv.Itoa(*opts.DropToUID)
	}
	if opts.DropToGID != nil {
		gidStr = strconv.Itoa(*opts.DropToGID)
	}

	shimArgs := append([]string{"sh", "-c", dnsShimScript, "sh", resolvConfPath(), uidStr, gidStr, name}, args...)

	nsenterArgs := []string{"--net=" + netnsPath(), "--", "unshare", "--mount", "--propagation", "private", "--"}
	nsenterArgs = append(nsenterArgs, shimArgs...)

	cmd := exec.Command("nsenter", nsenterArgs...)
	cmd.Env = append(os.Environ(), opts.Env...)
	if opts.Dir != "" {
		cmd.Dir = opts.Dir
	}
	return cmd, nil
}

// nsExecRun runs a command inside the namespace via the runner, for
// netguard's own internal setup steps (as opposed to Command, which hands an
// unstarted *exec.Cmd to callers outside this package). Uses the same
// nsenter mechanism as Command for consistency.
func (e *LinuxEngine) nsExecRun(name string, args ...string) error {
	full := append([]string{"--net=" + netnsPath(), "--", name}, args...)
	return e.runner.Run("nsenter", full...)
}

func (e *LinuxEngine) ensureIPForward() error {
	backup, err := LoadSysctlBackup()
	if err != nil {
		return err
	}
	if _, known := backup.Values[ipForwardKey]; !known {
		current, err := e.runner.Output("sysctl", "-n", ipForwardKey)
		if err != nil {
			return err
		}
		backup.Values[ipForwardKey] = strings.TrimSpace(current)
		if err := SaveSysctlBackup(backup); err != nil {
			return err
		}
	}
	return e.runner.Run("sysctl", "-w", ipForwardKey+"=1")
}

func (e *LinuxEngine) restoreIPForward() error {
	backup, err := LoadSysctlBackup()
	if err != nil {
		return err
	}
	orig, known := backup.Values[ipForwardKey]
	if !known {
		return nil
	}
	return e.runner.Run("sysctl", "-w", ipForwardKey+"="+orig)
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// killTrackedProcesses terminates every process vpnctl launched through the
// active profile (engine + run/tui/gui children) before the namespace they
// depend on disappears. Kills by tracked PID only, never by process name, so
// an unrelated sing-box the user runs independently is never touched.
func killTrackedProcesses(state *ActiveState) {
	pids := make([]int, 0, len(state.Processes)+2)
	if state.EnginePID != 0 {
		pids = append(pids, state.EnginePID)
	}
	if state.HealthPID != 0 {
		pids = append(pids, state.HealthPID)
	}
	for _, p := range state.Processes {
		pids = append(pids, p.PID)
	}
	for _, pid := range pids {
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		_ = proc.Signal(syscall.SIGTERM)
	}
	if len(pids) == 0 {
		return
	}
	time.Sleep(300 * time.Millisecond)
	for _, pid := range pids {
		if processAlive(pid) {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Signal(syscall.SIGKILL)
			}
		}
	}
}

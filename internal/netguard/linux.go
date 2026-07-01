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

// LinuxEngine is the Linux implementation of Engine: network namespaces,
// veth pairs, and iptables, driven entirely through the Runner seam so it
// can be exercised in dry-run mode by tests.
type LinuxEngine struct {
	runner Runner
}

// NewLinuxEngine builds the Linux Engine. When dryRun is true (or
// VPNCTL_DRY_RUN=1 is set), no command actually executes — every ip/iptables
// invocation is only recorded, retrievable via Recorded().
func NewLinuxEngine(dryRun bool) *LinuxEngine {
	return &LinuxEngine{runner: NewRunner(dryRun)}
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

// Command implements Engine. Refuses to build a command unless the
// namespace actually exists — there is no fallback path that could run a
// command in the host's default (unrestricted) namespace by mistake.
//
// Uses nsenter rather than `ip netns exec`: nsenter setns()s and then
// execve()s the target directly, replacing itself, so the PID Go sees via
// cmd.Process.Pid *is* the target process's real PID. `ip netns exec` forks
// and keeps running as a supervising parent instead, which would leave our
// PID-based health-check/stop/ps/kill tracking pointed at the wrong process.
func (e *LinuxEngine) Command(name string, args []string, opts ExecOptions) (*exec.Cmd, error) {
	exists, err := e.namespaceExists()
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no active profile: namespace %q does not exist", Namespace)
	}

	nsenterArgs := []string{"--net=" + netnsPath()}
	if opts.DropToUID != nil {
		nsenterArgs = append(nsenterArgs, fmt.Sprintf("--setuid=%d", *opts.DropToUID))
	}
	if opts.DropToGID != nil {
		nsenterArgs = append(nsenterArgs, fmt.Sprintf("--setgid=%d", *opts.DropToGID))
	}
	nsenterArgs = append(nsenterArgs, "--", name)
	nsenterArgs = append(nsenterArgs, args...)

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

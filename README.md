# vpnctl

Interactive TUI/CLI for switching between WireGuard/AmneziaWG and
VLESS/Hysteria2 VPN/proxy profiles on a Kali (or any Debian-based), with a **kernel-level kill-switch** (network namespace + default-DROP
iptables policy, never a library/hook-based one) and a **launcher** for
running GUI, CLI, and TUI programs through whichever profile is active,
guaranteed with no path to a direct/leaked connection.

```
┌─ vpnctl ───────────────────────────────────────────────────────────┐
│ PROFILES                          │ STATUS                         │
│ [WG/AmneziaWG]                    │ Active: switz (AmneziaWG)      │
│ > switz               ●active     │ State:  UP                     │
│   germany-01                      │ Server: 185.x.x.x:51820/udp    │
│ [VLESS]                           │                                │
│   nl02-mk01                       │ LOGS                           │
│ [Hysteria2]                       │ [awg-quick] handshake ok       │
│   kz03-hy01                       │                                │
├───────────────────────────────────┼────────────────────────────────┤
│ APPS                              │RUNNING (through active profile)│
│ > Firefox            [gui]        │ firefox      pid 4821  12m up  │
│   htop                [tui]       │                                │
└────────────────────────────────────────────────────────────────────┘
 ↑/k ↓/j navigate  enter activate/launch  tab switch panel
 t test  r run  i import  a apps  p processes  e edit  d down  ? help  q quit
```

## Why

Most VPN/proxy client tools are "connect, and there's also a way to run
things through it." vpnctl inverts that: it is first and foremost a
**launcher**. You pick an active profile, and every program you start
through vpnctl — Burp Suite, Firefox, `curl`, `nmap`, `msfconsole`, anything
— is guaranteed to go through the tunnel, because it never has a route
anywhere else. The isolation is enforced by the kernel (a dedicated network
namespace with a default-DROP `iptables` policy and a single point-to-point
`ACCEPT` rule for the resolved VPN/proxy server), not by an application-level
proxy setting an app might ignore.

## Requirements

- Linux with network namespace support (`ip netns`), root/`sudo` for every
  network-affecting command.
- `iproute2` (`ip`), `util-linux` (`nsenter`, `unshare`, `setpriv`),
  `iptables`, `jq`, `curl`.
- `awg-quick` and `awg` (from `amneziawg-tools`) plus `amneziawg-go` for
  AmneziaWG profiles.
- `xray` (Xray-core) and `tun2socks` for VLESS profiles — Xray-core is VLESS's
  reference implementation and supports every transport in the wild
  (`xhttp`/`ws`/`grpc`/`http`/`tcp`/`kcp`), including `xhttp`, which the
  official `sing-box` build doesn't ship. Xray-core has no native TUN
  inbound, so `tun2socks` turns its local SOCKS5 inbound into the same kind
  of transparent `vpnctl-tun` device sing-box's own TUN inbound provides.
- `sing-box` for Hysteria2 profiles (Xray-core has no Hysteria2 support).

`vpnctl doctor` checks all of the above and tells you exactly what's
missing.

## Install

### Option A — `.deb` package (recommended on Kali/Debian)

```bash
sudo apt install ./vpnctl_1.0.4_amd64.deb
```

Use `apt install ./...`, not `dpkg -i`: apt resolves the package's ordinary
Debian/Kali dependencies before `postinst` runs. `postinst` never calls
`apt-get` itself; it only handles upstream components that are usually not in
the base repos (`sing-box`, `xray`, `tun2socks`, `amneziawg-tools`,
`amneziawg-go`) by downloading a matching GitHub release asset where
possible, then falling back to the official source builds for AmneziaWG.
Nothing is interactive; any failure is printed,
not blocked on a debconf prompt. Run `vpnctl doctor` afterwards to confirm
everything landed.

Removing the package is symmetric:

```bash
sudo apt remove vpnctl    # tears down any active profile, clears runtime
                          # state, leaves your profiles in ~/.config/vpnctl
sudo apt purge vpnctl     # also deletes ~/.config/vpnctl, and removes any
                          # of sing-box/xray/tun2socks/amneziawg-tools that
                          # vpnctl itself installed (never ones you already had)
```

### Option B — `install.sh`

```bash
curl -fsSL https://raw.githubusercontent.com/BeesKnight/vpnctl/main/packaging/install.sh | sudo bash
```

Same dependency install logic as the `.deb`, plus it fetches the `vpnctl`
binary itself from GitHub Releases (falling back to `go build` from source if
no release exists yet) and drops it at `/usr/local/bin/vpnctl`.

### Building from source

```bash
git clone https://github.com/BeesKnight/vpnctl
cd vpnctl
go build -o vpnctl ./cmd/vpnctl
sudo install -m 0755 vpnctl /usr/local/bin/vpnctl
```

## First run

```bash
vpnctl doctor          # confirm dependencies/permissions are all in order
vpnctl list            # nothing yet — profiles live in ~/.config/vpnctl/profiles/{wg,proxy}
```

Import something:

```bash
# a WireGuard/AmneziaWG .conf you already have
vpnctl import --wg ~/Downloads/switz.conf

# a base64 subscription link (vless://, hysteria2:// entries, one per line)
vpnctl import --sub 'https://example.com/api/sub/xxxxx'
```

Then either open the TUI (just `vpnctl`, needs `sudo`) and press `enter` on
a profile, or do it all non-interactively:

```bash
sudo vpnctl use switz
sudo vpnctl test                       # curl an IP-echo service through it
sudo vpnctl run -- curl https://example.com   # blocking, streamed, exit code preserved
sudo vpnctl run --gui -- firefox              # detached GUI, vpnctl keeps running
sudo vpnctl run --tui -- htop                 # full terminal takeover, returns to caller on exit
sudo vpnctl ps                          # what's running through the active profile
sudo vpnctl kill <pid|name>
sudo vpnctl down
```

Closing the TUI (`q`) does **not** tear down the active profile — the
namespace, the engine (`awg-quick`/`sing-box`/`xray`+`tun2socks`), and the
health-check daemon all run detached from the TUI/CLI process that started them, so the tunnel
survives across separate `vpnctl` invocations. `vpnctl status` (or
reopening the TUI) picks the current state back up from
`~/.local/state/vpnctl/active.json`.

## The apps registry

`~/.config/vpnctl/apps.yaml` (created with a small example on first run)
lets the Apps panel launch a pre-configured program with the right mode
already known, instead of you typing a command and remembering `--gui`/
`--tui` every time:

```yaml
apps:
  - name: Firefox
    type: gui
    command: ["firefox"]
  - name: htop
    type: tui
    command: ["htop"]
  - name: nmap scan
    type: cli
    command: ["nmap", "-sV"]
```

## Design notes / known limitations

- **All profile families are transparent tunnels.** WireGuard/AmneziaWG uses
  its kernel/userspace WireGuard interface; Hysteria2 uses sing-box's native
  TUN inbound; VLESS uses Xray-core paired with tun2socks (Xray-core has no
  native TUN inbound of its own). All three end up as the same `vpnctl-tun`
  device from the kill-switch's point of view. Programs launched through
  `vpnctl run` or the Apps panel do not need SOCKS5/HTTP proxy settings. If
  the tunnel engine is down, the namespace's default-DROP kill-switch leaves them with no route
  rather than a direct connection.
- **Switching profiles while something is running is refused, not forced.**
  If `vpnctl ps` shows tracked processes, `vpnctl use <other>` errors out
  instead of silently killing them — stop them with `vpnctl kill` first.
- **Health-check re-resolve** runs as its own detached daemon (30s interval
  by default, `$VPNCTL_HEALTHCHECK_INTERVAL` in seconds to override), so a
  VPN server's hostname changing IP doesn't require the TUI to be open to
  notice and update the firewall rule.
- **Process tracking covers GUI/detached launches** (`run --gui`, Apps panel
  GUI entries) precisely, by PID. Foreground terminal-takeover launches
  (`run`, `run --tui`, Apps panel cli/tui entries, the Run screen) aren't
  listed in `vpnctl ps` — they block the TUI/terminal until they exit, so
  there's nothing to track concurrently.
- **Windows is out of scope for this iteration**, but the seam is already
  there: every `ip`/`iptables`/`nsenter` call lives behind the `netguard.Engine`
  interface in `internal/netguard`, implemented only by the Linux-tagged
  `linux.go`. A `windows.go` (WFP or WinTUN + `netsh advfirewall`) would be
  the only new file needed.

## Project layout

```
vpnctl/
├── cmd/vpnctl/          # CLI dispatch + TUI entry point
├── internal/
│   ├── actions/         # shared CLI/TUI operations (activate, test, ps/kill, ...)
│   ├── apps/            # apps.yaml registry
│   ├── engine/          # awg-quick / sing-box / xray+tun2socks process management
│   ├── healthcheck/      # detached re-resolve daemon
│   ├── importer/        # subscription + WireGuard config import
│   ├── netguard/         # netns + iptables kill-switch (the only place that
│   │                      touches `ip`/`iptables`/`nsenter`)
│   ├── profile/          # profile file parsing/loading
│   ├── run/              # CLI/TUI/GUI launch modes
│   ├── sysuser/          # real-user resolution under sudo
│   └── tui/              # bubbletea UI
├── packaging/
│   ├── nfpm.yaml
│   ├── postinst / prerm / postrm
│   └── install.sh
└── go.mod
```

## Testing

```bash
go test ./...
```

Unit tests cover the subscription URI parsers (`vless://`, `hysteria2://`),
WireGuard/AmneziaWG config parsing (including the `Jc`/`Jmin`/`Jmax`/
`S1`-`S4`/`H1`-`H4` obfuscation fields), and the kill-switch's iptables rule
generation in dry-run mode (`netguard.NewLinuxEngine(true)` — records every
`ip`/`iptables` invocation it would have made instead of running it).

Actually creating network namespaces, running `awg-quick`/`sing-box`/
`xray`+`tun2socks`, and the full install/purge cycle need root and a real
Linux network stack —
exercise those on the target Kali machine itself, not in a locked-down
container/CI sandbox without `CAP_SYS_ADMIN`.

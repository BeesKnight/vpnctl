#!/bin/bash
# vpnctl install.sh — the zero-friction MVP installer,
# the alternative to `dpkg -i vpnctl_*.deb` for machines that just want:
#
#   curl -fsSL https://raw.githubusercontent.com/BeesKnight/vpnctl/main/packaging/install.sh | sudo bash
#
# Downloads the vpnctl binary from GitHub Releases, installs it to
# /usr/local/bin/vpnctl, and does the same dependency install the .deb's
# postinst does (iproute2/iptables/jq/toolchain via apt, sing-box/Xray-core/
# tun2socks/AmneziaWG userspace from GitHub release assets or source) —
# fully non-interactively, same as postinst. Also builds and installs the
# vpnctld daemon + its systemd unit and sets up the "vpnctl" group, since
# vpnctl itself is just a thin client now (see DAEMON_MIGRATION.md) and is
# useless without a running daemon to talk to — this script used to stop at
# installing the vpnctl binary alone, which left every command failing with
# "vpnctld not reachable" the moment you tried to use it.
set -euo pipefail

REPO="BeesKnight/vpnctl"
BIN_DIR="/usr/local/bin"

log() { echo "vpnctl install.sh: $*"; }
die() { echo "vpnctl install.sh: ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must be run as root (sudo bash install.sh)"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) GOARCH="amd64" ;;
  aarch64) GOARCH="arm64" ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

# --- 1. vpnctl itself: latest GitHub release, falling back to building
# from source if no release asset exists yet (e.g. before the first tag) ---
install_vpnctl() {
  log "looking for the latest vpnctl release for linux/$GOARCH..."
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4 || true)"

  if [ -n "${TAG:-}" ]; then
    URL="https://github.com/${REPO}/releases/download/${TAG}/vpnctl_${TAG#v}_linux_${GOARCH}"
    TMP="$(mktemp)"
    if curl -fsSL "$URL" -o "$TMP" 2>/dev/null; then
      install -m 0755 "$TMP" "$BIN_DIR/vpnctl"
      rm -f "$TMP"
      log "installed vpnctl $TAG to $BIN_DIR/vpnctl"
      return 0
    fi
    log "no release binary at $URL, falling back to building from source"
  else
    log "no GitHub release found yet, falling back to building from source"
  fi

  if ! command -v go >/dev/null 2>&1; then
    die "no release binary available and 'go' isn't installed to build from source — install Go or wait for a release"
  fi
  if ! command -v git >/dev/null 2>&1; then
    die "no release binary available and 'git' isn't installed to build from source"
  fi

  TMP_SRC="$(mktemp -d)"
  git clone --depth 1 "https://github.com/${REPO}" "$TMP_SRC/vpnctl" || die "could not clone ${REPO}"
  ( cd "$TMP_SRC/vpnctl" && go build -o "$BIN_DIR/vpnctl" ./cmd/vpnctl ) || die "build failed"
  rm -rf "$TMP_SRC"
  log "built vpnctl from source and installed to $BIN_DIR/vpnctl"
}

# --- 2. ordinary apt dependencies/toolchain ---
install_apt_deps() {
  if ! command -v apt-get >/dev/null 2>&1; then
    log "WARNING: no apt-get found — install iproute2, iptables, jq, curl, git, go, make, gcc, and util-linux manually for your distro"
    return 0
  fi
  MISSING=""
  command -v ip >/dev/null 2>&1 || MISSING="$MISSING iproute2"
  command -v iptables >/dev/null 2>&1 || MISSING="$MISSING iptables"
  command -v jq >/dev/null 2>&1 || MISSING="$MISSING jq"
  command -v curl >/dev/null 2>&1 || MISSING="$MISSING curl"
  command -v nsenter >/dev/null 2>&1 || MISSING="$MISSING util-linux"
  command -v unshare >/dev/null 2>&1 || MISSING="$MISSING util-linux"
  command -v setpriv >/dev/null 2>&1 || MISSING="$MISSING util-linux"
  command -v git >/dev/null 2>&1 || MISSING="$MISSING git"
  command -v go >/dev/null 2>&1 || MISSING="$MISSING golang-go"
  command -v make >/dev/null 2>&1 || MISSING="$MISSING make"
  command -v gcc >/dev/null 2>&1 || MISSING="$MISSING gcc"
  if [ -n "$MISSING" ]; then
    log "installing missing packages:$MISSING"
    apt-get update -qq || true
    apt-get install -y $MISSING || log "WARNING: apt-get install failed for:$MISSING — install manually"
  fi
}

# --- 3. GitHub release asset helper ---

# RELEASE_CACHE_DIR/release_json/verify_checksum: see packaging/postinst's
# identical implementation for the full rationale — every binary installed
# from here ends up root-owned and later invoked as root (via nsenter,
# inside the kill-switch namespace), so a compromised release asset or an
# on-path MITM should be caught rather than installed silently. Kept in
# sync with postinst by hand since these are two independent maintainer
# scripts, not a shared library.
RELEASE_CACHE_DIR="$(mktemp -d)"
trap 'rm -rf "$RELEASE_CACHE_DIR"' EXIT

release_json() {
  repo="$1"
  cache_file="$RELEASE_CACHE_DIR/$(printf '%s' "$repo" | tr '/' '_').json"
  if [ ! -s "$cache_file" ]; then
    curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" -o "$cache_file" 2>/dev/null || true
  fi
  [ -s "$cache_file" ] || return 1
  printf '%s' "$cache_file"
}

latest_release_urls() {
  repo="$1"
  cf="$(release_json "$repo")" || return 1
  jq -r '.assets[]?.browser_download_url' "$cf" 2>/dev/null
}

asset_matches() {
  url_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  bin_lc="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
  case "$url_lc" in
    *"$bin_lc"*linux*"$GOARCH"*|*linux*"$GOARCH"*"$bin_lc"*|*"$bin_lc"*"$GOARCH"*linux*|*"$GOARCH"*linux*"$bin_lc"*) return 0 ;;
    *) return 1 ;;
  esac
}

verify_checksum() {
  repo="$1"
  asset_filename="$2"
  asset_path="$3"

  cf="$(release_json "$repo")" || {
    log "WARNING: could not verify checksum for $asset_filename (release metadata unavailable) — installing unverified"
    return 0
  }

  # Prefer a checksums file scoped to exactly this asset (Xray-core's
  # convention: one "<asset>.dgst" per platform binary in the same
  # release) before falling back to a single release-wide checksums file
  # (sing-box/GoReleaser convention) — see packaging/postinst's identical
  # code for the full "why" (grabbing the first same-shaped filename
  # regardless of platform would compare against an unrelated hash).
  checksums_url=""
  while IFS= read -r candidate; do
    case "$(basename "$candidate")" in
      "$asset_filename.dgst"|"$asset_filename.sha256"|"$asset_filename.sha256sum")
        checksums_url="$candidate"
        break
        ;;
    esac
  done <<EOF
$(jq -r '.assets[]?.browser_download_url' "$cf" 2>/dev/null)
EOF

  if [ -z "$checksums_url" ]; then
    while IFS= read -r candidate; do
      case "$(basename "$candidate" | tr '[:upper:]' '[:lower:]')" in
        *checksums*|*sha256sum*|sha256sums*)
          checksums_url="$candidate"
          break
          ;;
      esac
    done <<EOF
$(jq -r '.assets[]?.browser_download_url' "$cf" 2>/dev/null)
EOF
  fi

  if [ -z "$checksums_url" ]; then
    log "WARNING: $repo does not publish a checksums file for this release — installing $asset_filename unverified"
    return 0
  fi

  tmp_sums="$(mktemp)"
  if ! curl -fsSL "$checksums_url" -o "$tmp_sums" 2>/dev/null; then
    log "WARNING: could not download checksums file for $asset_filename — installing unverified"
    rm -f "$tmp_sums"
    return 0
  fi

  actual="$(sha256sum "$asset_path" 2>/dev/null | awk '{print $1}')"
  expected="$(grep -iF "$asset_filename" "$tmp_sums" 2>/dev/null | grep -oE '[0-9a-fA-F]{64}' | head -1)"
  if [ -z "$expected" ]; then
    expected="$(grep -oE '[0-9a-fA-F]{64}' "$tmp_sums" 2>/dev/null | head -1)"
  fi
  rm -f "$tmp_sums"

  if [ -z "$expected" ]; then
    log "WARNING: checksums file for $asset_filename didn't contain a recognizable sha256 — installing unverified"
    return 0
  fi

  actual_lc="$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')"
  expected_lc="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
  if [ "$actual_lc" != "$expected_lc" ]; then
    log "ERROR: checksum mismatch for $asset_filename (expected $expected_lc, got $actual_lc) — refusing to install a possibly corrupted or tampered download"
    return 1
  fi
  log "checksum verified for $asset_filename"
  return 0
}

install_binary_from_release() {
  repo="$1"
  binary="$2"
  dest="$3"
  urls="$(latest_release_urls "$repo" || true)"
  url=""
  while IFS= read -r candidate; do
    if asset_matches "$candidate" "$binary"; then
      url="$candidate"
      break
    fi
  done <<EOF
$urls
EOF
  [ -n "$url" ] || return 1

  tmp="$(mktemp -d)"
  asset="$tmp/asset"
  if ! curl -fsSL "$url" -o "$asset" 2>/dev/null; then
    rm -rf "$tmp"
    return 1
  fi
  if ! verify_checksum "$repo" "$(basename "$url")" "$asset"; then
    rm -rf "$tmp"
    return 1
  fi

  found=""
  case "$url" in
    *.tar.gz|*.tgz)
      mkdir -p "$tmp/extract"
      tar -xzf "$asset" -C "$tmp/extract" 2>/dev/null || true
      found="$(find "$tmp/extract" -type f -name "$binary" | head -1)"
      ;;
    *.tar.xz)
      mkdir -p "$tmp/extract"
      tar -xJf "$asset" -C "$tmp/extract" 2>/dev/null || true
      found="$(find "$tmp/extract" -type f -name "$binary" | head -1)"
      ;;
    *.zip)
      if command -v unzip >/dev/null 2>&1; then
        mkdir -p "$tmp/extract"
        unzip -qq "$asset" -d "$tmp/extract" 2>/dev/null || true
        found="$(find "$tmp/extract" -type f -name "$binary" | head -1)"
      fi
      ;;
    *)
      found="$asset"
      ;;
  esac

  if [ -n "$found" ] && install -m 0755 "$found" "$dest"; then
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

# install_named_asset_from_release: see packaging/postinst's identical
# function for the full rationale (exact-filename matching, for repos whose
# asset names don't spell out arch the same way, or that ship more than one
# asset per arch a substring match could ambiguously prefer).
install_named_asset_from_release() {
  repo="$1"
  asset_name="$2"
  binary_glob="$3"
  dest="$4"

  url=""
  while IFS= read -r candidate; do
    case "$candidate" in
      */"$asset_name") url="$candidate"; break ;;
    esac
  done <<EOF
$(latest_release_urls "$repo")
EOF
  [ -n "$url" ] || return 1

  tmp="$(mktemp -d)"
  asset="$tmp/asset.zip"
  if ! curl -fsSL "$url" -o "$asset" 2>/dev/null; then
    rm -rf "$tmp"
    return 1
  fi
  if ! verify_checksum "$repo" "$asset_name" "$asset"; then
    rm -rf "$tmp"
    return 1
  fi
  mkdir -p "$tmp/extract"
  if ! unzip -qq "$asset" -d "$tmp/extract" 2>/dev/null; then
    rm -rf "$tmp"
    return 1
  fi
  found="$(find "$tmp/extract" -type f -name "$binary_glob" | head -1)"
  if [ -n "$found" ] && install -m 0755 "$found" "$dest"; then
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

# --- 4. sing-box: latest release binary ---
install_singbox() {
  if command -v sing-box >/dev/null 2>&1; then
    log "sing-box already present, leaving it alone"
    return 0
  fi
  if install_binary_from_release "SagerNet/sing-box" "sing-box" "$BIN_DIR/sing-box"; then
    log "installed sing-box to $BIN_DIR/sing-box"
  else
    log "WARNING: could not install sing-box from GitHub release assets"
  fi
}

# --- 5. amneziawg-go and amneziawg-tools: release asset, then source build ---
build_amneziawg_go() {
  tmp="$(mktemp -d)"
  if git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$tmp/amneziawg-go" >/dev/null 2>&1 \
    && ( cd "$tmp/amneziawg-go" && make >/dev/null 2>&1 && install -m 0755 amneziawg-go "$BIN_DIR/amneziawg-go" ); then
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

build_amneziawg_tools() {
  tmp="$(mktemp -d)"
  if git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools "$tmp/amneziawg-tools" >/dev/null 2>&1 \
    && ( cd "$tmp/amneziawg-tools/src" && make >/dev/null 2>&1 && make install >/dev/null 2>&1 ); then
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

install_amneziawg_go() {
  if command -v amneziawg-go >/dev/null 2>&1; then
    log "amneziawg-go already present, leaving it alone"
    return 0
  fi
  if install_binary_from_release "amnezia-vpn/amneziawg-go" "amneziawg-go" "$BIN_DIR/amneziawg-go"; then
    log "installed amneziawg-go to $BIN_DIR/amneziawg-go"
    return 0
  fi
  log "amneziawg-go release binary not available, falling back to source build"
  build_amneziawg_go || log "WARNING: amneziawg-go build failed"
}

install_amneziawg_tools() {
  if command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1; then
    log "awg/awg-quick already present, leaving them alone"
    return 0
  fi
  release_ok=true
  command -v awg >/dev/null 2>&1 || install_binary_from_release "amnezia-vpn/amneziawg-tools" "awg" "$BIN_DIR/awg" || release_ok=false
  command -v awg-quick >/dev/null 2>&1 || install_binary_from_release "amnezia-vpn/amneziawg-tools" "awg-quick" "$BIN_DIR/awg-quick" || release_ok=false
  if [ "$release_ok" = true ] && command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1; then
    log "installed amneziawg-tools from GitHub release assets"
    return 0
  fi

  log "amneziawg-tools release binaries not available, falling back to source build"
  build_amneziawg_tools || log "WARNING: amneziawg-tools build failed"
}

# --- 6. Xray-core and tun2socks: VLESS needs both (see internal/engine/xray.go
# — Xray-core has no native TUN inbound, tun2socks pairs with it) ---
install_xray() {
  if command -v xray >/dev/null 2>&1; then
    log "xray already present, leaving it alone"
    return 0
  fi
  case "$GOARCH" in
    amd64) xray_asset="Xray-linux-64.zip" ;;
    arm64) xray_asset="Xray-linux-arm64-v8a.zip" ;;
    *) xray_asset="" ;;
  esac
  if [ -n "$xray_asset" ] && install_named_asset_from_release "XTLS/Xray-core" "$xray_asset" "xray" "$BIN_DIR/xray"; then
    log "installed xray to $BIN_DIR/xray"
  else
    log "WARNING: could not install xray from GitHub release assets — VLESS profiles need it"
  fi
}

install_tun2socks() {
  if command -v tun2socks >/dev/null 2>&1; then
    log "tun2socks already present, leaving it alone"
    return 0
  fi
  case "$GOARCH" in
    amd64) t2s_asset="tun2socks-linux-amd64.zip" ;;
    arm64) t2s_asset="tun2socks-linux-arm64.zip" ;;
    *) t2s_asset="" ;;
  esac
  if [ -n "$t2s_asset" ] && install_named_asset_from_release "xjasonlyu/tun2socks" "$t2s_asset" "tun2socks*" "$BIN_DIR/tun2socks"; then
    log "installed tun2socks to $BIN_DIR/tun2socks"
  else
    log "WARNING: could not install tun2socks from GitHub release assets — VLESS profiles' TUN mode needs it"
  fi
}

# --- 7. vpnctld: the daemon, its systemd unit, and the "vpnctl" group ---
#
# No prebuilt release asset exists for vpnctld (only vpnctl itself is
# published, see install_vpnctl above), so this always builds it from a
# source clone — which also gives us packaging/vpnctld.service to install
# without a second download. Mirrors packaging/postinst's daemon setup:
# create the group, add the invoking (real, non-root) user to it, then
# enable and start the service — run_migration (called separately, right
# before this function, at the bottom of the script) already handled the
# same one-time migration a .deb upgrade needs (a leftover active.json from
# a pre-daemon vpnctl would otherwise leave vpnctld starting on top of an
# orphaned namespace).
install_daemon() {
  log "building vpnctld (no prebuilt release asset for it yet)..."
  command -v go >/dev/null 2>&1 || die "'go' is required to build vpnctld — install golang-go or Go manually"
  command -v git >/dev/null 2>&1 || die "'git' is required to build vpnctld"

  tmp_src="$(mktemp -d)"
  git clone --depth 1 "https://github.com/${REPO}" "$tmp_src/vpnctl" || die "could not clone ${REPO}"
  ( cd "$tmp_src/vpnctl" && go build -o "$BIN_DIR/vpnctld" ./cmd/vpnctld ) || die "vpnctld build failed"
  install -m 0644 "$tmp_src/vpnctl/packaging/vpnctld.service" /lib/systemd/system/vpnctld.service \
    || die "installing the systemd unit failed"
  rm -rf "$tmp_src"
  log "installed vpnctld to $BIN_DIR/vpnctld and its systemd unit"

  groupadd -f vpnctl
  real_user="${SUDO_USER:-}"
  if [ -n "$real_user" ] && [ "$real_user" != "root" ]; then
    usermod -aG vpnctl "$real_user"
    log "added $real_user to the 'vpnctl' group (log out/in, or run 'newgrp vpnctl', for it to take effect in already-open shells)"
  else
    log "no non-root invoking user detected (\$SUDO_USER unset) — add the intended vpnctl user(s) to the 'vpnctl' group manually: usermod -aG vpnctl <user>"
  fi

  # run_migration (called separately, before install_daemon, at the bottom
  # of this script) already handled any leftover pre-daemon active.json —
  # nothing further to do here before enabling the service.

  if ! command -v systemctl >/dev/null 2>&1; then
    log "WARNING: systemctl not found — install/enable the vpnctld systemd unit manually (see packaging/vpnctld.service)"
    return 0
  fi
  systemctl daemon-reload
  if systemctl enable --now vpnctld; then
    log "vpnctld enabled and started (systemctl status vpnctld to check)"
  else
    log "WARNING: failed to enable/start vpnctld — check 'systemctl status vpnctld' and 'journalctl -u vpnctld'"
  fi
}

# migrate_from_file_based_model: same PID-kill/namespace-removal logic as
# packaging/postinst's function of the same name — see its comment for the
# full rationale. Applied to /root and every /home/*/.local/state/vpnctl
# before vpnctld starts for the first time.
migrate_from_file_based_model() {
  home="$1"
  state_dir="$home/.local/state/vpnctl"
  active_json="$state_dir/active.json"
  [ -f "$active_json" ] || return 0

  log "found leftover active.json from a pre-daemon vpnctl at $active_json, tearing down before starting vpnctld..."

  if command -v jq >/dev/null 2>&1; then
    pids="$(jq -r '
      [.engine_pid, .helper_pid, .health_pid] + [(.processes // [])[].pid]
      | .[] | select(type == "number" and . > 0 and (. % 1 == 0))
    ' "$active_json" 2>/dev/null)"
    for pid in $pids; do
      case "$pid" in
        ''|*[!0-9]*) continue ;;
      esac
      kill "$pid" 2>/dev/null || true
    done
    if [ -n "$pids" ]; then
      sleep 0.3
      for pid in $pids; do
        case "$pid" in
          ''|*[!0-9]*) continue ;;
        esac
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
      done
    fi
  fi

  if command -v ip >/dev/null 2>&1 && ip netns list 2>/dev/null | grep -q '^vpnctl0\b'; then
    log "namespace vpnctl0 still present after teardown, removing it"
    ip netns del vpnctl0 2>/dev/null || true
  fi

  if [ -S /var/run/wireguard/vpnctl-wg.sock ]; then
    log "stale WireGuard UAPI socket found, removing it"
    rm -f /var/run/wireguard/vpnctl-wg.sock
  fi

  rm -f "$active_json"
}

run_migration() {
  [ -d /root/.local/state/vpnctl ] && migrate_from_file_based_model /root
  for state_dir in /home/*/.local/state/vpnctl; do
    [ -d "$state_dir" ] || continue
    migrate_from_file_based_model "${state_dir%/.local/state/vpnctl}"
  done
}

install_apt_deps
install_singbox
install_xray
install_tun2socks
install_amneziawg_go
install_amneziawg_tools
install_vpnctl
run_migration
install_daemon

log "done. Run 'vpnctl doctor' to verify your setup, then 'vpnctl use <profile>' to get started (no sudo needed once vpnctld is running and you're in the 'vpnctl' group)."

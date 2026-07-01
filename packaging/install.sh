#!/bin/bash
# vpnctl install.sh — the zero-friction MVP installer (spec §2.1/§2.2),
# the alternative to `dpkg -i vpnctl_*.deb` for machines that just want:
#
#   curl -fsSL https://raw.githubusercontent.com/BeesKnight/vpnctl/main/packaging/install.sh | sudo bash
#
# Downloads the vpnctl binary from GitHub Releases, installs it to
# /usr/local/bin/vpnctl, and does the same dependency doustall the .deb's
# postinst does (iproute2/iptables/jq via apt, sing-box from a GitHub
# release, amneziawg-tools via apt or a source build) — fully
# non-interactively, same as postinst.
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

# --- 2. iproute2/iptables/jq ---
install_apt_deps() {
  if ! command -v apt-get >/dev/null 2>&1; then
    log "WARNING: no apt-get found — install iproute2, iptables, jq manually for your distro"
    return 0
  fi
  MISSING=""
  command -v ip >/dev/null 2>&1 || MISSING="$MISSING iproute2"
  command -v iptables >/dev/null 2>&1 || MISSING="$MISSING iptables"
  command -v jq >/dev/null 2>&1 || MISSING="$MISSING jq"
  command -v nsenter >/dev/null 2>&1 || MISSING="$MISSING util-linux"
  if [ -n "$MISSING" ]; then
    log "installing missing packages:$MISSING"
    apt-get update -qq || true
    apt-get install -y $MISSING || log "WARNING: apt-get install failed for:$MISSING — install manually"
  fi
}

# --- 3. sing-box: latest release binary ---
install_singbox() {
  if command -v sing-box >/dev/null 2>&1; then
    log "sing-box already present, leaving it alone"
    return 0
  fi
  TAG="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4 || true)"
  if [ -z "${TAG:-}" ]; then
    log "WARNING: could not determine latest sing-box release — install manually: https://github.com/SagerNet/sing-box/releases"
    return 0
  fi
  VER_NUM="${TAG#v}"
  URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${VER_NUM}-linux-${GOARCH}.tar.gz"
  TMP="$(mktemp -d)"
  if curl -fsSL "$URL" -o "$TMP/sing-box.tar.gz" 2>/dev/null; then
    tar -xzf "$TMP/sing-box.tar.gz" -C "$TMP"
    BIN="$(find "$TMP" -type f -name sing-box | head -1)"
    if [ -n "$BIN" ]; then
      install -m 0755 "$BIN" "$BIN_DIR/sing-box"
      log "installed sing-box $TAG to $BIN_DIR/sing-box"
    fi
  else
    log "WARNING: could not download $URL — install sing-box manually"
  fi
  rm -rf "$TMP"
}

# --- 4. amneziawg-tools/amneziawg-go: apt, then source build ---
install_amneziawg() {
  if command -v awg-quick >/dev/null 2>&1; then
    log "awg-quick already present, leaving it alone"
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1 && apt-get install -y amneziawg-tools amneziawg-dkms >/tmp/vpnctl-awg-apt.log 2>&1; then
    log "amneziawg-tools installed via apt"
    return 0
  fi
  log "amneziawg-tools not available via apt — falling back to a source build"
  if command -v git >/dev/null 2>&1 && command -v go >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
    TMP="$(mktemp -d)"
    if git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$TMP/amneziawg-go" >/dev/null 2>&1 \
       && git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools "$TMP/amneziawg-tools" >/dev/null 2>&1; then
      ( cd "$TMP/amneziawg-go" && make >/dev/null 2>&1 && install -m 0755 amneziawg-go "$BIN_DIR/" ) \
        || log "WARNING: amneziawg-go build failed"
      ( cd "$TMP/amneziawg-tools/src" && make >/dev/null 2>&1 \
          && install -m 0755 wg "$BIN_DIR/awg" \
          && install -m 0755 wg-quick/wg-quick.bash "$BIN_DIR/awg-quick" ) \
        || log "WARNING: amneziawg-tools build failed"
      if command -v awg-quick >/dev/null 2>&1; then
        log "amneziawg built from source and installed"
      fi
    else
      log "WARNING: could not clone amneziawg source repos — plain WireGuard (wg-quick) still works for non-obfuscated profiles"
    fi
    rm -rf "$TMP"
  else
    log "WARNING: git/go/make not available — install amneziawg-tools manually for AmneziaWG obfuscation support; plain WireGuard profiles still work"
  fi
}

install_apt_deps
install_singbox
install_amneziawg
install_vpnctl

log "done. Run 'vpnctl doctor' to verify your setup, then 'vpnctl use <profile>' to get started."

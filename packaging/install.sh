#!/bin/bash
# vpnctl install.sh — the zero-friction MVP installer,
# the alternative to `dpkg -i vpnctl_*.deb` for machines that just want:
#
#   curl -fsSL https://raw.githubusercontent.com/BeesKnight/vpnctl/main/packaging/install.sh | sudo bash
#
# Downloads the vpnctl binary from GitHub Releases, installs it to
# /usr/local/bin/vpnctl, and does the same dependency doustall the .deb's
# postinst does (iproute2/iptables/jq/toolchain via apt, sing-box and
# AmneziaWG userspace from GitHub release assets or source) — fully
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
latest_release_urls() {
  repo="$1"
  curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
    | jq -r '.assets[]?.browser_download_url' 2>/dev/null
}

asset_matches() {
  url_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  bin_lc="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
  case "$url_lc" in
    *"$bin_lc"*linux*"$GOARCH"*|*linux*"$GOARCH"*"$bin_lc"*|*"$bin_lc"*"$GOARCH"*linux*|*"$GOARCH"*linux*"$bin_lc"*) return 0 ;;
    *) return 1 ;;
  esac
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

install_apt_deps
install_singbox
install_amneziawg_go
install_amneziawg_tools
install_vpnctl

log "done. Run 'vpnctl doctor' to verify your setup, then 'vpnctl use <profile>' to get started."

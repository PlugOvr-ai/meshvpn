#!/bin/sh
# meshvpn installer.
#
#   curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh | sudo sh
#
# Install and immediately set up this machine (the service is started for you):
#
#   curl -fsSL .../install.sh | sudo sh -s -- init --endpoint my-server.example.com:7870
#   curl -fsSL .../install.sh | sudo sh -s -- join mesh1-...
#
# Environment: MESHVPN_VERSION=v0.1.0 to pin a release, MESHVPN_BIN_DIR to change /usr/local/bin.
set -eu

REPO="PlugOvr-ai/meshvpn"
BIN_DIR="${MESHVPN_BIN_DIR:-/usr/local/bin}"
VERSION="${MESHVPN_VERSION:-latest}"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "meshvpn currently supports Linux only (found $(uname -s))."

case "$(uname -m)" in
    x86_64 | amd64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) TARGET="aarch64-unknown-linux-musl" ;;
    armv7* | armv8l) TARGET="armv7-unknown-linux-musleabihf" ;;
    armv6*) TARGET="arm-unknown-linux-musleabihf" ;;
    *) die "no prebuilt binary for CPU architecture $(uname -m) - build from source: cargo install --git https://github.com/$REPO" ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "please run as root"
    SUDO="sudo"
else
    SUDO=""
fi

if [ "$VERSION" = "latest" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
fi

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$1" -O "$2"
    else
        die "curl or wget is required"
    fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

ARCHIVE="meshvpn-$TARGET.tar.gz"
say "Downloading meshvpn ($VERSION, $TARGET)..."
fetch "$BASE/$ARCHIVE" "$TMP/$ARCHIVE" || die "download failed: $BASE/$ARCHIVE"
fetch "$BASE/$ARCHIVE.sha256" "$TMP/$ARCHIVE.sha256" || die "download failed: $BASE/$ARCHIVE.sha256"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$TMP" && sha256sum -c "$ARCHIVE.sha256" >/dev/null) || die "checksum mismatch - download corrupted?"
else
    say "(sha256sum not found, skipping checksum verification)"
fi

tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
$SUDO mkdir -p "$BIN_DIR"
$SUDO install -m 0755 "$TMP/meshvpn" "$BIN_DIR/meshvpn"
say "Installed $("$BIN_DIR/meshvpn" --version) to $BIN_DIR/meshvpn"

[ -c /dev/net/tun ] || say "warning: /dev/net/tun is missing - load it with 'modprobe tun' (containers need it passed in)."
command -v ssh >/dev/null 2>&1 || say "note: install openssh-client if this machine should use a reverse SSH tunnel."

# Optional: set the machine up right away, e.g. `sh -s -- join mesh1-...`.
if [ $# -gt 0 ]; then
    $SUDO "$BIN_DIR/meshvpn" "$@"
    case "$1" in
        init | join)
            if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
                $SUDO "$BIN_DIR/meshvpn" install
            else
                say "No systemd found - start meshvpn with: sudo meshvpn up"
            fi
            ;;
    esac
else
    echo
    echo "Next: create a network with   sudo meshvpn init"
    echo "      or join one with        sudo meshvpn join <invite>"
fi

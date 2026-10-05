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
# Without root (rootless: binary in ~/.local/bin, config in ~/.config/meshvpn, userspace
# networking, a systemd user service). Used automatically when sudo is missing:
#
#   curl -fsSL .../install.sh | sh -s -- --user join mesh1-...
#
# Environment: MESHVPN_VERSION=v0.1.0 to pin a release, MESHVPN_BIN_DIR to change /usr/local/bin,
# MESHVPN_DOWNLOAD_URL to download the release files from a mirror instead of GitHub,
# MESHVPN_ROOTLESS=1 for the same as --user.
set -eu

REPO="PlugOvr-ai/meshvpn"
VERSION="${MESHVPN_VERSION:-latest}"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

ROOTLESS="${MESHVPN_ROOTLESS:-}"
[ "$ROOTLESS" = 0 ] && ROOTLESS=""
if [ "${1:-}" = "--user" ] || [ "${1:-}" = "--rootless" ]; then
    ROOTLESS=1
    shift
fi

[ "$(uname -s)" = "Linux" ] || die "meshvpn currently supports Linux only (found $(uname -s))."

case "$(uname -m)" in
    x86_64 | amd64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) TARGET="aarch64-unknown-linux-musl" ;;
    armv7* | armv8l) TARGET="armv7-unknown-linux-musleabihf" ;;
    armv6*) TARGET="arm-unknown-linux-musleabihf" ;;
    *) die "no prebuilt binary for CPU architecture $(uname -m) - build from source: cargo install --git https://github.com/$REPO" ;;
esac

if [ -n "$ROOTLESS" ] && [ "$(id -u)" -eq 0 ]; then
    die "--user is for installing without root - as root, run the installer without it"
fi
if [ "$(id -u)" -ne 0 ] && [ -z "$ROOTLESS" ] && ! command -v sudo >/dev/null 2>&1; then
    say "Not root and no sudo here: installing rootless (for the current user only)."
    ROOTLESS=1
fi
SUDO=""
if [ -n "$ROOTLESS" ]; then
    [ -n "${HOME:-}" ] || die "HOME is not set"
    BIN_DIR="${MESHVPN_BIN_DIR:-$HOME/.local/bin}"
    MESH_DIR="${MESHVPN_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/meshvpn}"
    DIR_ARGS="--dir $MESH_DIR"
    case "$MESH_DIR" in *" "*) die "MESHVPN_DIR must not contain spaces" ;; esac
else
    BIN_DIR="${MESHVPN_BIN_DIR:-/usr/local/bin}"
    MESH_DIR="/etc/meshvpn"
    DIR_ARGS=""
    [ "$(id -u)" -eq 0 ] || SUDO="sudo"
fi

# --- Proxy -----------------------------------------------------------------------------------
# `curl ... | sudo sh` loses the caller's environment (sudo resets it), so also look where proxies
# are configured system-wide. The proxy found is used for the downloads below and saved for
# meshvpn itself (auto-updates), which systemd starts without these variables.
PROXY="" PROXY_FROM="" NOPROXY=""
proxy_in_file() { # $1 = variable name pattern, $2... = files
    pattern="$1"; shift
    sed -n "s/^[[:space:]]*\(export[[:space:]][[:space:]]*\)\{0,1\}\($pattern\)=[\"']\{0,1\}\([^\"'[:space:]]*\).*/\3/p" "$@" 2>/dev/null | head -n 1
}
for v in https_proxy HTTPS_PROXY http_proxy HTTP_PROXY all_proxy ALL_PROXY; do
    eval "val=\${$v:-}"
    if [ -n "$val" ]; then PROXY="$val"; PROXY_FROM="environment"; break; fi
done
if [ -z "$PROXY" ]; then
    for f in /etc/environment /etc/profile.d/*.sh; do
        [ -r "$f" ] || continue
        val="$(proxy_in_file 'https_proxy\|HTTPS_PROXY\|http_proxy\|HTTP_PROXY' "$f")"
        if [ -n "$val" ]; then PROXY="$val"; PROXY_FROM="$f"; break; fi
    done
fi
if [ -z "$PROXY" ] && command -v apt-config >/dev/null 2>&1; then
    val="$(apt-config dump 2>/dev/null | sed -n 's/^Acquire::https\{0,1\}::Proxy "\(.*\)";$/\1/p' | grep -vi '^\(direct\|false\|\)$' | head -n 1)"
    [ -z "$val" ] || { PROXY="$val"; PROXY_FROM="apt configuration"; }
fi
if [ -z "$PROXY" ]; then
    for f in /etc/dnf/dnf.conf /etc/yum.conf; do
        val="$(sed -n 's/^proxy[[:space:]]*=[[:space:]]*//p' "$f" 2>/dev/null | head -n 1)"
        if [ -n "$val" ] && [ "$val" != "_none_" ]; then PROXY="$val"; PROXY_FROM="$f"; break; fi
    done
fi
if [ -z "$PROXY" ] && [ -n "${SUDO_USER:-}" ] && command -v gsettings >/dev/null 2>&1; then
    # Desktop proxy setting of the user who ran sudo (GNOME and friends).
    if [ "$(sudo -u "$SUDO_USER" gsettings get org.gnome.system.proxy mode 2>/dev/null)" = "'manual'" ]; then
        host="$(sudo -u "$SUDO_USER" gsettings get org.gnome.system.proxy.https host 2>/dev/null | tr -d "'")"
        port="$(sudo -u "$SUDO_USER" gsettings get org.gnome.system.proxy.https port 2>/dev/null)"
        if [ -z "$host" ]; then
            host="$(sudo -u "$SUDO_USER" gsettings get org.gnome.system.proxy.http host 2>/dev/null | tr -d "'")"
            port="$(sudo -u "$SUDO_USER" gsettings get org.gnome.system.proxy.http port 2>/dev/null)"
        fi
        [ -z "$host" ] || [ "${port:-0}" = 0 ] || { PROXY="http://$host:$port"; PROXY_FROM="desktop settings of $SUDO_USER"; }
    fi
fi
if [ -n "$PROXY" ]; then
    case "$PROXY" in *://*) ;; *) PROXY="http://$PROXY" ;; esac
    NOPROXY="${no_proxy:-${NO_PROXY:-}}"
    [ -n "$NOPROXY" ] || NOPROXY="$(proxy_in_file 'no_proxy\|NO_PROXY' /etc/environment /etc/profile.d/*.sh)"
    NOPROXY="${NOPROXY:+$NOPROXY,}localhost,127.0.0.1,::1"
    export http_proxy="$PROXY" https_proxy="$PROXY" HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY"
    export no_proxy="$NOPROXY" NO_PROXY="$NOPROXY"
    say "Using proxy $(printf '%s' "$PROXY" | sed 's#//[^@/]*@#//***@#') (from $PROXY_FROM)"
fi

if [ -n "${MESHVPN_DOWNLOAD_URL:-}" ]; then
    BASE="${MESHVPN_DOWNLOAD_URL%/}"
elif [ "$VERSION" = "latest" ]; then
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
if [ -n "$PROXY" ]; then
    # meshvpn reads this when the variables are missing (systemd service, sudo).
    printf 'https_proxy=%s\nhttp_proxy=%s\nno_proxy=%s\n' "$PROXY" "$PROXY" "$NOPROXY" \
        | $SUDO sh -c "mkdir -p '$MESH_DIR' && chmod 700 '$MESH_DIR' && umask 077 && cat > '$MESH_DIR/proxy.env'"
fi
say "Installed $("$BIN_DIR/meshvpn" --version) to $BIN_DIR/meshvpn"

if [ -n "$ROOTLESS" ]; then
    say "Rootless install: config in $MESH_DIR, userspace networking - other nodes reach the services here, ssh to *.mesh works directly, other programs reach the mesh via socks5h://127.0.0.1:1055."
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *) say "note: $BIN_DIR is not in your PATH - add it, e.g.: echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile" ;;
    esac
    # shellcheck disable=SC2086
    if [ $# -gt 0 ]; then
        "$BIN_DIR/meshvpn" $DIR_ARGS "$@"
        case "$1" in
            init | join) "$BIN_DIR/meshvpn" $DIR_ARGS install ;;
        esac
    elif [ -f "$MESH_DIR/config.toml" ]; then
        # Already set up: restart on the new version.
        "$BIN_DIR/meshvpn" $DIR_ARGS install
    else
        # Plain `meshvpn` picks this directory by itself unless the machine also has a root install.
        if [ -d /etc/meshvpn ] || [ -n "${MESHVPN_DIR:-}" ]; then MV="meshvpn --dir $MESH_DIR"; else MV="meshvpn"; fi
        echo
        echo "Next: create a network with   $MV init"
        echo "      or join one with        $MV join <invite>"
        echo "      then start it with      $MV install"
    fi
    exit 0
fi

[ -c /dev/net/tun ] || say "note: no /dev/net/tun here (e.g. a container without NET_ADMIN) - meshvpn runs in userspace mode: other nodes reach the services here, programs here reach the mesh via socks5h://127.0.0.1:1055 (ssh to *.mesh works directly)."
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
elif [ -f /etc/systemd/system/meshvpn.service ] && $SUDO test -f /etc/meshvpn/config.toml; then
    # Already set up: restart the service on the new version (this also stops a meshvpn
    # that was started by hand and would block the network interface).
    $SUDO "$BIN_DIR/meshvpn" install
else
    echo
    echo "Next: create a network with   sudo meshvpn init"
    echo "      or join one with        sudo meshvpn join <invite>"
fi

#!/bin/sh
# Install meshvpn on a device that cannot reach the internet, from a machine that can SSH
# into it - typically the jump host its reverse SSH tunnel goes to. Nothing is installed on
# the machine running this script.
#
#   curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/deploy.sh \
#     | sh -s -- --invite mesh1-... user@localhost -p 2222
#
# What happens:
#   1. The meshvpn release for the device's CPU is downloaded here and uploaded over SSH.
#   2. On the device (with sudo): meshvpn is installed, gets its own SSH key, joins the
#      network and starts as a service.
#   3. That key is added to ~/.ssh/authorized_keys of the user running this script, limited
#      to port forwarding. The device uses it to keep its own SSH connection to this machine
#      and reaches the network (and GitHub, for updates) through it.
#
# Options:
#   --invite CODE        invite from `meshvpn invite` on any member (required)
#   -p PORT              SSH port of the device (default 22)
#   -i KEY               SSH key for logging into the device
#   --name NAME          name of the device in the network (default: its hostname)
#   --jump USER@HOST[:PORT]
#                        how the device reaches this machine over SSH (default: detected
#                        from the device's existing SSH connection, user = you)
#   --binary FILE        upload this meshvpn binary instead of downloading a release
#   --version vX.Y.Z     release to install (default: latest)
set -eu

REPO="PlugOvr-ai/meshvpn"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,31s/^# \{0,1\}//p' "$0" 2>/dev/null || true; exit 1; }

INVITE="" DEVICE="" PORT=22 KEY="" NAME="" JUMP="" BINARY="" VERSION="latest"
while [ $# -gt 0 ]; do
    case "$1" in
        --invite) INVITE="$2"; shift 2 ;;
        -p | --port) PORT="$2"; shift 2 ;;
        -i | --identity) KEY="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --jump) JUMP="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        -h | --help) usage ;;
        -*) die "unknown option $1" ;;
        *) [ -z "$DEVICE" ] || die "only one device, please"; DEVICE="$1"; shift ;;
    esac
done
[ -n "$DEVICE" ] || die "which device? e.g.: sh deploy.sh --invite mesh1-... user@localhost -p 2222"
case "$INVITE" in mesh1-*) ;; *) die "--invite mesh1-... is required (run \`meshvpn invite\` on any member)" ;; esac

TMP="$(mktemp -d)"
cleanup() {
    ssh -o ControlPath="$TMP/cm" -O exit "$DEVICE" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# One SSH login for all steps. stdin never comes from the terminal pipe (`curl | sh` feeds
# this script through it), so every ssh call redirects it explicitly.
set -- -o ControlMaster=auto -o ControlPath="$TMP/cm" -o ControlPersist=600 -p "$PORT"
[ -z "$KEY" ] || set -- "$@" -i "$KEY"
dev() { c="$1"; shift; ssh "$@" -T "$DEVICE" "$c"; }   # usage: dev 'command' "$@" </dev/null
if [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null; then
    dev_sudo() { ssh "$@" -tt "$DEVICE" "$SCRIPT" </dev/tty; }   # may ask for the sudo password
else
    dev_sudo() { ssh "$@" -T "$DEVICE" "$SCRIPT" </dev/null; }   # needs passwordless sudo
fi

say "Connecting to $DEVICE (port $PORT)..."
# shellcheck disable=SC2016 # expands on the device
INFO="$(dev 'uname -m; hostname; command -v ssh >/dev/null && echo has-ssh || echo no-ssh
  ss -tnH state established "( dport = :22 )" 2>/dev/null | awk "{print \$4}" | grep -v "^127\.\|^\[::1\]" | sort -u || true' "$@" </dev/null)" \
    || die "cannot log into $DEVICE"
MACHINE="$(echo "$INFO" | sed -n 1p)"
HOSTNAME_DEV="$(echo "$INFO" | sed -n 2p)"
[ "$(echo "$INFO" | sed -n 3p)" = "has-ssh" ] || die "the device needs an ssh client (openssh-client)"
PEERS="$(echo "$INFO" | sed -n '4,$p')"

if [ -z "$JUMP" ]; then
    # The device's existing SSH connection (its reverse tunnel) tells us how it reaches us.
    COUNT="$(printf '%s\n' "$PEERS" | grep -c . || true)"
    [ "$COUNT" = 1 ] || die "cannot tell how $DEVICE reaches this machine (SSH connections seen from it: ${PEERS:-none}). Pass --jump USER@HOST[:PORT]"
    JUMP="$(id -un)@$(printf '%s' "$PEERS" | sed 's/:22$//; s/^\[\(.*\)\]$/\1/')"
fi
JUMP_PORT=22
case "$JUMP" in *:*) JUMP_PORT="${JUMP##*:}"; JUMP="${JUMP%:*}" ;; esac
case "$JUMP" in *@*) ;; *) JUMP="$(id -un)@$JUMP" ;; esac
say "The device will connect back to $JUMP (port $JUMP_PORT)."

if [ -n "$BINARY" ]; then
    cp "$BINARY" "$TMP/meshvpn"
else
    case "$MACHINE" in
        x86_64 | amd64) TARGET="x86_64-unknown-linux-musl" ;;
        aarch64 | arm64) TARGET="aarch64-unknown-linux-musl" ;;
        armv7* | armv8l) TARGET="armv7-unknown-linux-musleabihf" ;;
        armv6*) TARGET="arm-unknown-linux-musleabihf" ;;
        *) die "no prebuilt meshvpn for $MACHINE - pass one with --binary" ;;
    esac
    if [ "$VERSION" = latest ]; then BASE="https://github.com/$REPO/releases/latest/download"
    else BASE="https://github.com/$REPO/releases/download/$VERSION"; fi
    say "Downloading meshvpn ($VERSION, $TARGET)..."
    for f in "meshvpn-$TARGET.tar.gz" "meshvpn-$TARGET.tar.gz.sha256"; do
        if command -v curl >/dev/null 2>&1; then curl -fsSL "$BASE/$f" -o "$TMP/$f"
        else wget -q "$BASE/$f" -O "$TMP/$f"; fi || die "download failed: $BASE/$f"
    done
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$TMP" && sha256sum -c "meshvpn-$TARGET.tar.gz.sha256" >/dev/null) || die "checksum mismatch"
    fi
    tar -xzf "$TMP/meshvpn-$TARGET.tar.gz" -C "$TMP" meshvpn
fi

say "Uploading meshvpn to $HOSTNAME_DEV..."
VERSION_DEV="$(dev 'umask 077; cat > ~/.meshvpn-upload && chmod 755 ~/.meshvpn-upload && ~/.meshvpn-upload --version' "$@" <"$TMP/meshvpn")" \
    || die "upload failed (does the binary run on $MACHINE?)"

q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
NAME_ARG=""
[ -z "$NAME" ] || NAME_ARG="--name $(q "$NAME")"

say "Installing $VERSION_DEV on $HOSTNAME_DEV (you may be asked for its sudo password)..."
SCRIPT="set -e
SUDO=''; [ \"\$(id -u)\" -eq 0 ] || SUDO=sudo
\$SUDO install -m 755 ~/.meshvpn-upload /usr/local/bin/meshvpn
rm -f ~/.meshvpn-upload
\$SUDO mkdir -p /etc/meshvpn
\$SUDO chmod 700 /etc/meshvpn
\$SUDO test -f /etc/meshvpn/ssh_key || \$SUDO ssh-keygen -q -t ed25519 -N '' -C \"meshvpn@\$(hostname)\" -f /etc/meshvpn/ssh_key
\$SUDO cat /etc/meshvpn/ssh_key.pub > /tmp/meshvpn-deploy.pub
chmod 644 /tmp/meshvpn-deploy.pub"
dev_sudo "$@" || die "installing on $HOSTNAME_DEV failed"
PUBKEY="$(dev 'cat /tmp/meshvpn-deploy.pub; rm -f /tmp/meshvpn-deploy.pub' "$@" </dev/null | tr -d '\r')"
case "$PUBKEY" in ssh-ed25519\ *) ;; *) die "could not read the device's key" ;; esac

# Let the device in here for port forwarding only: any command it tries just prints
# meshvpn-ok, so a compromised device gets no shell on this machine.
mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
KEY_BODY="$(echo "$PUBKEY" | awk '{print $2}')"
if ! grep -qF "$KEY_BODY" ~/.ssh/authorized_keys; then
    printf 'restrict,port-forwarding,command="echo meshvpn-ok" %s\n' "$PUBKEY" >>~/.ssh/authorized_keys
    say "Authorized the device's key in ~/.ssh/authorized_keys (port forwarding only)."
fi

say "Connecting $HOSTNAME_DEV to the network..."
SCRIPT="set -e
SUDO=''; [ \"\$(id -u)\" -eq 0 ] || SUDO=sudo
if [ \"\$(\$SUDO ssh -i /etc/meshvpn/ssh_key -p $JUMP_PORT -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 $JUMP true </dev/null)\" != meshvpn-ok ]; then
  echo 'error: the device cannot SSH to $JUMP (port $JUMP_PORT) - pass the right address with --jump' >&2; exit 1
fi
if \$SUDO test -f /etc/meshvpn/config.toml; then
  echo 'Already part of a network - keeping its configuration, updating meshvpn.'
else
  \$SUDO /usr/local/bin/meshvpn join $(q "$INVITE") $NAME_ARG --ssh $JUMP --ssh-port $JUMP_PORT --ssh-remote-port 0 --ssh-identity /etc/meshvpn/ssh_key | sed -n 's/^ *mesh IP: */  mesh IP: /p; s/^ *this node: */  name:    /p'
fi
if [ -d /run/systemd/system ]; then
  \$SUDO /usr/local/bin/meshvpn install >/dev/null
  \$SUDO systemctl restart meshvpn
else
  \$SUDO pkill -x meshvpn || true
  \$SUDO sh -c 'nohup /usr/local/bin/meshvpn up >>/var/log/meshvpn.log 2>&1 &'
fi"
dev_sudo "$@" || die "setting up meshvpn on $HOSTNAME_DEV failed"

say "Done. $HOSTNAME_DEV joins the network within a few seconds - check with \`meshvpn status\` on any node."
echo "Nothing was installed on this machine; keep SSH access from the device to $JUMP working."

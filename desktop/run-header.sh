#!/bin/sh
# meshvpn with a full desktop: this one file holds meshvpn, Xfce and the LibreWolf browser, with
# everything they need. Nothing is downloaded and no package manager is involved, so it works on
# any Linux distribution of this CPU architecture, in containers too.
#
#   sudo sh meshvpn-full-@ARCH@.run                        install
#   sudo sh meshvpn-full-@ARCH@.run join mesh1-...         install and join a network
#   sudo sh meshvpn-full-@ARCH@.run init --endpoint h:7870 install and create a network
#   sudo sh meshvpn-full-@ARCH@.run --uninstall            remove the desktop (keeps meshvpn)
#
# Without root (sh meshvpn-full-@ARCH@.run ...) it installs for the current user alone: everything
# goes in ~/.local, with one link in /tmp (see relocate below).
#
# Then, from any other node: meshvpn desktop <this node>
set -eu

ARCH=@ARCH@
NEEDS_MB=@UNPACKED_MB@
LINES=@HEADER_LINES@
SMALL=@SMALL_BYTES@
STORE=/nix/store
USER_MODE=""
# Commands the desktop's menu, the browser bar and people's terminals call by name.
COMMANDS="xfce4-terminal thunar xfce4-appfinder xfce4-session-logout xfce4-settings-manager exo-open"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Nix on this machine: its store is the one we'd unpack into, and its cleanup deletes what it
# doesn't know, so it must not manage ours (and we must not delete what's its).
real_nix() { [ -e /nix/var/nix/db ]; }

remove_store_paths() { # $1 = file listing paths, $2 = file of paths to keep (may be empty)
    real_nix && return 0
    [ -f "$1" ] || return 0
    while IFS= read -r p; do
        case "$p" in /nix/store/?*) ;; *) continue ;; esac
        grep -qxF "$p" "$2" 2>/dev/null || rm -rf "$p"
    done < "$1"
}

if [ "${1:-}" = "--user" ]; then
    [ "$(id -u)" -ne 0 ] || die "--user is for installing without root - as root, run the installer without it"
    shift
fi
[ "$(id -u)" -eq 0 ] || USER_MODE=1

if [ -n "$USER_MODE" ]; then
    [ -n "${HOME:-}" ] || die "HOME is not set"
    DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
    mkdir -p "$DATA" 2>/dev/null || die "can't write to $DATA: set HOME to a directory of yours and run this again"
    BASE="$DATA/meshvpn/desktop-full"
    UNPACK="$BASE"
    HOME_DIR="$BASE/opt/meshvpn-desktop-full"
    BIN="$HOME/.local/bin"
    APPS="$DATA/applications"
    CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/meshvpn/config.toml"
    SUDO_HINT=""
else
    UNPACK=/
    HOME_DIR=/opt/meshvpn-desktop-full
    BIN=/usr/local/bin
    APPS=/usr/local/share/applications
    CONFIG=/etc/meshvpn/config.toml
    SUDO_HINT="sudo "
fi

if [ "${1:-}" = "--uninstall" ]; then
    for c in xfce4-session librewolf $COMMANDS; do
        # Only what we put there.
        [ -f "$BIN/$c" ] && grep -q "$HOME_DIR" "$BIN/$c" 2>/dev/null && rm -f "$BIN/$c"
    done
    rm -f "$APPS/meshvpn-librewolf.desktop"
    if [ -n "$USER_MODE" ]; then
        if [ -f "$BASE/prefix" ]; then
            # Only our own: /tmp is shared, and it may be someone else's by now.
            [ "$(readlink "$(cat "$BASE/prefix")" 2>/dev/null)" != "$BASE/nix/store" ] || rm -f "$(cat "$BASE/prefix")"
        fi
        chmod -R u+w "$BASE" 2>/dev/null || true
        rm -rf "$BASE"
    else
        remove_store_paths "$HOME_DIR/paths" /dev/null
        rm -rf "$HOME_DIR"
        rmdir /nix/store /nix 2>/dev/null || true
    fi
    say "Removed the desktop. meshvpn itself stays: to remove it too, see meshvpn uninstall."
    exit 0
fi

MACHINE="$(uname -m)"
case "$MACHINE" in amd64) MACHINE=x86_64 ;; arm64) MACHINE=aarch64 ;; esac
[ "$(uname -s)" = Linux ] || die "this installer is for Linux (found $(uname -s))"
[ "$MACHINE" = "$ARCH" ] || die "this installer is for $ARCH, this machine is $MACHINE"

if [ -n "$USER_MODE" ]; then
    say "No root here: installing for this user alone, in $BASE. (For the whole machine: sudo sh $0)"
    mkdir -p "$BASE"
    [ -w /tmp ] || die "needs to write to /tmp, for one link to the desktop's files"
    # An earlier install, replaced as a whole. Its link's name stays if it can.
    chmod -R u+w "$BASE/nix" "$BASE/opt" 2>/dev/null || true
    rm -rf "$BASE/nix" "$BASE/opt"
    FREE_AT="$BASE"
else
    mkdir -p /nix/store /opt
    FREE_AT=/nix/store
fi
FREE_MB="$(df -Pm "$FREE_AT" 2>/dev/null | awk 'NR==2 {print $4}' || true)"
if [ -n "$FREE_MB" ] && [ "$FREE_MB" -lt "$NEEDS_MB" ]; then
    die "needs ${NEEDS_MB} MB free for $FREE_AT, there are ${FREE_MB} MB"
fi
[ -n "$USER_MODE" ] || ! real_nix || say "note: Nix is installed here. Its garbage collector would delete the desktop, because Nix doesn't know about it; run this installer again if that happens."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM
[ -f "$HOME_DIR/paths" ] && cp "$HOME_DIR/paths" "$TMP/old-paths"

say "Unpacking meshvpn, Xfce and LibreWolf (about $NEEDS_MB MB, this takes a minute)..."
# After this script come two archives: meshvpn and the X server, then the desktop.
tail -n +"$LINES" "$0" | head -c "$SMALL" | tar -xzf - -C "$UNPACK" || die "unpacking failed: is this file complete?"
tail -n +"$LINES" "$0" | tail -c +"$((SMALL + 1))" | tar -xzf - -C "$UNPACK" || die "unpacking failed: is this file complete?"
[ -L "$HOME_DIR/env" ] || die "unpacking failed: Xfce is missing"
[ -n "$USER_MODE" ] || [ -x "$HOME_DIR/env/bin/xfce4-session" ] || die "unpacking failed: Xfce is missing"
[ -n "$USER_MODE" ] || [ ! -f "$TMP/old-paths" ] || remove_store_paths "$TMP/old-paths" "$HOME_DIR/paths"

mkdir -p "$BIN"
install -m 0755 "$HOME_DIR/meshvpn" "$BIN/meshvpn"
rm -f "$HOME_DIR/meshvpn"

# Without root /nix/store can't exist, and it's compiled into all of the desktop. So every mention
# becomes a path of the same length that anyone can make, a link in /tmp to the files here. No user
# namespaces or the like are involved, because containers usually don't allow them. The name is
# random per install, so that users of one machine don't collide. The sticky bit of /tmp means only
# we can remove the link; the kernel doesn't follow a link in /tmp that belongs to someone else, and
# the check below refuses one too. The link is made again whenever something here starts, as /tmp
# may have been emptied.
LINK_LINE=""
KEEP_LINE=""
if [ -n "$USER_MODE" ]; then
    PREFIX="$(cat "$BASE/prefix" 2>/dev/null || true)"
    case "$PREFIX" in /tmp/mv???) ;; *) PREFIX="" ;; esac
    # Taken by someone else meanwhile: a new one.
    if [ -n "$PREFIX" ] && [ -L "$PREFIX" ] && [ "$(readlink "$PREFIX")" != "$BASE/nix/store" ]; then PREFIX=""; fi
    while [ -z "$PREFIX" ] || { [ ! -L "$PREFIX" ] && [ -e "$PREFIX" ]; }; do
        PREFIX="/tmp/mv$(LC_ALL=C tr -dc a-z0-9 < /dev/urandom | head -c 3)"
        if [ -L "$PREFIX" ]; then PREFIX=""; fi
    done
    [ "${#PREFIX}" -eq "${#STORE}" ] || die "internal error: $PREFIX"
    say "Adapting it to this user (under a minute)..."
    "$BIN/meshvpn" desktop relocate "$BASE" --from "$STORE" --to "$PREFIX" || die "adapting the desktop failed"
    printf '%s\n' "$PREFIX" > "$BASE/prefix"
    cat > "$HOME_DIR/link" <<EOS
# Installed by meshvpn: makes sure the desktop's files can be found (see the installer).
meshvpn_link() {
    [ -L "$PREFIX" ] || ln -s "$BASE/nix/store" "$PREFIX" 2>/dev/null || true
    set -- \$(ls -ldn "$PREFIX" 2>/dev/null)
    if [ "\${3:-}" = "\$(id -u)" ] && [ "\$(readlink "$PREFIX")" = "$BASE/nix/store" ]; then
        return 0
    fi
    echo "meshvpn desktop: $PREFIX is not ours (another user may have taken it). To fix this, run the meshvpn-full installer again." >&2
    exit 1
}
meshvpn_link
EOS
    . "$HOME_DIR/link"
    LINK_LINE=". \"$HOME_DIR/link\""
    # Cleaners of /tmp remove old links, also during a long session.
    KEEP_LINE="( while kill -0 \$\$ 2>/dev/null; do meshvpn_link; touch -h \"$PREFIX\" 2>/dev/null; sleep 3600; done ) </dev/null >/dev/null 2>&1 &"
    "$HOME_DIR/env/bin/dbus-daemon" --version >/dev/null 2>&1 \
        || die "can't run the desktop's programs from $BASE (is it mounted noexec?)"
fi

# The session's own environment: the desktop's files come after the system's, so the programs of
# this machine stay first in terminals and in the menu.
cat > "$BIN/xfce4-session" <<EOS
#!/bin/sh
# Installed by meshvpn: starts Xfce from $HOME_DIR
$LINK_LINE
$KEEP_LINE
E="$HOME_DIR/env"
export PATH="\$PATH:\$E/bin"
export XDG_DATA_DIRS="\${XDG_DATA_DIRS:-/usr/local/share:/usr/share}:\$E/share"
export XDG_CONFIG_DIRS="\$E/etc/xdg:\${XDG_CONFIG_DIRS:-/etc/xdg}"
panel="\${XDG_CONFIG_HOME:-\$HOME/.config}/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml"
if [ ! -e "\$panel" ]; then
    mkdir -p "\$(dirname "\$panel")"
    cp "\$E/etc/xdg/xfce4/panel/default.xml" "\$panel" 2>/dev/null && chmod u+w "\$panel"
fi
# Its compiled-in configuration is in /etc, which on this machine is not its own.
exec "\$E/bin/dbus-run-session" --config-file="\$E/share/dbus-1/session.conf" -- "\$E/bin/xfce4-session" "\$@"
EOS
chmod 0755 "$BIN/xfce4-session"

for c in librewolf $COMMANDS; do
    cat > "$BIN/$c" <<EOS
#!/bin/sh
# Installed by meshvpn: $c from $HOME_DIR
$LINK_LINE
export PATH="\$PATH:$HOME_DIR/env/bin"
export XDG_DATA_DIRS="\${XDG_DATA_DIRS:-/usr/local/share:/usr/share}:$HOME_DIR/env/share"
export XDG_CONFIG_DIRS="$HOME_DIR/env/etc/xdg:\${XDG_CONFIG_DIRS:-/etc/xdg}"
exec "$HOME_DIR/env/bin/$c" "\$@"
EOS
    chmod 0755 "$BIN/$c"
done

# The browser bar's list of applications.
mkdir -p "$APPS"
cp -f "$HOME_DIR/env/share/applications/librewolf.desktop" "$APPS/meshvpn-librewolf.desktop"
chmod 644 "$APPS/meshvpn-librewolf.desktop"

"$BIN/meshvpn" desktop setup --from "$HOME_DIR/x-bundle.tar.gz" >/dev/null || die "installing the X server failed"
# Users without their own copy of the X server use the machine's, set up just now.
rm -f "$HOME_DIR/x-bundle.tar.gz"

say "Installed $("$BIN/meshvpn" --version) with Xfce and LibreWolf."
echo "Licences and where to get the source code: $HOME_DIR/README"
if [ -n "$USER_MODE" ]; then
    case ":$PATH:" in
        *":$BIN:"*) ;;
        *) echo "note: $BIN is not in your PATH; add it to run meshvpn by name." ;;
    esac
fi

if [ $# -gt 0 ]; then
    "$BIN/meshvpn" "$@"
    case "$1" in
        init | join) "$BIN/meshvpn" install ;;
    esac
    echo
    echo "From another node: meshvpn desktop <this node>"
elif [ -f "$CONFIG" ]; then
    "$BIN/meshvpn" install
else
    echo
    echo "Next: create a network with   ${SUDO_HINT}meshvpn init"
    echo "      or join one with        ${SUDO_HINT}meshvpn join <invite>"
    echo "Then from another node:       meshvpn desktop <this node>"
fi
exit 0

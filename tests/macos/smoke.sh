#!/bin/bash
# The logs belong to the runner user, the daemons run as root.
# shellcheck disable=SC2024
# meshvpn on macOS (CI: a GitHub macOS runner, with sudo). Two nodes on this machine: "maca" in
# kernel mode (a utun interface) and "macb" in userspace mode. Traffic in both directions goes
# through the utun, so this checks the macOS network interface, routes, /etc/hosts and launchd.
#
#   tests/macos/smoke.sh target/release/meshvpn
set -euo pipefail
# Where install.sh puts it: sshd only runs a root-owned binary in a protected directory.
sudo mkdir -p /opt/meshvpn/bin
sudo install -m 0755 "$1" /opt/meshvpn/bin/meshvpn
B=/opt/meshvpn/bin/meshvpn
DB=/tmp/meshvpn-b
fail() { echo "FAIL: $*"; sudo tail -40 /tmp/a.log /tmp/b.log 2>/dev/null; exit 1; }
wait_for() { # $1 = description, $2... = command
    local what="$1"; shift
    for _ in $(seq 60); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
    fail "timed out: $what"
}
cleanup() {
    sudo pkill -f "meshvpn.* up" || true
    sudo "$B" uninstall >/dev/null 2>&1 || true
    kill "${HTTP:-0}" 2>/dev/null || true
}
trap cleanup EXIT

sudo rm -rf /etc/meshvpn "$DB"
sudo "$B" init --name maca --endpoint 127.0.0.1:7870
(sudo "$B" up > /tmp/a.log 2>&1 &)
wait_for "maca running" sudo "$B" status
INVITE="$(sudo "$B" --json invite | python3 -c 'import json,sys; print(json.load(sys.stdin)["invite"])')"
sudo "$B" --dir "$DB" join "$INVITE" --name macb --listen 0.0.0.0:47871 --userspace
# One /etc/hosts block on this machine is enough.
sudo python3 - "$DB/config.toml" <<'PY'
import sys
p = sys.argv[1]
lines = [l for l in open(p) if not l.startswith("manage_hosts")]
open(p, "w").write("manage_hosts = false\n" + "".join(lines))  # top level, before any [table]
PY
(sudo "$B" --dir "$DB" up > /tmp/b.log 2>&1 &)
online() { sudo "$B" --json status | python3 -c 'import json,sys; s=json.load(sys.stdin); sys.exit(0 if any(p["name"]=="macb" and p["online"] for p in s["peers"]) else 1)'; }
wait_for "macb online" online

IFACE="$(sudo "$B" --json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["interface"])')"
B_IP="$(sudo "$B" --dir "$DB" --json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["ip"])')"
echo "maca on $IFACE, macb at $B_IP"
case "$IFACE" in utun*) ;; *) fail "interface should be utunN, is $IFACE" ;; esac
ifconfig "$IFACE" | grep -q "inet 100\." || fail "no mesh address on $IFACE"
netstat -rn -f inet | grep -q "^100.64/10.*$IFACE" || { netstat -rn -f inet; fail "no route for the mesh"; }
grep -q "macb.mesh" /etc/hosts || fail "/etc/hosts has no entry for macb"

ping -c 2 -t 10 "$B_IP" >/dev/null || fail "ping macb through the utun"
mkdir -p /tmp/www && echo hello-mac > /tmp/www/index.html
(cd /tmp/www && python3 -m http.server 8000 >/dev/null 2>&1) & HTTP=$!
wait_for "the web server" curl -fsS -m 2 http://127.0.0.1:8000/
netstat -an -p tcp | grep -E "LISTEN" | grep -E "[.:]8000 " || true
get() { curl -fsS -m 5 "$@" | grep -q hello-mac; }
# out of the utun: macb's userspace stack forwards to the server here
wait_for "TCP into the mesh through the utun" get "http://$B_IP:8000/"
# into the utun: from macb through the mesh to maca's address
wait_for "TCP out of the mesh into the utun" get -x socks5h://127.0.0.1:1055 "http://maca.mesh:8000/"
ping -c 2 -t 10 macb.mesh >/dev/null || fail "names: macb.mesh"

# Logins into the Mac through its own sshd (if this Mac lets us switch Remote Login on):
# from macb through the mesh, with the key macb publishes and maca's rule.
if sudo systemsetup -setremotelogin on >/dev/null 2>&1 || sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null; then
    [ -f ~/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519
    sudo "$B" ssh allow "$(id -un)@macb" --as "$(id -un)"
    who="$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
        -o "ProxyCommand=sudo $B --dir $DB nc %h %p" "$(id -un)@maca.mesh" whoami 2>&1 || true)"
    echo "ssh login into the Mac: $who"
    [ "$who" = "$(id -un)" ] && echo "MACOS_SSHD_LOGIN=ok" || echo "MACOS_SSHD_LOGIN=failed (not fatal)"
else
    echo "MACOS_SSHD_LOGIN=skipped (Remote Login can't be switched on here)"
fi

sudo "$B" status
sudo "$B" doctor || true
"$B" --json nodes >/dev/null || fail "nodes as a normal user"

# launchd: the service takes over from the hand-started daemon
sudo "$B" install
sudo launchctl print system/ai.plugovr.meshvpn | grep -q "state = running" || fail "launchd service not running"
(sudo "$B" --dir "$DB" up > /tmp/b.log 2>&1 &)  # install stopped every hand-started meshvpn
wait_for "maca back as a service" online
sudo "$B" uninstall
sleep 2
! sudo launchctl print system/ai.plugovr.meshvpn >/dev/null 2>&1 || fail "service still loaded after uninstall"
echo "macOS smoke test passed"

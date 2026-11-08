#!/bin/sh
# Certifies a release key with a root key (see src/update.rs): writes release-key.cert, which every
# release carries and `meshvpn update` checks. Run it on the machine with the root key - about once
# a year, before the current certificate expires (the release workflow warns 30 days ahead), or at
# once if the release key leaked (then also put the old key into REVOKED_KEYS in src/update.rs).
#
#   scripts/certify-release-key.sh release-key.pub.pem 400 > release-key.cert
#
# MESHVPN_ROOT_KEY: the root key (default ~/.config/meshvpn-release/release-signing-key.pem;
# a passphrase-protected key asks for the passphrase).
set -eu
pub="${1:?usage: certify-release-key.sh RELEASE_KEY_PUBLIC.pem DAYS}"
days="${2:?usage: certify-release-key.sh RELEASE_KEY_PUBLIC.pem DAYS}"
root="${MESHVPN_ROOT_KEY:-$HOME/.config/meshvpn-release/release-signing-key.pem}"
case "$days" in *[!0-9]*|'') echo "DAYS must be a number" >&2; exit 1 ;; esac
[ "$days" -le 800 ] || { echo "at most 800 days" >&2; exit 1; }
b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
key="$(openssl pkey -pubin -in "$pub" -outform DER | tail -c 32 | b64url)"
expires_ms=$(( ($(date +%s) + days * 86400) * 1000 ))
expires="$(date -u -d "@$((expires_ms / 1000))" +%Y-%m-%d 2>/dev/null || date -u -r "$((expires_ms / 1000))" +%Y-%m-%d)"
printf 'meshvpn release key v1\n%s\n%s\n' "$key" "$expires_ms" > "$tmp/msg"
openssl pkeyutl -sign -inkey "$root" -rawin -in "$tmp/msg" -out "$tmp/sig"
# The root key must be one meshvpn trusts.
rootpub="$(openssl pkey -in "$root" -pubout -outform DER | tail -c 32 | b64url)"
here="$(dirname "$0")/../src/update.rs"
if [ -f "$here" ] && ! grep -q "\"$rootpub\"" "$here"; then
    echo "this root key ($rootpub) is not in ROOT_KEYS ($here)" >&2
    exit 1
fi
printf '{\n  "key": "%s",\n  "expires_ms": %s,\n  "expires": "%s",\n  "sig": "%s"\n}\n' \
    "$key" "$expires_ms" "$expires" "$(b64url < "$tmp/sig")"

#!/bin/sh
# Checks a meshvpn release by hand, as `meshvpn update` does (see SECURITY.md): in a directory with
# the release's SHA256SUMS, SHA256SUMS.sig, release-key.cert (from 0.28.0 on) and the files to
# check, with OpenSSL 3 and jq:
#
#   scripts/verify-release.sh 0.28.0 [DIR]
#
# 1. release-key.cert: a root key (below) certifies the release key until a date.
# 2. SHA256SUMS.sig: the release key (or a root key) signed this version's SHA256SUMS.
# 3. The files match SHA256SUMS.
set -eu
V="${1:?usage: verify-release.sh VERSION [DIR]}"; V="${V#v}"
cd "${2:-.}"
ROOT_KEYS="hHYAO3iLkvQIVXUW8GHBOaGOY-6HqTPAFEH7XofinYk"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
unb64url() { s="$(tr -- '-_' '+/')"; while [ $(( ${#s} % 4 )) -ne 0 ]; do s="$s="; done; printf '%s' "$s" | base64 -d; }
# A raw Ed25519 public key (base64url) as a PEM file OpenSSL reads.
pem() { { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; printf '%s' "$1" | unb64url; } | openssl pkey -pubin -inform DER -out "$2"; }
verify() { openssl pkeyutl -verify -pubin -inkey "$1" -rawin -in "$2" -sigfile "$3" >/dev/null 2>&1; }

{ printf 'meshvpn release v1\n%s\n' "$V"; cat SHA256SUMS; } > "$tmp/msg"
unb64url < SHA256SUMS.sig > "$tmp/sig"
ok=""
for r in $ROOT_KEYS; do
    pem "$r" "$tmp/root.pem"
    if verify "$tmp/root.pem" "$tmp/msg" "$tmp/sig"; then ok="signed by root key $r"; fi
done
if [ -z "$ok" ]; then
    [ -f release-key.cert ] || { echo "FAIL: not signed by a root key, and no release-key.cert"; exit 1; }
    key="$(jq -r .key release-key.cert)"; exp="$(jq -r .expires_ms release-key.cert)"
    printf 'meshvpn release key v1\n%s\n%s\n' "$key" "$exp" > "$tmp/cmsg"
    jq -r .sig release-key.cert | unb64url > "$tmp/csig"
    certified=""
    for r in $ROOT_KEYS; do
        pem "$r" "$tmp/root.pem"
        if verify "$tmp/root.pem" "$tmp/cmsg" "$tmp/csig"; then certified="$r"; fi
    done
    [ -n "$certified" ] || { echo "FAIL: release-key.cert is not signed by a root key"; exit 1; }
    pem "$key" "$tmp/rel.pem"
    verify "$tmp/rel.pem" "$tmp/msg" "$tmp/sig" || { echo "FAIL: SHA256SUMS.sig doesn't verify"; exit 1; }
    ok="signed by release key $key, certified by root key $certified until $(jq -r .expires release-key.cert)"
fi
echo "OK: $V $ok"
sha256sum -c --ignore-missing SHA256SUMS

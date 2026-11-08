#!/bin/sh
# Emergency only - releases are signed by the release workflow (release key, see src/update.rs).
# Signs a published release with a root key: uploads SHA256SUMS.sig, an Ed25519 signature over
#   "meshvpn release v1\n<version>\n" followed by the release's SHA256SUMS
# (see src/update.rs, release_message). Run it on the machine that holds the release key, after
# the release workflow has published the release:
#
#   scripts/sign-release.sh PlugOvr-ai/meshvpn v0.27.0
#
# MESHVPN_RELEASE_KEY: the key (default ~/.config/meshvpn-release/release-signing-key.pem).
# It checks the signature against the public keys in src/update.rs before uploading.
set -eu
repo="${1:?usage: sign-release.sh OWNER/REPO TAG}"
tag="${2:?usage: sign-release.sh OWNER/REPO TAG}"
key="${MESHVPN_RELEASE_KEY:-$HOME/.config/meshvpn-release/release-signing-key.pem}"
case "$tag" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "not a release tag: $tag" >&2; exit 1 ;; esac
[ -r "$key" ] || { echo "no release key at $key" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
gh release download "$tag" -R "$repo" -p SHA256SUMS -D "$tmp"
{ printf 'meshvpn release v1\n%s\n' "${tag#v}"; cat "$tmp/SHA256SUMS"; } > "$tmp/msg"
openssl pkeyutl -sign -inkey "$key" -rawin -in "$tmp/msg" -out "$tmp/sig.bin"
# The signature must verify with the key's public half...
openssl pkey -in "$key" -pubout -out "$tmp/pub.pem"
openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$tmp/msg" -sigfile "$tmp/sig.bin" >/dev/null
# ...and that must be one of the root keys meshvpn trusts.
pub="$(openssl pkey -pubin -in "$tmp/pub.pem" -outform DER | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
here="$(dirname "$0")/../src/update.rs"
if [ -f "$here" ] && ! grep -q "\"$pub\"" "$here"; then
    echo "this key ($pub) is not in ROOT_KEYS ($here)" >&2
    exit 1
fi
base64 < "$tmp/sig.bin" | tr '+/' '-_' | tr -d '=\n' > "$tmp/SHA256SUMS.sig"
gh release upload "$tag" -R "$repo" "$tmp/SHA256SUMS.sig" --clobber
echo "signed $repo $tag ($(grep -c . "$tmp/SHA256SUMS") files)"

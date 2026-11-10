#!/bin/sh
# Builds the packed desktop: Xfce and a browser with everything they need, down to their own C
# library, as one archive that works on any Linux distribution of this CPU architecture. Also the
# archive of their sources, which we have to offer next to it (desktop/legal.py).
#
# Runs inside Nix, whose packages live with all their libraries under /nix/store:
#   docker run --rm -v "$PWD/desktop:/build:ro" -v "$PWD/out:/out" nixos/nix:latest sh /build/build-full.sh
# Output: /out/meshvpn-desktop-full-<arch>.tar.gz, to unpack at / (see desktop/run-header.sh)
#         /out/meshvpn-full-sources-<arch>.tar.gz.partNN (GitHub takes 2 GB per file)
set -eu

# The same revision gives the same desktop. Move it to get a newer browser.
REV="${NIXPKGS_REV:-7dcdd87373d72e7a2173e4db02e20d3d7f495cfd}" # nixos-26.05
ARCH="$(uname -m)"
OUT="${OUT:-/out}"
mkdir -p /etc/nix "$OUT"
printf 'experimental-features = nix-command flakes\nsandbox = false\n' >> /etc/nix/nix.conf

ROOT="$(nix build --no-link --print-out-paths --impure --expr "
  let pkgs = import (builtins.getFlake \"github:NixOS/nixpkgs/$REV\") { system = builtins.currentSystem; };
  in import /build/full.nix { inherit pkgs; }")"
echo "built $ROOT"
# Not all in this image.
for t in gnused gnugrep findutils gnutar coreutils zstd.bin pigz python3; do
    PATH="$(nix build --no-link --print-out-paths "github:NixOS/nixpkgs/$REV#$t")/bin:$PATH"
done
export PATH

L=/tmp/legal
rm -rf "$L"
python3 /build/legal.py "$ROOT" "$L"
STAGE=/tmp/stage
D="$STAGE/opt/meshvpn-desktop-full"
rm -rf "$STAGE" && mkdir -p "$D"
ln -s "$ROOT" "$D/env"
sed 's|^|/|' "$L/members" > "$D/paths"
cp "$L/packages" "$D/packages"
# How old the browser is, for `meshvpn doctor` and the installer: from the revision, so that the
# same revision still gives the same desktop.
cat > "$D/browser" <<EOT
chromium=$(nix eval --raw --impure --expr "(import (builtins.getFlake \"github:NixOS/nixpkgs/$REV\") { system = builtins.currentSystem; }).chromium.version")
nixpkgs=$REV
date=$(nix eval --raw --impure --expr "toString (builtins.getFlake \"github:NixOS/nixpkgs/$REV\").lastModified")
EOT
cat "$D/browser"
cp -r "$L/licenses" "$D/licenses"
cat > "$D/README" <<EOT
meshvpn packed desktop ($ARCH): Xfce and the Chromium browser, from nixpkgs $REV.

packages    what's inside
browser     the browser's version and how old it is
licenses/   each package's licence and copyright files, from its source

Everything is free software under its own licence, with NO WARRANTY. The complete source of all of
it, with the recipes that build it, is published next to the installer you got this from, as
meshvpn-full-sources-$ARCH.tar.gz.part*: https://github.com/PlugOvr-ai/meshvpn/releases
Compilers and other build tools aren't in there: Nix gets those by itself.
Used by \`meshvpn desktop\`; see https://github.com/PlugOvr-ai/meshvpn

Installed without root, the path /nix/store inside these files was replaced by one of the same
length, and nothing else was changed: \`meshvpn desktop relocate\`, src/desktop/bundle.rs in meshvpn.
EOT

NAME="meshvpn-desktop-full-$ARCH.tar.gz"
# gzip: tar and gzip are the only tools every Linux image has.
# u+w: Nix's read-only directories would stop BusyBox's tar without root, which applies them at once.
tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner --mode=u+w --anchored --exclude-from="$L/exclude" \
    -cf - -C "$STAGE" opt -C / -T "$L/members" | pigz -9 > "$OUT/$NAME"
(cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256")
du -sh "$OUT/$NAME"

# The sources: each package's downloads, and nixpkgs with our files, which say how they're built.
SRC=/tmp/src
rm -rf "$SRC" && mkdir -p "$SRC/meshvpn-full-sources/build"
cp /build/full.nix /build/build-full.sh /build/legal.py "$SRC/meshvpn-full-sources/build/"
cp "$L/packages" "$L/report" "$SRC/meshvpn-full-sources/"
cp -r "$(nix eval --raw --impure --expr "(builtins.getFlake \"github:NixOS/nixpkgs/$REV\").outPath")" \
    "$SRC/meshvpn-full-sources/nixpkgs-$REV"
cat > "$SRC/meshvpn-full-sources/README" <<EOT
The complete source of the meshvpn packed desktop ($ARCH).

nix/store/      each package's source archives and patches, with Nix's names for them
nixpkgs-$REV/   how each package is built, with the remaining patches
build/          how the desktop is put together: docker run ... nixos/nix sh build-full.sh
                (with network: Nix gets the compilers and other build tools, which aren't in here)
packages        what's in the desktop
report          what was removed from it, and why
EOT
rm -f "$OUT"/meshvpn-full-sources-"$ARCH".tar.gz.part*
sed 's|^/||' "$L/sources.list" > /tmp/src-members
tar --mtime=@1 --owner=0 --group=0 --numeric-owner -cf /tmp/sources.tar -C "$SRC" meshvpn-full-sources -C / -T /tmp/src-members
pigz -6 < /tmp/sources.tar | split -b 1900M -d - "$OUT/meshvpn-full-sources-$ARCH.tar.gz.part"
rm -f /tmp/sources.tar
# A desktop whose sources went missing must not ship.
TOTAL="$(cat "$OUT"/meshvpn-full-sources-"$ARCH".tar.gz.part* | wc -c)"
[ "$TOTAL" -gt 1000000000 ] || { echo "the source archive is too small: $TOTAL bytes" >&2; exit 1; }
cat "$OUT"/meshvpn-full-sources-"$ARCH".tar.gz.part* | pigz -dc | tar -tf - | grep -q "meshvpn-full-sources/build/full.nix"
(cd "$OUT" && sha256sum meshvpn-full-sources-"$ARCH".tar.gz.part* > "meshvpn-full-sources-$ARCH.sha256")
ls -la "$OUT"

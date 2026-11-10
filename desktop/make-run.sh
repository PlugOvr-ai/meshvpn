#!/bin/sh
# Puts the one-file installer together:
#   make-run.sh <meshvpn binary> <meshvpn-desktop-ARCH.tar.gz> <meshvpn-desktop-full-ARCH.tar.gz> <out dir> <third-party licences>
# Output: <out dir>/meshvpn-full-<ARCH>.run: desktop/run-header.sh and then two gzip archives.
set -eu
BINARY="$1" XBUNDLE="$2" FULL="$3" OUT="$4" NOTICES="$5"
HERE="$(cd "$(dirname "$0")" && pwd)"
ARCH="$(basename "$FULL" | sed 's/^meshvpn-desktop-full-//; s/\.tar\.gz$//')"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/make-run.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

mkdir -p "$WORK/opt/meshvpn-desktop-full"
install -m 0755 "$BINARY" "$WORK/opt/meshvpn-desktop-full/meshvpn"
install -m 0644 "$XBUNDLE" "$WORK/opt/meshvpn-desktop-full/x-bundle.tar.gz"
install -m 0644 "$NOTICES" "$WORK/opt/meshvpn-desktop-full/THIRD-PARTY-LICENSES.txt"
install -m 0644 "$HERE/../LICENSE" "$WORK/opt/meshvpn-desktop-full/LICENSE"
tar --owner=0 --group=0 --numeric-owner -C "$WORK" -czf "$WORK/small.tar.gz" opt

SMALL="$(wc -c < "$WORK/small.tar.gz")"
# The archive doesn't say how much it unpacks to without reading all of it; gzip -l is wrong above 4 GB.
UNPACKED_MB="$(gzip -dc "$FULL" | wc -c | awk '{print int($1 / 1048576) + 200}')"
LINES="$(($(wc -l < "$HERE/run-header.sh") + 1))"
mkdir -p "$OUT"
sed -e "s/@ARCH@/$ARCH/g" -e "s/@UNPACKED_MB@/$UNPACKED_MB/g" -e "s/@HEADER_LINES@/$LINES/g" -e "s/@SMALL_BYTES@/$SMALL/g" \
    "$HERE/run-header.sh" > "$WORK/run"
cat "$WORK/run" "$WORK/small.tar.gz" "$FULL" > "$OUT/meshvpn-full-$ARCH.run"
chmod 755 "$OUT/meshvpn-full-$ARCH.run"
(cd "$OUT" && sha256sum "meshvpn-full-$ARCH.run" > "meshvpn-full-$ARCH.run.sha256")
ls -la "$OUT/meshvpn-full-$ARCH.run"

#!/bin/sh
# Builds the meshvpn desktop bundle: a fully static Xvfb and xkbcomp (no shared libraries,
# so they run in any Linux container, glibc or musl), the keyboard layouts and a few fonts.
#
# Runs inside Alpine (musl, static libraries available):
#   docker run --rm -v "$PWD/desktop:/build" -v "$PWD/out:/out" alpine:3.22 sh /build/build-bundle.sh
# Output: /out/meshvpn-desktop-<arch>.tar.gz (+ .sha256)
set -eu

XSERVER=21.1.19
LIBXAU=1.0.12
LIBFONTENC=1.1.8
LIBXFONT2=2.0.7
LIBXKBFILE=1.1.3
XKBCOMP=1.4.7

ARCH="$(uname -m)"
OUT="${OUT:-/out}"
PREFIX=/opt/x
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/share/pkgconfig"

apk add --no-cache build-base meson ninja pkgconf xorgproto xtrans font-util-dev \
    pixman-dev pixman-static freetype-dev freetype-static zlib-dev zlib-static libpng-static \
    bzip2-static brotli-static libx11-dev libx11-static libxcb-dev libxcb-static nettle-dev \
    nettle-static libbsd-dev libbsd-static libmd xkeyboard-config font-dejavu curl xz tar >/dev/null

mkdir -p /src && cd /src
fetch() { [ -f "$(basename "$1")" ] || curl -fsSLO "$1"; tar xf "$(basename "$1")"; }
fetch "https://www.x.org/releases/individual/lib/libXau-$LIBXAU.tar.xz"
fetch "https://www.x.org/releases/individual/lib/libfontenc-$LIBFONTENC.tar.xz"
fetch "https://www.x.org/releases/individual/lib/libXfont2-$LIBXFONT2.tar.xz"
fetch "https://www.x.org/releases/individual/lib/libxkbfile-$LIBXKBFILE.tar.xz"
fetch "https://www.x.org/releases/individual/app/xkbcomp-$XKBCOMP.tar.xz"
fetch "https://www.x.org/releases/individual/xserver/xorg-server-$XSERVER.tar.xz"

# Static libraries Alpine doesn't ship as such.
for p in "libXau-$LIBXAU" "libfontenc-$LIBFONTENC" "libXfont2-$LIBXFONT2"; do
    (cd "$p" && ./configure --prefix="$PREFIX" --enable-static --disable-shared CFLAGS="-O2 -fPIC" >/dev/null && make -j"$(nproc)" install >/dev/null)
done
(cd "libxkbfile-$LIBXKBFILE" && meson setup b --prefix="$PREFIX" --default-library=static --buildtype=release >/dev/null && ninja -C b install >/dev/null)

# xkbcomp: compiles keyboard layouts for the X server.
(cd "xkbcomp-$XKBCOMP" && ./configure --prefix="$PREFIX" LDFLAGS=-static PKG_CONFIG="pkg-config --static" >/dev/null && make -j"$(nproc)" >/dev/null)

# Xvfb: no GLX/DRI (no dynamic loading in a static binary), no TCP, no XDMCP.
cd "xorg-server-$XSERVER"
# The bundle can live anywhere: meshvpn tells the server where xkbcomp is.
sed -i 's|^    if (XkbBinDirectory != NULL) {|    { const char *e = getenv("MESHVPN_XKB_BIN"); if (e \&\& *e) XkbBinDirectory = e; }\n    if (XkbBinDirectory != NULL) {|' xkb/ddxLoad.c
grep -q MESHVPN_XKB_BIN xkb/ddxLoad.c
# The release tarball lacks parts of the test suite.
sed -i "s/^    subdir('test')/    #subdir('test')/" meson.build
meson setup b --buildtype=release --default-library=static -Dprefer_static=true -Dc_link_args=-static \
    -Dxorg=false -Dxephyr=false -Dxnest=false -Dxvfb=true -Dxwin=false -Dxquartz=false \
    -Dglamor=false -Dglx=false -Dxdmcp=false -Dxdm-auth-1=false -Dsecure-rpc=false \
    -Dudev=false -Dudev_kms=false -Dhal=false -Dsystemd_logind=false -Dpciaccess=false \
    -Ddrm=false -Ddri1=false -Ddri2=false -Ddri3=false -Dxselinux=false -Dlibunwind=false \
    -Ddocs=false -Ddevel-docs=false -Ddocs-pdf=false -Dsha1=libnettle \
    -Dxkb_output_dir=/tmp -Dxkb_bin_dir=/usr/bin -Dxkb_dir=/usr/share/X11/xkb \
    -Ddefault_font_path=built-ins -Dlisten_tcp=false -Dxf86-input-inputtest=false -Dxvmc=false \
    -Dvgahw=false -Ddga=false -Dagp=false -Dint10=false -Dlinux_apm=false -Dlinux_acpi=false >/dev/null
ninja -C b hw/vfb/Xvfb >/dev/null
cd /src

B=/bundle/meshvpn-desktop
rm -rf /bundle && mkdir -p "$B/bin" "$B/share/fonts"
cp "xorg-server-$XSERVER/b/hw/vfb/Xvfb" "xkbcomp-$XKBCOMP/xkbcomp" "$B/bin/"
strip "$B/bin/"*
cp -r /usr/share/X11/xkb "$B/share/xkb"
for f in DejaVuSans DejaVuSans-Bold DejaVuSans-Oblique DejaVuSansMono DejaVuSansMono-Bold DejaVuSerif; do
    cp "/usr/share/fonts/dejavu/$f.ttf" "$B/share/fonts/"
done
cat > "$B/README" <<EOF
meshvpn desktop bundle ($ARCH): static Xvfb $XSERVER, xkbcomp $XKBCOMP (X.Org, MIT/X11
licenses), xkeyboard-config layouts (MIT), DejaVu fonts (Bitstream Vera license).
Used by \`meshvpn desktop\`; see https://github.com/PlugOvr-ai/meshvpn
EOF

mkdir -p "$OUT"
NAME="meshvpn-desktop-$ARCH.tar.gz"
tar -C /bundle -czf "$OUT/$NAME" meshvpn-desktop
(cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256")
ls -la "$OUT"

# The packed desktop: Xfce and a browser with everything they need, down to their own C library.
# Built by desktop/build-full.sh, which also removes what we must not ship (desktop/legal.py).
{ pkgs }:
let
  # From the xfce set by name: top-level `exo` is an unrelated program.
  x = name: pkgs.xfce.${name};

  # Chromium as nixpkgs builds it: H.264 and AAC are compiled into the browser itself, so removing
  # the codec packages (desktop/legal.py) doesn't remove those. Its sandbox needs user namespaces,
  # which default Docker blocks, and it refuses to run as root with one. It then runs without, and
  # shows its warning about that.
  # nixpkgs' start script, without the search paths into GTK4, which isn't shipped (desktop/legal.py)
  # and which Chromium doesn't link to: it uses GTK3 here.
  launcher = pkgs.runCommand "chromium-launcher" { } ''
    mkdir -p $out/bin $out/share
    sed -E 's#:/nix/store/[a-z0-9]{32}-gtk4-[^:"]*##g' ${pkgs.chromium}/bin/chromium > $out/bin/chromium
    chmod +x $out/bin/chromium
    if grep -q -- '-gtk4-' $out/bin/chromium; then
        echo "GTK4 is still in the start script" >&2
        exit 1
    fi
    cp -r --no-preserve=mode ${pkgs.chromium}/share/icons $out/share/icons
  '';
  browser = pkgs.writeShellScriptBin "chromium" ''
    flags=""
    if [ "$(id -u)" = 0 ] || ! ${pkgs.util-linux}/bin/unshare -Ur true 2>/dev/null; then
        flags="--no-sandbox"
    fi
    exec ${launcher}/bin/chromium $flags --disable-dev-shm-usage --disable-gpu --no-first-run \
        --no-default-browser-check --password-store=basic "$@"
  '';
  browserAlias = pkgs.writeShellScriptBin "chromium-browser" ''
    exec ${browser}/bin/chromium "$@"
  '';
  menuEntry = pkgs.writeTextDir "share/applications/chromium-browser.desktop" ''
    [Desktop Entry]
    Version=1.0
    Type=Application
    Name=Chromium
    Icon=chromium
    Exec=chromium %U
    Terminal=false
    Categories=Network;WebBrowser;
    MimeType=text/html;x-scheme-handler/http;x-scheme-handler/https;
  '';

  # What exo-open and the panel's launchers use.
  helpers = pkgs.writeTextDir "etc/xdg/xfce4/helpers.rc" ''
    WebBrowser=chromium
    TerminalEmulator=xfce4-terminal
    FileManager=thunar
  '';
  browserHelper = pkgs.writeTextDir "share/xfce4/helpers/chromium.desktop" ''
    [Desktop Entry]
    Version=1.0
    Type=X-XFCE-Helper
    Name=Chromium
    Icon=chromium
    X-XFCE-Binaries=chromium;
    X-XFCE-Category=WebBrowser
    X-XFCE-Commands=%B;
    X-XFCE-CommandsWithParameter=%B "%s";
  '';
in
pkgs.buildEnv {
  name = "meshvpn-desktop-full";
  paths = [
    (pkgs.hiPrio browser)
    (pkgs.hiPrio browserAlias)
    (pkgs.hiPrio menuEntry)
    (pkgs.lowPrio launcher)
    helpers
    browserHelper
    (x "xfce4-session")
    (x "xfwm4")
    (x "xfce4-panel")
    (x "xfdesktop")
    (x "xfce4-settings")
    (x "xfce4-appfinder")
    (x "xfce4-terminal")
    (x "xfconf")
    (x "exo")
    (x "garcon")
    (x "libxfce4ui")
    (x "thunar")
    pkgs.xfce4-icon-theme
    pkgs.dbus
    pkgs.dconf
    pkgs.adwaita-icon-theme
    pkgs.hicolor-icon-theme
    pkgs.dejavu_fonts
    pkgs.xdg-utils
    pkgs.shared-mime-info
    pkgs.gsettings-desktop-schemas
  ];
  ignoreCollisions = true;
  pathsToLink = [ "/bin" "/share" "/etc" "/lib/xfce4" ];
}

# The packed desktop: Xfce and a browser with everything they need, down to their own C library.
# Built by desktop/build-full.sh, which also removes what we must not ship (desktop/legal.py).
{ pkgs }:
let
  # From the xfce set by name: top-level `exo` is an unrelated program.
  x = name: pkgs.xfce.${name};

  # A browser with no H.264 of its own: it plays that through FFmpeg, which it doesn't get here, and
  # Chromium has it compiled in. It has an AAC decoder of its own, switched off here with MP4. It
  # also doesn't fetch the codec plugins (OpenH264, Widevine).
  browser = pkgs.wrapFirefox (pkgs.librewolf-unwrapped // { ffmpegSupport = false; }) {
    extraPrefs = ''
      lockPref("media.gmp-provider.enabled", false);
      lockPref("media.gmp-gmpopenh264.enabled", false);
      lockPref("media.gmp-widevinecdm.enabled", false);
      lockPref("media.eme.enabled", false);
      lockPref("media.mp4.enabled", false);
    '';
  };

  # What exo-open and the panel's launchers use.
  helpers = pkgs.writeTextDir "etc/xdg/xfce4/helpers.rc" ''
    WebBrowser=librewolf
    TerminalEmulator=xfce4-terminal
    FileManager=thunar
  '';
  browserHelper = pkgs.writeTextDir "share/xfce4/helpers/librewolf.desktop" ''
    [Desktop Entry]
    Version=1.0
    Type=X-XFCE-Helper
    Name=LibreWolf
    Icon=librewolf
    X-XFCE-Binaries=librewolf;
    X-XFCE-Category=WebBrowser
    X-XFCE-Commands=%B;
    X-XFCE-CommandsWithParameter=%B "%s";
  '';
in
pkgs.buildEnv {
  name = "meshvpn-desktop-full";
  paths = [
    browser
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

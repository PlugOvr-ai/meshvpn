#!/usr/bin/env python3
"""What the packed desktop may contain, and what must come with it.

    legal.py <root store path> <output dir>

1. Removes patent-encumbered codecs and everything only they need. Nothing is recompiled: the paths
   are left out of the archive, and files elsewhere that refer to them (plugins nobody here uses)
   too. The build fails if a removed path is still needed by something we can't do without.
2. Writes licenses/: each package's own licence and copyright files, from its source.
3. Writes sources/: the source and patches of each package, plus what's needed to build them.

Output: <dir>/members (store paths to pack), <dir>/exclude (files in them to leave out),
<dir>/licenses/, <dir>/sources.list (store paths of the sources), <dir>/report.
"""
import json
import os
import re
import subprocess
import sys
import tarfile
import zipfile

# Patent pools (H.264, H.265, AAC, MPEG-2, AMR, DTS, AC-3...), their libraries and the plugin sets
# known for them. MP3, FLAC, Vorbis, Opus, VP8, VP9 and AV1 stay. GTK4 is here because its media
# module brings the GStreamer plugins, and nothing we run uses GTK4.
DENY = re.compile(
    r"^(x264|x265|xvid|openh264|ffmpeg|gst-plugins-(bad|ugly)|gst-libav|fdk-aac|faad2|faac|vo-aacenc|"
    r"libde265|opencore-amr|vo-amrwbenc|a52dec|liba52|libdca|libmpeg2|mjpegtools|libdvdcss|libdvdread|"
    r"libdvdnav|ldacbt|libfreeaptx|chromaprint|gtk4)(-|$)",
    re.I,
)
# Nothing may refer to a removed path in these, or the desktop wouldn't start.
NO_DANGLING = re.compile(r"^(xfce4-|xfwm4|xfdesktop|thunar|exo|garcon|libxfce|mate-|marco|caja|libmate|chromium|glibc|gtk\+3|glib-|dbus)")
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense|patents|mpl|gpl|lgpl)", re.I)
# Where those without such a file state their terms: Perl modules in their README, libdrm in its headers.
STATED_IN = re.compile(r"^(readme|xf86drm\.h|.*\.pod$)", re.I)


def sh(*args, ok=False):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if p.returncode and not ok:
        sys.exit(f"failed: {' '.join(args)}")
    return p.stdout


def name(path):
    return os.path.basename(path).split("-", 1)[1]


def prune(root):
    """Everything reachable from root without passing through a denied package."""
    keep, drop, todo = set(), set(), [root]
    while todo:
        p = todo.pop()
        if p in keep or p in drop:
            continue
        if DENY.match(name(p)):
            drop.add(p)
            continue
        keep.add(p)
        todo += [r for r in sh("nix-store", "-q", "--references", p).split() if r != p]
    return keep, drop


def referring_files(keep, drop):
    """Files in what we keep that name something removed."""
    pattern = "|".join(os.path.basename(p)[:32] for p in drop)
    files = set(sh("grep", "-rlaE", pattern, *sorted(keep), ok=True).split("\n")) - {""}
    for p in keep:
        for line in sh("find", p, "-type", "l", "-printf", "%p\t%l\n").splitlines():
            link, target = line.split("\t", 1)
            if re.search(pattern, target):
                files.add(link)
    return files


def sources_of(paths):
    """path -> the fixed-output inputs (downloads: tarballs, patches, vendored dependencies) of its derivation."""
    out, unknown = {}, []
    for p in sorted(paths):
        drv = sh("nix-store", "-q", "--deriver", p, ok=True).strip()
        if not drv.endswith(".drv") or not os.path.exists(drv):
            unknown.append(p)
            continue
        out[p] = fixed_inputs(drv, 3) or deep_inputs(drv)
    return out, unknown


FOD_CACHE = {}


def drv_json(drv):
    if drv not in FOD_CACHE:
        data = json.loads(sh("nix", "derivation", "show", drv))
        data = data.get("derivations", data)
        FOD_CACHE[drv] = next(iter(data.values()))
    return FOD_CACHE[drv]


def fixed_inputs(drv, depth):
    d = drv_json(drv)
    found = set()
    inputs = d.get("inputDrvs", {})
    if isinstance(d.get("inputs"), dict):
        inputs = d["inputs"].get("drvs", inputs)
    for i in inputs:
        i = i if i.startswith("/") else "/nix/store/" + i
        o = drv_json(i).get("outputs", {}).get("out", {})
        if "hash" in o or "hashAlgo" in o or "method" in o:
            found.add(i)
        elif depth > 0 and re.search(r"(source|src|patched|vendor|deps)", os.path.basename(i)):
            # A source tree that was prepared first.
            found |= fixed_inputs(i, depth - 1)
    return found


def deep_inputs(drv):
    """For what has no download of its own (parts cut from a bigger package): that package's, if
    one input is named like it. Toolchains and wrappers stay out."""
    stem = re.sub(r"-[0-9].*$", "", os.path.basename(drv).split("-", 1)[1]).removesuffix(".drv")
    d = drv_json(drv)
    inputs = d.get("inputDrvs", {})
    if isinstance(d.get("inputs"), dict):
        inputs = d["inputs"].get("drvs", inputs)
    found = set()
    for i in inputs:
        i = i if i.startswith("/") else "/nix/store/" + i
        other = os.path.basename(i).split("-", 1)[1]
        if other.split("-")[0] in stem or stem.split("-")[0] in other:
            found |= fixed_inputs(i, 3)
    return found


def licence_name(member, pattern=LICENCE_FILE):
    """Licence files at the top of a source tree or one level down (archives have one top directory)."""
    parts = member.split("/")
    return len(parts) <= 3 and pattern.match(parts[-1])


def write_licence(dest, member, data):
    target = os.path.join(dest, member.replace("/", "_"))
    with open(target, "wb") as fh:
        fh.write(data)


def copy_licences(src, dest, pattern=LICENCE_FILE):
    """A package's licence files, from a source directory or archive. Returns how many."""
    os.makedirs(dest, exist_ok=True)
    count = 0
    if os.path.isdir(src):
        for base, dirs, files in os.walk(src):
            rel = os.path.relpath(base, src)
            if rel.count("/") > 1:
                dirs[:] = []
                continue
            for f in files:
                member = os.path.normpath(os.path.join(rel, f))
                full = os.path.join(base, f)
                if licence_name(member, pattern) and os.path.isfile(full):
                    with open(full, "rb") as fh:
                        write_licence(dest, member, fh.read())
                    count += 1
    elif zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            for member in z.namelist():
                if not member.endswith("/") and licence_name(member, pattern):
                    write_licence(dest, member, z.read(member))
                    count += 1
    else:
        try:
            if src.endswith(".zst"):
                pipe = subprocess.Popen(["zstd", "-dc", src], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                tar = tarfile.open(fileobj=pipe.stdout, mode="r|")
            else:
                tar = tarfile.open(src)
            with tar:
                for m in tar:
                    if m.isfile() and licence_name(m.name.removeprefix("./"), pattern):
                        write_licence(dest, m.name.removeprefix("./"), tar.extractfile(m).read())
                        count += 1
        except (tarfile.TarError, OSError, EOFError):
            pass  # A patch or a single file, not an archive.
    return count


def main():
    root, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    report = []
    keep, drop = prune(root)
    report.append(f"kept {len(keep)} store paths, removed {len(drop)}: " + " ".join(sorted(map(name, drop))))
    closure = set(sh("nix-store", "-qR", root).split())
    unreachable = closure - keep - drop
    report.append(f"no longer needed by anything: {len(unreachable)}: " + " ".join(sorted(map(name, unreachable))))
    if drop:
        files = referring_files(keep, drop)
    else:
        files = set()
    bad = sorted(f for f in files if NO_DANGLING.match(name("/nix/store/" + f.split("/")[3])) and not f.endswith((".pc", ".la", ".cmake")))
    report.append(f"files left out, they refer to something removed: {len(files)}")
    report += ["  " + f for f in sorted(files)]
    with open(os.path.join(out, "members"), "w") as fh:
        fh.write("\n".join(sorted(p.lstrip("/") for p in keep)) + "\n")
    with open(os.path.join(out, "exclude"), "w") as fh:
        fh.write("\n".join(sorted(f.lstrip("/") for f in files)) + "\n")
    with open(os.path.join(out, "packages"), "w") as fh:
        fh.write("\n".join(sorted({name(p) for p in keep})) + "\n")

    srcs, unknown = sources_of(keep)
    report.append(f"no derivation known (generated from nixpkgs or unusual): {len(unknown)}: " + " ".join(map(name, unknown)))
    all_inputs = sorted(set().union(*srcs.values()))
    realised = {}
    failed = []
    for i in all_inputs:
        o = sh("nix-store", "-r", i, ok=True).split()
        if o:
            realised[i] = o[0]
        else:
            failed.append(i)
    report.append(f"sources: {len(realised)}, could not be fetched: {len(failed)}: " + " ".join(os.path.basename(f) for f in failed))
    with open(os.path.join(out, "sources.list"), "w") as fh:
        fh.write("\n".join(sorted(realised.values())) + "\n")

    no_source, no_licence = [], []
    lic = os.path.join(out, "licenses")
    for p, inputs in sorted(srcs.items()):
        package = name(p)
        real = [realised[i] for i in inputs if i in realised]
        if not real:
            no_source.append(package)
            continue
        n = sum(copy_licences(r, os.path.join(lic, package)) for r in real) or sum(
            copy_licences(r, os.path.join(lic, package), STATED_IN) for r in real
        )
        if not n:
            no_licence.append(package)
            try:
                os.rmdir(os.path.join(lic, package))
            except OSError:
                pass
    report.append(f"packages with no source of their own (wrappers and generated files, in nixpkgs): {len(no_source)}: " + " ".join(no_source))
    report.append(f"packages with no licence file in their source: {len(no_licence)}: " + " ".join(no_licence))
    # Most have to be found, or this isn't working. The ones left are checked by hand against this list.
    if len(no_licence) > len(srcs) // 10:
        bad.append(f"licence files not found for {len(no_licence)} of {len(srcs)} packages")
    if failed:
        bad.append("sources that could not be fetched")
    if bad:
        report.append("ERROR:\n  " + "\n  ".join(bad))
    with open(os.path.join(out, "report"), "w") as fh:
        fh.write("\n".join(report) + "\n")
    print("\n".join(report))
    if bad:
        sys.exit(1)


main()

#!/usr/bin/env python3
"""Does the published source archive of the packed desktop hold what it says it holds?

    tests/sources/check.py --dir <downloads> --arch x86_64 --work <empty dir, ~15 GB free>

<downloads> holds meshvpn-full-<arch>.run and meshvpn-full-sources-<arch>.tar.gz.part*, as published.
Needs Docker. Without network, from the archive alone, in a bare Nix image:

1. The recipe in the archive (its nixpkgs and build/) gives exactly the store path the installer ships.
2. Every path the installer ships is something that recipe produces.
3. Every download of every shipped package is in the archive, with the hash the recipe asks for.

Also lists the downloads the archive leaves out: those of the tools that build the packages
(compilers, build systems), which the licences don't ask for. Exit code 1 if 1, 2 or 3 fail.
Whether it all really compiles is a longer job: see rebuild.py.
"""
import argparse
import base64
import glob
import json
import os
import re
import subprocess
import sys

IMAGE = "nixos/nix:latest"


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, text=True, **kw).stdout


def shipped(run):
    """(root store path, shipped store paths) out of the installer, without unpacking all of it."""
    head = open(run, "rb").read(4096).decode("latin-1")
    lines = int(re.search(r"^LINES=(\d+)$", head, re.M).group(1))
    small = int(re.search(r"^SMALL=(\d+)$", head, re.M).group(1))
    full = f"tail -n +{lines} '{run}' | tail -c +{small + 1}"
    # The stage comes first in the archive; --occurrence stops tar there, the pipe's end is expected.
    paths = subprocess.run(f"{full} | tar -xzO --occurrence=1 opt/meshvpn-desktop-full/paths", shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.split()
    listing = subprocess.run(f"{full} | tar -tvz --occurrence=1 opt/meshvpn-desktop-full/env", shell=True,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
    root = listing.strip().split(" -> ")[-1]
    return root, paths


def docker(work, script):
    """A bare Nix image, no network, the archive read-only: nothing else can help."""
    return subprocess.run(
        ["docker", "run", "--rm", "-i", "--network", "none", "-v", f"{work}:/work", IMAGE, "sh", "-eu"],
        input=script, text=True, check=True, stdout=subprocess.PIPE).stdout


def inputs_of(d):
    i = d.get("inputDrvs", {})
    if isinstance(d.get("inputs"), dict):
        i = d["inputs"].get("drvs", i)
    return [x if x.startswith("/") else "/nix/store/" + x for x in i]


def outputs_of(d):
    """Output paths of a derivation, in either form Nix writes."""
    out = []
    for o in d.get("outputs", {}).values():
        p = o.get("path")
        if p:
            out.append(p if p.startswith("/") else "/nix/store/" + p)
    return out


def fixed(d):
    """(algorithm, flat?, hash) of a download, None for anything else."""
    o = d.get("outputs", {}).get("out", {})
    if "hash" not in o:
        return None
    algo = o.get("hashAlgo", "sha256")
    method = o.get("method", "")
    if algo.startswith("r:"):
        algo, method = algo[2:], "nar"
    elif algo.startswith("text:"):
        algo, method = algo[5:], "text"
    return algo, method == "flat", o["hash"], method


def to_hex(h):
    """Nix writes hashes in hex or as sha256-<base64>."""
    if "-" in h[:8]:
        return base64.b64decode(h.split("-", 1)[1]).hex()
    return h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--arch", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    os.makedirs(work, exist_ok=True)
    system = f"{a.arch}-linux"
    problems = []

    root, paths = shipped(os.path.join(a.dir, f"meshvpn-full-{a.arch}.run"))
    if not root.startswith("/nix/store/") or len(paths) < 50:
        sys.exit(f"can't read the installer: root {root!r}, {len(paths)} paths")
    print(f"the installer ships {root} and {len(paths)} store paths")

    if not os.path.exists(f"{work}/meshvpn-full-sources"):
        parts = sorted(glob.glob(os.path.join(a.dir, f"meshvpn-full-sources-{a.arch}.tar.gz.part*")))
        print(f"unpacking {len(parts)} parts...", flush=True)
        sh("cat " + " ".join(f"'{p}'" for p in parts) + f" | tar -xz -C '{work}'")
    nixpkgs = os.path.basename(glob.glob(f"{work}/meshvpn-full-sources/nixpkgs-*")[0])

    # All in one run: what instantiating writes is gone with the container.
    docker(work, f"""
        export NIX_CONFIG='experimental-features = nix-command flakes'
        drv="$(nix-instantiate --expr 'import /work/meshvpn-full-sources/build/full.nix {{
            pkgs = import /work/meshvpn-full-sources/{nixpkgs} {{ system = "{system}"; }}; }}')"
        echo "$drv" > /work/root.drv
        nix derivation show --recursive "$drv" > /work/graph.json
        # This Nix leaves the paths of downloads out of what it shows: ask for all of them.
        for d in $(nix-store -qR "$drv"); do
            case "$d" in *.drv) echo "$d"; nix-store -q --outputs "$d" ;; esac
        done > /work/outputs
    """)
    graph = json.load(open(f"{work}/graph.json"))
    graph = graph.get("derivations", graph)
    graph = {(k if k.startswith("/") else "/nix/store/" + k): v for k, v in graph.items()}
    current = None
    known = {}
    for line in open(f"{work}/outputs").read().split():
        if line.endswith(".drv"):
            current = line
        else:
            known.setdefault(current, []).append(line)
    for k, d in graph.items():
        for name, o in d.get("outputs", {}).items():
            if not o.get("path"):
                outs = known.get(k, [])
                o["path"] = outs[0] if len(outs) == 1 else next(x for x in outs if name == "out" or x.endswith("-" + name))
    drv = open(f"{work}/root.drv").read().strip()
    built = outputs_of(graph[drv])
    print(f"the recipe in the archive gives {built}, from {len(graph)} derivations")

    # 1
    if root not in built:
        problems.append(f"the recipe gives {built}, the installer ships {root}")

    # 2
    by_output = {o: k for k, d in graph.items() for o in outputs_of(d)}
    strangers = [p for p in paths if p not in by_output]
    if strangers:
        problems.append(f"shipped, but not from this recipe: {strangers}")

    # 3
    shipped_drvs = {by_output[p] for p in paths if p in by_output}

    def downloads(drv, depth=3, seen=None):
        """A package's downloads: its own, and those of source trees prepared for it."""
        seen = set() if seen is None else seen
        found = set()
        for i in inputs_of(graph[drv]):
            if i in seen:
                continue
            seen.add(i)
            if fixed(graph[i]):
                found.add(i)
            elif depth and i not in shipped_drvs and re.search(r"(source|src|patched|vendor|deps)", os.path.basename(i)):
                found |= downloads(i, depth - 1, seen)
        return found

    wanted = {}
    for d in shipped_drvs:
        for f in downloads(d):
            wanted.setdefault(f, set()).add(d)
    every = {k for k, d in graph.items() if fixed(d)}
    # Wrappers and generated files have none, and anything else must be looked at by a person.
    nothing = sorted(os.path.basename(d)[33:].removesuffix(".drv") for d in shipped_drvs if not downloads(d))

    def in_archive(f):
        return os.path.lexists(f"{work}/{outputs_of(graph[f])[0].lstrip('/')}")

    missing = sorted(f for f in wanted if not in_archive(f))
    for f in missing:
        names = sorted(os.path.basename(x)[33:] for x in wanted[f])
        problems.append(f"not in the archive: {os.path.basename(f)[33:]}, needed by {names}")

    # The hashes, of everything in the archive that the recipe knows.
    check = sorted(f for f in every if in_archive(f))
    jobs = []
    for f in check:
        algo, flat, want, method = fixed(graph[f])
        if method in ("git", "text"):
            continue
        jobs.append((outputs_of(graph[f])[0], algo, flat, want))
    print(f"hashing {len(jobs)} downloads...", flush=True)
    script = "export NIX_CONFIG='experimental-features = nix-command flakes'\n"
    for path, algo, flat, _ in jobs:
        script += f"nix-hash --type {algo} --base16 {'--flat ' if flat else ''}/work{path}\n"
    got = docker(work, script).split()
    for (path, _, _, want), have in zip(jobs, got):
        if to_hex(want) != have:
            problems.append(f"wrong hash: {path}: wants {want}, is {have}")
    if len(got) != len(jobs):
        problems.append(f"hashed {len(got)} of {len(jobs)}")

    extra = sorted(os.path.basename(p) for p in glob.glob(f"{work}/nix/store/*")
                   if "/nix/store/" + os.path.basename(p) not in {outputs_of(graph[f])[0] for f in every})
    left_out = sorted(os.path.basename(f)[33:].removesuffix(".drv") for f in every if not in_archive(f))
    summary = {
        "root": root,
        "shipped_paths": len(paths),
        "derivations": len(graph),
        "downloads_of_shipped_packages": len(wanted),
        "downloads_in_the_build": len(every),
        "hashes_checked": len(jobs),
        "in_archive_but_not_in_recipe": extra,
        "shipped_without_a_download": nothing,
        "left_out": left_out,
        "problems": problems,
    }
    plan = {
        "nixpkgs": nixpkgs,
        "system": system,
        "shipped_drvs": sorted(shipped_drvs),
        "all_chosen": sorted(shipped_drvs),
        "sources": [
            {"path": outputs_of(graph[f])[0], "algo": fixed(graph[f])[0], "recursive": not fixed(graph[f])[1]}
            for f in check
            if fixed(graph[f])[3] not in ("git", "text")
        ],
    }
    with open(f"{work}/rebuild-plan.json", "w") as fh:
        json.dump(plan, fh)
    with open(f"{work}/result.json", "w") as fh:
        json.dump(summary, fh, indent=1)
    print(f"downloads of shipped packages: {len(wanted)}; all downloads of the whole build: {len(every)}")
    print(f"hashes checked: {len(jobs)}; in the archive but not in the recipe: {len(extra)}")
    print(f"downloads left out (tools that build the packages): {len(left_out)}; full list in {work}/result.json")
    print(f"shipped, with no download of their own: {len(nothing)}: {' '.join(nothing)}")
    for p in problems:
        print("PROBLEM:", p)
    print("OK" if not problems else f"{len(problems)} problems")
    sys.exit(1 if problems else 0)


main()

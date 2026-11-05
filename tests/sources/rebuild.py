#!/usr/bin/env python3
"""Compiles the packed desktop's packages from the published source archive.

    tests/sources/rebuild.py --work <dir check.py used> [--only regex] [-j jobs]

Run tests/sources/check.py first: this builds on what it unpacked and worked out. Hours of work with
Chromium, and only for the architecture of this machine. Three steps, in Docker:

1. Network on: the sources go into a new Nix store from the archive. The tools that compile them
   (compilers, build systems) and the packages themselves come from cache.nixos.org.
2. The sources are checked again: what's in the store must be what's in the archive.
3. Network off: every chosen package is compiled again (nix-store --check), and compared with
   what the first build gave. With no network, nothing else can have supplied a source.

"Differs" is a package that compiled but not to the same bytes: the source is there, the build
isn't reproducible. "Failed" is one that didn't compile. Exit code 1 if any failed.

What this doesn't show: the tools were taken from the cache rather than built from nothing (the
archive leaves their sources out, see check.py), so this isn't a full bootstrap.
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys

IMAGE = "nixos/nix:latest"
CONF = "experimental-features = nix-command flakes\nsandbox = false\nmax-jobs = {jobs}\ncores = 0\nfallback = false\n"


def docker(work, store, script, network=True, log=None):
    cmd = ["docker", "run", "--rm", "-i", "-v", f"{work}:/work", "-v", f"{store}:/nix"]
    if not network:
        cmd += ["--network", "none"]
    return subprocess.run(cmd + [IMAGE, "sh", "-eu"], input=script, text=True, stdout=log or subprocess.PIPE,
                          stderr=subprocess.STDOUT if log else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--only", help="packages to compile, a regex on their names (default: all shipped)")
    ap.add_argument("-j", type=int, default=4, help="packages at once")
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    store = f"{work}/rebuild-nix"
    conf = CONF.format(jobs=a.j)

    plan = json.load(open(f"{work}/rebuild-plan.json"))
    drvs = [d for d in plan["shipped_drvs"] if not a.only or re.search(a.only, os.path.basename(d)[33:])]
    if not drvs:
        sys.exit("nothing to compile")
    print(f"{len(drvs)} packages, {len(plan['sources'])} sources", flush=True)

    if not os.path.exists(f"{store}/store"):
        os.makedirs(store, exist_ok=True)
        subprocess.run(["docker", "run", "--rm", "-v", f"{store}:/new", IMAGE, "sh", "-c", "cp -a /nix/. /new/"], check=True)

    # Each source gets the path Nix expects only if its name and contents are right.
    add = ""
    for s in plan["sources"]:
        flag = "--recursive " if s["recursive"] else ""
        name = os.path.basename(s["path"])[33:]
        # (Valid from an earlier run: added by this same step, as the store is new.)
        add += (f"if ! nix-store --check-validity {s['path']} 2>/dev/null; then\n"
                f"rm -rf /tmp/a; mkdir /tmp/a; cp -a /work{s['path']} /tmp/a/{shlex.quote(name)}\n"
                f"got=\"$(nix-store --add-fixed {flag}{s['algo']} /tmp/a/{shlex.quote(name)})\"\n"
                f"[ \"$got\" = {s['path']} ] || {{ echo \"not what the recipe asks for: $got\"; exit 1; }}\nfi\n")
    all_drvs = " ".join(plan["all_chosen"] if not a.only else drvs)
    with open(f"{work}/rebuild-1.log", "w") as log:
        p = docker(work, store, f"""
            mkdir -p /etc/nix; cat > /etc/nix/nix.conf <<'EOC'
{conf}EOC
            {add}
            nix-instantiate --expr 'import /work/meshvpn-full-sources/build/full.nix {{
                pkgs = import /work/meshvpn-full-sources/{plan["nixpkgs"]} {{ system = "{plan["system"]}"; }}; }}' > /dev/null
            # What --check compares with, and what it compiles with.
            nix-store --realise {all_drvs} > /dev/null
            for d in {all_drvs}; do
                for r in $(nix-store -q --references "$d"); do
                    case "$r" in *.drv) nix-store --realise "$r" > /dev/null ;; esac
                done
            done
            echo STEP1-OK
        """, log=log)
    if p.returncode:
        os.system(f"tail -20 '{work}/rebuild-1.log'")
        sys.exit("step 1 failed")
    print("step 1 done: sources from the archive, tools and first builds from the cache", flush=True)

    with open(f"{work}/rebuild-2.log", "w") as log:
        p = docker(work, store, f"""
            mkdir -p /etc/nix; cat > /etc/nix/nix.conf <<'EOC'
{conf}EOC
            nix-store --verify-path {" ".join(s["path"] for s in plan["sources"])}
            for d in {" ".join(drvs)}; do
                if nix-store --realise --check --keep-going "$d" > /tmp/o 2>&1; then
                    echo "SAME $d"
                else
                    cat /tmp/o
                    echo "NOTSAME $d"
                fi
            done
        """, network=False, log=log)
    text = open(f"{work}/rebuild-2.log", errors="replace").read()
    same = re.findall(r"^SAME (\S+)", text, re.M)
    differ, failed = [], []
    start = 0
    for m in re.finditer(r"^(SAME|NOTSAME) (\S+)$", text, re.M):
        if m.group(1) == "NOTSAME":
            # Nix's wording for "it built, and came out different".
            (differ if "may not be deterministic" in text[start:m.start()] else failed).append(m.group(2))
        start = m.end()
    name = lambda d: os.path.basename(d)[33:].removesuffix(".drv")
    result = {"same": sorted(map(name, same)), "differs": sorted(map(name, differ)), "failed": sorted(map(name, failed))}
    json.dump(result, open(f"{work}/rebuild-result.json", "w"), indent=1)
    print(f"compiled with no network: {len(same)} same, {len(differ)} differ, {len(failed)} failed, of {len(drvs)}")
    print("failed:", " ".join(result["failed"]))
    print("differ:", " ".join(result["differs"]))
    sys.exit(1 if failed or p.returncode or len(same) + len(differ) + len(failed) != len(drvs) else 0)


main()

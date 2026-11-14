#!/usr/bin/env python3
"""What reading a volume's chunks from another node costs: throughput and CPU of both daemons,
without a network limit (the containers' bridge), so the software is what limits.

    tests/volume/bench.py --binary meshvpn-musl [--files 3072] [--perf IMAGE] [--keep]

Two nodes, a volume on both with one copy of each chunk, files of one chunk each (4 MB) copied
in. Node a then reads (through /volumes, i.e. FUSE) the files whose chunk is on b only - every
byte crosses to a - once with one reader, once with eight (`cat`, the page cache cold: every
file is read once). CPU: user+system seconds of each daemon during the reads, per GB.

--perf IMAGE: an image FROM meshvpn-e2e with linux-perf installed, and a binary built with its
symbols (CARGO_PROFILE_RELEASE_STRIP=false): prints where both daemons spend their time while
eight read (perf in the containers, which get CAP_SYSLOG for the kernel's symbols).
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e"))
import run as e2e  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CHUNK = 4 << 20


def cpu(node):
    """User+system seconds the daemon has used."""
    out = node.sh("cat /proc/$(pidof meshvpn)/stat").split(")")[-1].split()
    return (int(out[11]) + int(out[12])) / os.sysconf("SC_CLK_TCK")


def here(node, name):
    for d in node.mvj("volume list")["volumes"]:
        if d["name"] == name:
            return d["here"] or {}
    return {}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--files", type=int, default=3072, help="files of 4 MB copied in")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--out", help="append the results as a JSON line here")
    ap.add_argument("--perf", metavar="IMAGE", help="the test image with linux-perf in it: profiles both daemons "
                    "while eight read (the binary needs its symbols)")
    a = ap.parse_args()
    e2e.BINARY = os.path.abspath(a.binary)
    print("building the test image...", flush=True)
    e2e.run(["docker", "build", "-q", "-t", e2e.IMAGE, os.path.join(HERE, "..", "e2e")], timeout=900)
    image = a.perf or e2e.IMAGE
    lab = e2e.Lab("volume_bench")
    ok = False
    try:
        gb = int(a.files * CHUNK * 2 // 1e9 + 2)
        extra = e2e.FUSE + ["--tmpfs", f"/var/lib/meshvpn/volumes:rw,size={gb}g"]
        if a.perf:
            extra += ["--cap-add", "SYSLOG"]  # the kernel's symbols for perf
        net = lab.network("net")
        na, nb = (lab.node(n, [net], extra=extra, image=image) for n in ("a", "b"))
        na.mv(f"init --name a --endpoint {na.c}:7870")
        na.up()
        nb.mv(f"join {e2e.invite(na)} --name b")
        nb.up()
        e2e.wait(lambda: na.online("b"), "b online")
        # The chunks go over the LAN path once the nodes have found it.
        time.sleep(30)
        na.mv("volume create bench --nodes a,b --copies 1")
        e2e.wait(lambda: here(na, "bench").get("leading") and here(nb, "bench").get("mounted"), "volume up", 60)
        na.sh(f"mkdir -p /root/up && for i in $(seq 1 {a.files}); do head -c {CHUNK} /dev/urandom > /root/up/f$i; done",
              timeout=900)
        # Copying in needs SSH access to b (a publishes root's key within half a minute).
        na.sh("mkdir -p ~/.ssh && ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/id_ed25519")
        nb.mv("ssh allow root@a --as root")
        # (eight files: at least one has its chunk on b)
        e2e.wait(lambda: na.sh("meshvpn volume cp " + " ".join(f"/root/up/f{i}" for i in range(1, 9)) + " bench:probe",
                               ok=False).returncode == 0, "a may copy in", 90)
        out = na.mvj("volume cp /root/up bench:", timeout=1800)
        print(f"copied in: {out['files']} files, {out['bytes'] / 1e9:.1f} GB at {out['mb_s']:.0f} MB/s", flush=True)
        na.sh("rm -rf /root/up")
        # The files whose chunk only b has.
        ids = set(nb.sh("ls /var/lib/meshvpn/volumes/*/").split())
        man = json.loads(na.sh("cat /etc/meshvpn/volumes/bench-*.json", timeout=60))
        remote = sorted(f"/volumes/bench/{f['path']}" for f in man["files"]
                        if f["id"] in ids and not f["path"].startswith("probe"))
        e2e.wait(lambda: na.sh(f"test -f {remote[-1]} && echo y", ok=False).stdout.strip() == "y", "a sees them", 30)
        half = len(remote) // 2
        results = {"files": a.files, "remote_files": len(remote)}
        for name, files, par in (("1 reader", remote[:half], 1), ("8 readers", remote[half:], 8)):
            na.sh("printf '%s\\n' " + " ".join(files) + " > /tmp/list")
            before = here(na, "bench")["read_remote_bytes"], cpu(na), cpu(nb)
            prof = a.perf and par > 1
            if prof:
                for n in (na, nb):
                    n.sh("(perf record -F 499 -p $(pidof meshvpn) -o /tmp/perf.data > /tmp/perf.log 2>&1 &)")
                time.sleep(1)
            t = time.time()
            na.sh(f"xargs -P{par} -n8 cat < /tmp/list > /dev/null", timeout=1800)
            secs = time.time() - t
            if prof:
                for n, who in ((na, "reader"), (nb, "server")):
                    n.sh("kill -INT $(pidof perf); while pidof perf > /dev/null; do sleep 0.2; done")
                    rep = n.sh("perf report -i /tmp/perf.data --stdio --no-children --sort sym 2>/dev/null "
                               "| grep -v '^#' | grep -v '^$' | head -40", timeout=300)
                    print(f"--- perf, {who} (a):\n{rep}" if who == "reader" else f"--- perf, {who} (b):\n{rep}", flush=True)
            after = here(na, "bench")["read_remote_bytes"], cpu(na), cpu(nb)
            got = after[0] - before[0]
            want = len(files) * CHUNK
            r = results[name] = {
                "mb_s": round(want / secs / 1e6), "secs": round(secs, 2),
                "remote_share": round(got / want, 3),
                "cpu_a_s_per_gb": round((after[1] - before[1]) / (want / 1e9), 2),
                "cpu_b_s_per_gb": round((after[2] - before[2]) / (want / 1e9), 2),
            }
            print(f"{name}: {want / 1e9:.1f} GB in {secs:.1f} s = {r['mb_s']} MB/s "
                  f"({r['remote_share']:.0%} from b); CPU per GB: reader {r['cpu_a_s_per_gb']} s, "
                  f"server {r['cpu_b_s_per_gb']} s", flush=True)
        if a.out:
            with open(a.out, "a") as f:
                f.write(json.dumps(results) + "\n")
        ok = True
    finally:
        if ok or not a.keep:
            lab.cleanup()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

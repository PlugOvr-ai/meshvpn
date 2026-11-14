#!/usr/bin/env python3
"""A simulated GPU cluster for meshvpn's volumes: network storage that is the bottleneck, and
nodes that read a dataset as a training job would - straight from the storage, then from a volume
filled from it (`meshvpn volume create --from`); and a node outside the group (a laptop) that
copies files in (`meshvpn volume cp`).

    tests/volume/sim.py --binary meshvpn-musl --data /media/data/meshvpn-dataset-sim [--rate 1gbit] [--nodes 3]

- storage: a container serving DATA/export over SSH, its link limited to --rate (1 ms delay);
- nodes: meshvpn nodes with the storage at /mnt/storage (sshfs, 4 connections), a RAM disk as
  "SSD" for their chunks and a memory limit, so neither the dataset nor their share fits their
  page cache;
- data (made once in DATA/export): small (many 128 kB files) and large (512 MB files, read as
  1 MB samples at random places);
- per variant: 2 epochs from the storage, then `volume create --from`, 1 epoch while the nodes
  copy, the copy's time, 2 epochs from /volumes; then one epoch with a node gone;
- a node outside the group copies 2 GB (32 files of 64 MB) into a new volume; the nodes read it.
An epoch takes as long as its slowest rank (the others wait at the next all-reduce).
"""
import argparse
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e"))
import run as e2e  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VARIANTS = {"small": (40_000, 128 * 1024), "large": (10, 512 << 20)}
UPLOAD = (32, 64 << 20)


def make_data(export):
    for name, (count, size) in VARIANTS.items():
        d = os.path.join(export, name)
        done = os.path.join(export, f".{name}.done")
        if os.path.exists(done):
            continue
        print(f"making {name}: {count} files of {size >> 10} kB...", flush=True)
        for i in range(count):
            sub = os.path.join(d, f"{i // 1000:03d}")
            os.makedirs(sub, exist_ok=True)
            with open(os.path.join(sub, f"{i:06d}.bin"), "wb") as f:
                left = size
                while left:
                    n = min(left, 8 << 20)
                    f.write(os.urandom(n))
                    left -= n
        open(done, "w").close()
    up = os.path.join(os.path.dirname(export), "upload")
    if not os.path.exists(os.path.join(up, ".done")):
        os.makedirs(os.path.join(up, "run"), exist_ok=True)
        for i in range(UPLOAD[0]):
            with open(os.path.join(up, "run", f"part{i:02d}.bin"), "wb") as f:
                f.write(os.urandom(UPLOAD[1]))
        open(os.path.join(up, ".done"), "w").close()


def epoch(nodes, root, mode, n):
    """One epoch on all nodes at once; (seconds of the slowest rank, MB/s over all ranks, per rank)."""
    out = [None] * len(nodes)

    def go(r, node):
        line = node.sh(f"python3 /usr/local/bin/loader.py {root} {mode} {r} {len(nodes)} {n}", timeout=3600)
        out[r] = json.loads(line.strip().splitlines()[-1])
    threads = [threading.Thread(target=go, args=(r, nd)) for r, nd in enumerate(nodes)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    secs = max(o["secs"] for o in out)
    total = sum(o["bytes"] for o in out)
    return {"secs": secs, "mb_s": round(total / secs / 1e6, 1), "ranks": out}


def here(node, name):
    for d in node.mvj("volume list")["volumes"]:
        if d["name"] == name:
            return d["here"] or {}
    return {}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--data", required=True, help="host directory for the generated dataset")
    ap.add_argument("--rate", default="1gbit", help="the storage's link (tc netem rate)")
    ap.add_argument("--nodes", type=int, default=3)
    ap.add_argument("--memory", default="8g", help="memory limit of each node (page cache and RAM disk)")
    ap.add_argument("--ssd", default="6g", help="size of each node's RAM disk for its chunks")
    ap.add_argument("--variants", default="small,large")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--out", help="write the results as JSON here")
    a = ap.parse_args()
    e2e.BINARY = os.path.abspath(a.binary)
    export = os.path.join(os.path.abspath(a.data), "export")
    make_data(export)
    print("building the test image...", flush=True)
    e2e.run(["docker", "build", "-q", "-t", e2e.IMAGE, os.path.join(HERE, "..", "e2e")], timeout=900)
    lab = e2e.Lab("volume_sim")
    results = {"rate": a.rate, "nodes": a.nodes, "memory": a.memory}
    ok = False
    try:
        names = [f"gpu{i + 1}" for i in range(a.nodes)]
        up = os.path.join(os.path.dirname(export), "upload")
        extra = ["--memory", a.memory, "--tmpfs", f"/var/lib/meshvpn/volumes:rw,size={a.ssd}", "-v", f"{up}:/upload:ro"]
        _, storage, every = e2e.storage_cluster(lab, names + ["laptop"], export=export, rate=a.rate, node_extra=extra)
        nodes, laptop = every[:-1], every[-1]
        for n in nodes:
            e2e.run(["docker", "cp", os.path.join(HERE, "loader.py"), f"{n.c}:/usr/local/bin/loader.py"])
        # The nodes find their LAN paths (the chunks go there, not through the tunnel).
        time.sleep(30)
        for v in a.variants.split(","):
            mode = v
            r = results[v] = {}
            print(f"\n== {v}", flush=True)
            for i in (1, 2):
                r[f"storage_epoch{i}"] = e = epoch(nodes, f"/mnt/storage/{v}", mode, i)
                print(f"from the storage, epoch {i}: {e['secs']:.0f} s, {e['mb_s']} MB/s", flush=True)
            start = time.time()
            nodes[0].mv(f"volume create {v} --nodes {','.join(names)} --from /mnt/storage/{v}", timeout=3600)
            e2e.wait(lambda: all(n.sh(f"test -d /volumes/{v} && echo y", ok=False).stdout.strip() == "y" for n in nodes),
                     "mounted everywhere", 600)
            r["list_secs"] = round(time.time() - start, 1)
            print(f"volume create, mounted everywhere (the first node lists the files): {r['list_secs']} s", flush=True)
            r["copying_epoch"] = e = epoch(nodes, f"/volumes/{v}", mode, 3)
            print(f"while the nodes copy, epoch 3: {e['secs']:.0f} s, {e['mb_s']} MB/s", flush=True)
            e2e.wait(lambda: all(here(n, v).get("staged") for n in nodes), "copied everywhere", 7200, interval=5)
            r["copy_secs"] = time.time() - start
            r["copy"] = [here(n, v) for n in nodes]
            print(f"copied after {r['copy_secs']:.0f} s from volume create", flush=True)
            for i in (4, 5):
                r[f"cached_epoch{i}"] = e = epoch(nodes, f"/volumes/{v}", mode, i)
                print(f"from /volumes, epoch {i}: {e['secs']:.0f} s, {e['mb_s']} MB/s", flush=True)
            r["reads"] = [here(n, v) for n in nodes]
        # A laptop (outside the group) copies files in: 2 copies of each chunk on the nodes.
        nodes[0].mv(f"volume create scratch --nodes {','.join(names)}")
        e2e.wait(lambda: all(here(n, "scratch").get("mounted") for n in nodes), "scratch mounted", 120)
        out = laptop.mvj("volume cp /upload/run scratch:", timeout=3600)
        results["upload"] = out
        print(f"\nlaptop -> volume (2 copies): {out['files']} files, {out['bytes'] / 1e9:.1f} GB in {out['seconds']:.0f} s "
              f"({out['mb_s']:.0f} MB/s)", flush=True)
        e2e.wait(lambda: all(n.sh("ls /volumes/scratch/run 2>/dev/null | wc -l").strip() == str(UPLOAD[0]) for n in nodes),
                 "every node sees the files", 60)
        results["upload_read"] = e = epoch(nodes, "/volumes/scratch", "large", 7)
        print(f"reading them on the nodes: {e['secs']:.0f} s, {e['mb_s']} MB/s", flush=True)
        # A node gone: its share comes from the storage (the job goes on with the others).
        v = a.variants.split(",")[0]
        nodes[-1].stop()
        rest = nodes[:-1]
        results["node_gone"] = e = epoch(rest, f"/volumes/{v}", v, 6)
        print(f"\n{names[-1]} gone, {v}, epoch 6 on {len(rest)} nodes: {e['secs']:.0f} s, {e['mb_s']} MB/s", flush=True)
        # Same bytes as the storage (a sample of files).
        for n in rest:
            cmd = (f"cd /mnt/storage/{v} && find . -type f | sort | awk 'NR % 97 == 1' | xargs sha256sum > /tmp/a && "
                   f"cd /volumes/{v} && sha256sum -c --quiet /tmp/a && echo same")
            e2e.check(n.sh(cmd, timeout=1800).strip().endswith("same"), f"{n.name}: other bytes")
        print("the bytes are the same as on the storage (sample of files, every node)", flush=True)
        ok = True
    finally:
        if a.out:
            with open(a.out, "w") as f:
                json.dump(results, f, indent=1)
        if ok or not a.keep:
            lab.cleanup()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

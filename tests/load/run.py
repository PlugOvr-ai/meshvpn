#!/usr/bin/env python3
"""Load test: how meshvpn's mesh behaves with many nodes (docs/design-scaling.md, step 0).

One Docker container per node (userspace mode, no TUN), all on one Docker network, in one
managed network. For each size it measures:

  * join:      how long until a few sample nodes see all others online,
  * at rest:   bytes/s in and out of each container (its eth0) and CPU and memory of meshvpn,
               over a fixed window after the mesh has settled,
  * new node:  how long until the sample nodes see one more node that joins,
  * records:   size of the saved state (all node records) per node.

    tests/load/run.py --binary target/x86_64-unknown-linux-musl/release/meshvpn 20 50 100

Results are printed as a table and appended to tests/load/results.jsonl. Containers are named
meshload-* and removed afterwards (also after Ctrl+C).
"""

import argparse
import concurrent.futures as cf
import json
import os
import random
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = "debian:stable-slim"
PREFIX = "meshload"


def run(args, ok=True, timeout=300, input=None):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input)
    if ok and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args)[:200]} -> {p.returncode}: {p.stdout}{p.stderr}")
    return p


def sh(c, cmd, ok=True, timeout=120):
    return run(["docker", "exec", c, "sh", "-c", cmd], ok=ok, timeout=timeout).stdout


def status(c):
    return json.loads(sh(c, "meshvpn --json status", timeout=60))


def online_peers(c):
    try:
        return {p["name"] for p in status(c)["peers"] if p.get("online")}
    except Exception:  # noqa: BLE001 - a busy node may not answer in time
        return set()


def cleanup():
    ids = run(["docker", "ps", "-aq", "--filter", f"name=^{PREFIX}-"], ok=False).stdout.split()
    if ids:
        run(["docker", "rm", "-f"] + ids, ok=False, timeout=600)
    run(["docker", "network", "rm", f"{PREFIX}-net"], ok=False)


def start_container(name, binary):
    c = f"{PREFIX}-{name}"
    run(["docker", "run", "-d", "--name", c, "--hostname", name, "--network", f"{PREFIX}-net",
         IMAGE, "sleep", "infinity"])
    run(["docker", "cp", binary, f"{c}:/usr/local/bin/meshvpn"])
    return c


def up(c):
    run(["docker", "exec", "-d", c, "sh", "-c", "meshvpn up >> /var/log/meshvpn.log 2>&1"])
    deadline = time.time() + 60
    while time.time() < deadline:
        if run(["docker", "exec", c, "meshvpn", "status"], ok=False, timeout=30).returncode == 0:
            return
        time.sleep(0.5)
    raise RuntimeError(f"{c}: meshvpn didn't start")


def join(name, binary, invite):
    c = start_container(name, binary)
    sh(c, f"meshvpn join {invite} --name {name}")
    up(c)
    return c


def counters(c):
    """(rx bytes, tx bytes, meshvpn CPU seconds, RSS kB) of a container."""
    out = sh(c, "cat /sys/class/net/eth0/statistics/rx_bytes /sys/class/net/eth0/statistics/tx_bytes; "
                "p=$(for d in /proc/[0-9]*; do [ \"$(cat $d/comm 2>/dev/null)\" = meshvpn ] && echo ${d#/proc/}; done | sort -n | head -1); cut -d' ' -f14,15 /proc/$p/stat; grep VmRSS /proc/$p/status", timeout=60)
    lines = out.split("\n")
    ut, st = map(int, lines[2].split())
    rss = int(lines[3].split()[1])
    return int(lines[0]), int(lines[1]), (ut + st) / os.sysconf("SC_CLK_TCK"), rss


def why_missing(c, names):
    """For a sample that misses nodes: which of them it has no record of, and which it has
    a record of but not online (with how long ago it last heard of them)."""
    try:
        peers = {p["name"]: p for p in status(c)["peers"]}
    except Exception:  # noqa: BLE001
        return "no status"
    me = c.split("-", 1)[1]
    unknown = sorted(n for n in names if n != me and n not in peers)
    offline = sorted(f"{n}({peers[n].get('last_seen_secs')})" for n in names if n in peers and not peers[n].get("online"))
    return f"{me}: no record {len(unknown)} {unknown[:5]}, offline {len(offline)} {offline[:5]}"


def wait_all_seen(samples, names, timeout, verbose=False):
    """Seconds until every sample node sees all `names` online, or None; and the last fraction."""
    t0, frac, told = time.time(), 0.0, 0.0
    with cf.ThreadPoolExecutor(len(samples)) as ex:
        while time.time() - t0 < timeout:
            if verbose and time.time() - told >= 20:
                told = time.time()
                for line in ex.map(lambda c: why_missing(c, names), samples):
                    print(f"  {time.time() - t0:5.0f}s {line}", flush=True)
            seen = list(ex.map(online_peers, samples))
            frac = min(len(names & (s | {sname})) / len(names) for s, sname in zip(seen, [x.split("-", 1)[1] for x in samples]))
            if frac >= 1.0:
                return time.time() - t0, 1.0
            time.sleep(2)
    return None, frac


def measure(n, binary, window, settle, parallel, old_binary=None, old_share=0.0, verbose=False):
    cleanup()
    run(["docker", "network", "create", f"{PREFIX}-net"])
    names = [f"n{i:03d}" for i in range(n)]
    hub = start_container(names[0], binary)
    sh(hub, f"meshvpn init --name {names[0]} --network load --endpoint {hub}:7870")
    up(hub)
    invite = json.loads(sh(hub, f"meshvpn --json invite --uses {n + 5} --expires 2h"))["invite"]

    t_start = time.time()
    with cf.ThreadPoolExecutor(parallel) as ex:
        # With --old-binary, every k-th node runs the older version (a network in mid-upgrade).
        old = set(names[1:][::max(1, round(1 / old_share))]) if old_binary and old_share > 0 else set()
        containers = [hub] + list(ex.map(lambda nm: join(nm, old_binary if nm in old else binary, invite), names[1:]))
    t_started = time.time() - t_start

    samples = [hub] + random.sample(containers[1:], min(4, n - 1))
    if old:  # sample both versions
        samples = [hub] + random.sample([c for c in containers[1:] if c.split("-", 1)[1] in old], min(2, len(old))) \
            + random.sample([c for c in containers[1:] if c.split("-", 1)[1] not in old], min(2, n - 1 - len(old)))
    t_join, frac = wait_all_seen(samples, set(names), timeout=max(300, 3 * n), verbose=verbose)
    res = {"nodes": n, "old_nodes": len(old), "start_s": round(t_started, 1),
           "converge_s": None if t_join is None else round(t_join, 1), "converged_frac": round(frac, 3)}

    time.sleep(settle)
    with cf.ThreadPoolExecutor(32) as ex:
        a = dict(zip(containers, ex.map(counters, containers)))
        t0 = time.time()
        time.sleep(window)
        b = dict(zip(containers, ex.map(counters, containers)))
        dt = time.time() - t0
    rx = [(b[c][0] - a[c][0]) / dt for c in containers]
    tx = [(b[c][1] - a[c][1]) / dt for c in containers]
    cpu = [100 * (b[c][2] - a[c][2]) / dt for c in containers]
    rss = [b[c][3] / 1024 for c in containers]
    res.update({
        "rx_kBps_median": round(statistics.median(rx) / 1000, 1), "rx_kBps_max": round(max(rx) / 1000, 1),
        "tx_kBps_median": round(statistics.median(tx) / 1000, 1), "tx_kBps_max": round(max(tx) / 1000, 1),
        "cpu_pct_median": round(statistics.median(cpu), 2), "cpu_pct_max": round(max(cpu), 2),
        "rss_MB_median": round(statistics.median(rss), 1), "rss_MB_max": round(max(rss), 1),
        "total_MBps": round(sum(rx) / 1e6, 2),
    })
    state = int(sh(hub, "stat -c %s /etc/meshvpn/state.json"))
    res["state_kB"] = round(state / 1000, 1)
    res["record_bytes"] = round(state / n)

    # One more node: how long until the samples see it.
    extra = "x999"
    t0 = time.time()
    join(extra, binary, invite)
    t_new, _ = wait_all_seen(samples, {extra}, timeout=300)
    res["new_node_s"] = None if t_new is None else round(time.time() - t0, 1)
    cleanup()
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True, help="static meshvpn binary (musl)")
    ap.add_argument("--window", type=int, default=120, help="seconds to measure at rest")
    ap.add_argument("--settle", type=int, default=60, help="seconds to wait after joining before measuring")
    ap.add_argument("--parallel", type=int, default=16, help="nodes joining at the same time")
    ap.add_argument("--old-binary", help="an older meshvpn binary for some of the nodes")
    ap.add_argument("--old-share", type=float, default=0.5, help="share of nodes running --old-binary")
    ap.add_argument("-v", "--verbose", action="store_true", help="while joining, say what the samples miss")
    ap.add_argument("sizes", nargs="+", type=int)
    args = ap.parse_args()
    # Linux keeps one ARP table for all containers: a full mesh of N containers needs N*(N-1) entries.
    need = max(args.sizes) * (max(args.sizes) + 4)
    with open("/proc/sys/net/ipv4/neigh/default/gc_thresh3") as f:
        have = int(f.read())
    if have < need:
        sys.exit(f"the host's ARP table holds {have} entries, {need} are needed (nodes would lose each other).\n"
                 f"Raise it until the next reboot:  sudo sysctl -w net.ipv4.neigh.default.gc_thresh3={need} "
                 f"net.ipv4.neigh.default.gc_thresh2={need // 2} net.ipv4.neigh.default.gc_thresh1={need // 4}")
    run(["docker", "pull", "-q", IMAGE])
    version = run(["git", "-C", HERE, "describe", "--tags", "--dirty"], ok=False).stdout.strip() or "unknown"
    results = []
    try:
        for n in args.sizes:
            print(f"--- {n} nodes", flush=True)
            r = measure(n, os.path.abspath(args.binary), args.window, args.settle, args.parallel,
                        args.old_binary and os.path.abspath(args.old_binary), args.old_share, args.verbose)
            r.update({"version": version, "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "window_s": args.window})
            print(json.dumps(r), flush=True)
            with open(os.path.join(HERE, "results.jsonl"), "a") as f:
                f.write(json.dumps(r) + "\n")
            results.append(r)
    finally:
        cleanup()
    cols = ["nodes", "converge_s", "new_node_s", "rx_kBps_median", "rx_kBps_max", "tx_kBps_median",
            "cpu_pct_median", "cpu_pct_max", "rss_MB_median", "total_MBps", "record_bytes"]
    print("\n| " + " | ".join(cols) + " |\n|" + "---|" * len(cols))
    for r in results:
        print("| " + " | ".join(str(r.get(c)) for c in cols) + " |")


if __name__ == "__main__":
    sys.exit(main())

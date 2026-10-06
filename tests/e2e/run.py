#!/usr/bin/env python3
"""End-to-end tests: real meshvpn nodes in Docker containers.

Every test builds its own little network of containers (with its own Docker networks),
exercises a feature the way a user or agent would, and cleans up.

    tests/e2e/run.py --binary target/x86_64-unknown-linux-musl/release/meshvpn [-j 4] [test ...]

The binary must be static (musl) or match the container's libc. Needs Docker, with containers
allowed to use NET_ADMIN and /dev/net/tun (GitHub's ubuntu runners can).
"""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import random
import string
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = "meshvpn-e2e"
BINARY = None
DESKTOP_BUNDLE = None
DEPLOY_SH = os.path.join(HERE, "..", "..", "deploy.sh")
INSTALL_SH = os.path.join(HERE, "..", "..", "install.sh")
TESTS = {}
print_lock = threading.Lock()


def test(fn):
    TESTS[fn.__name__.removeprefix("test_")] = fn
    return fn


class Failed(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Failed(msg)


def run(args, input=None, timeout=300, ok=True):
    p = subprocess.run(args, input=input, capture_output=True, timeout=timeout,
                       text=isinstance(input, str) or input is None)
    if ok and p.returncode != 0:
        raise Failed(f"{' '.join(args)[:300]} -> exit {p.returncode}\n{p.stdout}{p.stderr}")
    return p


def wait(fn, what, timeout=60, interval=1.0):
    """Waits until fn() is truthy; returns its value."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:  # noqa: BLE001 - keep waiting, report the last error
            last = e
        time.sleep(interval)
    raise Failed(f"timed out after {timeout}s waiting for: {what}" + (f" (last error: {last})" if last else ""))


class Node:
    def __init__(self, lab, name, container):
        self.lab, self.name, self.c = lab, name, container

    def sh(self, cmd, user=None, ok=True, timeout=180, input=None):
        args = ["docker", "exec", "-i"] + (["-u", user, "-w", f"/home/{user}"] if user else []) + [self.c, "sh", "-c", cmd]
        p = run(args, input=input, timeout=timeout, ok=ok)
        return p if not ok else p.stdout

    def mv(self, args, user=None, ok=True, timeout=180):
        return self.sh(f"meshvpn {args}", user=user, ok=ok, timeout=timeout)

    def mvj(self, args, user=None, timeout=180):
        return json.loads(self.mv(f"--json {args}", user=user, timeout=timeout))

    def up(self, env=""):
        run(["docker", "exec", "-d", self.c, "sh", "-c", f"{env} meshvpn up >> /var/log/meshvpn.log 2>&1"])
        wait(lambda: self.sh("meshvpn status >/dev/null 2>&1 && echo ok", ok=False).stdout.strip() == "ok",
             f"{self.name}: meshvpn running", timeout=30, interval=0.5)

    def stop(self):
        self.sh("pkill -x meshvpn; while pgrep -x meshvpn >/dev/null; do sleep 0.2; done; true", timeout=60)

    def status(self):
        return self.mvj("status")

    def peer(self, name):
        for p in self.status()["peers"]:
            if p["name"] == name:
                return p
        return None

    def online(self, name):
        p = self.peer(name)
        return bool(p and p["online"])

    def ip(self):
        return self.status()["ip"]

    def net_ip(self, network):
        return run(["docker", "inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
                    self.c]).stdout.strip()

    def log(self):
        return self.sh("cat /var/log/meshvpn.log 2>/dev/null || true")

    def fake_gpus(self, gpus):
        """gpus: [(name, mem_total, mem_used, util)] - an nvidia-smi stand-in."""
        rows = "\\n".join(f"{i}, {n}, {t}, {u}, {p}, 550.54" for i, (n, t, u, p) in enumerate(gpus))
        script = f"""#!/bin/sh
case "$1" in --query-gpu=*) printf '{rows}\\n' ;; *) echo "| CUDA Version: 12.4 |" ;; esac
"""
        self.sh("cat > /usr/local/bin/nvidia-smi && chmod 755 /usr/local/bin/nvidia-smi", input=script)


class Lab:
    def __init__(self, test):
        self.prefix = f"e2e-{test.replace('_', '')}-{''.join(random.choices(string.ascii_lowercase, k=4))}"
        self.containers, self.networks = [], []

    def network(self, name, internal=False, subnet=None):
        full = f"{self.prefix}-{name}"
        args = ["docker", "network", "create"] + (["--internal"] if internal else []) + \
            (["--subnet", subnet] if subnet else []) + [full]
        run(args)
        self.networks.append(full)
        return full

    def node(self, name, networks, caps=True, sysctls=(), ip=None, install=True, net_admin=False, cmd=None):
        c = f"{self.prefix}-{name}"
        args = ["docker", "run", "-d", "--name", c, "--hostname", name, "--network", networks[0]]
        if ip:
            args += ["--ip", ip]
        if caps:
            args += ["--cap-add", "NET_ADMIN", "--device", "/dev/net/tun"]
        elif net_admin:
            args += ["--cap-add", "NET_ADMIN"]
        for s in sysctls:
            args += ["--sysctl", s]
        run(args + [IMAGE] + (cmd or []))
        self.containers.append(c)
        for n in networks[1:]:
            run(["docker", "network", "connect", n, c])
        node = Node(self, name, c)
        if install:
            run(["docker", "cp", BINARY, f"{c}:/usr/local/bin/meshvpn"])
            node.sh("chown root:root /usr/local/bin/meshvpn && chmod 755 /usr/local/bin/meshvpn")
        return node

    def cleanup(self):
        if self.containers:
            run(["docker", "rm", "-f"] + self.containers, ok=False)
        for n in self.networks:
            run(["docker", "network", "rm", n], ok=False)


def invite(admin, args=""):
    return admin.mvj(f"invite {args}")["invite"]


def mesh(lab, names, net=None, tags=None, join_args="", admin_args=""):
    """A managed network: the first name is the admin (endpoint = its container name)."""
    net = net or lab.network("net")
    nodes = [lab.node(n, [net]) for n in names]
    hub = nodes[0]
    hub.mv(f"init --name {hub.name} --endpoint {hub.c}:7870 {admin_args}")
    hub.up()
    for n in nodes[1:]:
        t = f"--tag {tags}" if tags else ""
        n.mv(f"join {invite(hub)} --name {n.name} {t} {join_args}")
        n.up()
    for n in nodes[1:]:
        wait(lambda n=n: hub.online(n.name), f"{n.name} online at {hub.name}")
    return net, nodes


def ping(a, ip, count=2):
    return a.sh(f"ping -c{count} -W3 -i0.3 {ip}", ok=False).returncode == 0


def sha(node, path, user=None):
    return node.sh(f"cd {path} && find . -type f | sort | xargs sha256sum | sha256sum | cut -c1-16", user=user).strip()


# =============================================================================================
# Tests


@test
def test_basics(lab):
    """Join, ping by IP and name, status/nodes JSON, stable exit codes, rename."""
    _, (hub, a, b) = mesh(lab, ["hub", "a", "b"])
    wait(lambda: a.online("b"), "a sees b")
    check(ping(a, b.ip()), "a can't ping b")
    check(ping(a, "b.mesh"), "names don't resolve (b.mesh)")
    check(len(a.mvj("nodes")) == 3, "nodes --json should list 3 nodes")
    p = a.mv("nodes nope", ok=False)
    check(p.returncode == 5, f"unknown node should exit 5, got {p.returncode}")
    p = a.sh("meshvpn status", user="agent", ok=False)
    check(p.returncode == 0, "status should work without root")
    # rename (also guards against the v0.5.0 hang: say() calling itself)
    out = b.mv("rename bee", timeout=20)
    check("renamed b -> bee" in out, f"rename output: {out}")
    wait(lambda: a.online("bee"), "a sees the new name")
    check(ping(a, "bee.mesh"), "new name doesn't resolve")


@test
def test_admin_invites(lab):
    """Managed networks: single-use, expiring, forged invites; admin-only actions; admin changes."""
    net, (hub, a) = mesh(lab, ["hub", "a"])
    check(hub.mvj("admin status")["managed"], "new networks should be managed")
    reused = invite(hub)
    b = lab.node("b", [net])
    b.mv(f"join {reused} --name b")
    b.up()
    wait(lambda: hub.online("b"), "b admitted")
    c = lab.node("c", [net])
    c.mv(f"join {reused} --name c")
    c.up()
    time.sleep(8)
    check(not hub.online("c"), "a second node got in with a single-use invite")
    wait(lambda: "already been used" in (c.status().get("turned_away") or ""), "c is told why", 20)
    check("membership" in c.mv("doctor", ok=False).stdout, "doctor should show why c is not admitted")
    # network key only
    raw = json.loads(base64.urlsafe_b64decode(invite(hub)[6:] + "=="))
    raw.pop("ticket"), raw.pop("admins")
    forged = "mesh1-" + base64.urlsafe_b64encode(json.dumps(raw).encode()).decode().rstrip("=")
    d = lab.node("d", [net])
    d.mv(f"join {forged} --name d")
    d.up()
    time.sleep(8)
    check(not hub.online("d"), "a node with only the network key got in")
    check("not admitted" in hub.log(), "refused attempts should be logged at the admin")
    wait(lambda: "needs an invite" in (d.status().get("turned_away") or ""), "d is told why", 20)
    # expired: refused right away, the existing setup stays
    expired = invite(hub, "--expires 2s")
    time.sleep(4)
    before = c.sh("cat /etc/meshvpn/config.toml")
    p = c.mv(f"join --force {expired} --name c2", ok=False)
    check(p.returncode != 0 and "expired" in p.stderr, f"joining with an expired invite should fail: {p.stderr}")
    check(c.sh("cat /etc/meshvpn/config.toml") == before, "a refused join must not change the config")
    # admin-only actions
    check(a.mv("invite", ok=False).returncode != 0, "a member could invite")
    check(a.mv("ban b", ok=False).returncode != 0, "a member could ban")
    # admin changes
    hub.mv("admin add a")
    wait(lambda: a.mv("invite", ok=False).returncode == 0, "a can invite once it is admin", timeout=20)
    a.mv("admin rm hub")
    wait(lambda: hub.mv("invite", ok=False).returncode != 0, "hub can't invite after removal", timeout=20)


@test
def test_witness(lab):
    """A member that was offline while someone joined accepts the newcomer after the invite expired."""
    net, (hub, a) = mesh(lab, ["hub", "a"])
    a.stop()
    n = lab.node("n", [net])
    n.mv(f"join {invite(hub, '--expires 8s')} --name n")
    n.up()
    wait(lambda: hub.online("n"), "n admitted")
    time.sleep(12)
    a.up()
    wait(lambda: a.online("n"), "a accepts n via the hub's witness", timeout=60)


@test
def test_ban(lab):
    """Ban rotates the key; an offline member catches up; the banned node can't come back."""
    net, (hub, a, bad) = mesh(lab, ["hub", "a", "bad"])
    pre_ban = invite(hub)
    a.stop()
    out = hub.mv("ban bad")
    check("banned bad" in out, out)
    wait(lambda: not hub.online("bad"), "bad dropped")
    a.up()
    wait(lambda: a.online("hub"), "a reconnects after the key change", timeout=60)
    # The new key is saved right after the reconnect, not necessarily before.
    wait(lambda: a.sh("grep -c '^key_version = 1' /etc/meshvpn/config.toml", ok=False).stdout.strip() == "1",
         "a saves the new key", 15)
    # An unused invite from before the ban carries the old key: worthless now, even with a new identity.
    bad.stop()
    bad.mv(f"join --force {pre_ban} --name sneaky")
    bad.up()
    time.sleep(10)
    check(not hub.online("sneaky"), "a banned machine got back in with an invite from before the ban")
    wait(lambda: "key changed" in (bad.status().get("turned_away") or ""), "sneaky is told why", 20)
    # A fresh invite from the admin works (that is the admin's decision).
    bad.stop()
    bad.mv(f"join --force {invite(hub)} --name newcomer")
    bad.up()
    wait(lambda: hub.online("newcomer"), "a new invite after the ban works", timeout=40)


@test
def test_nat_traversal(lab):
    """Two clients behind separate NAT routers get a direct UDP path; falls back when UDP is blocked."""
    pub = lab.network("pub", subnet="198.51.100.0/24")
    nets = {x: lab.network(f"lan{x}", internal=True) for x in "AB"}
    hub = lab.node("hub", [pub], ip="198.51.100.10")
    routers, clients = {}, {}
    for x in "AB":
        r = lab.node(f"nat{x}", [pub, nets[x]], caps=False, net_admin=True,
                     sysctls=["net.ipv4.ip_forward=1"], install=False)
        out_if = r.sh("ip -o -4 addr | awk '/198.51.100/ {print $2}'").strip()
        pub_ip = r.net_ip(pub)
        # A typical home router: one public port per internal port, unsolicited packets dropped.
        r.sh(f"""
            iptables -t nat -A POSTROUTING -o {out_if} -p udp --sport 7870 -j SNAT --to-source {pub_ip}:7870
            iptables -t nat -A POSTROUTING -o {out_if} -j MASQUERADE
            iptables -A INPUT -i {out_if} -m conntrack --ctstate NEW,INVALID -j DROP
        """)
        routers[x] = r
        c = lab.node(f"client{x.lower()}", [nets[x]])
        c.sh(f"ip route add default via {r.net_ip(nets[x])}")
        clients[x] = c
    hub.mv(f"init --name hub --endpoint 198.51.100.10:7870")
    hub.up()
    for c in clients.values():
        c.mv(f"join {invite(hub)} --name {c.name}")
        c.up()
    a, b = clients["A"], clients["B"]
    wait(lambda: a.online("clientb"), "clients see each other", timeout=60)
    wait(lambda: "UDP" in (a.peer("clientb") or {}).get("path", ""), "direct UDP path between the NATs", timeout=90)
    bip = b.ip()
    # works without the hub
    hub.stop()
    time.sleep(3)
    check(ping(a, bip, 3), "direct path broke without the hub")
    hub.up()
    wait(lambda: a.online("hub"), "hub back")
    # block UDP between the routers: falls back to the relay
    b_pub = routers["B"].net_ip(pub)
    routers["A"].sh(f"iptables -I FORWARD -p udp -s {b_pub} -j DROP; iptables -I FORWARD -p udp -d {b_pub} -j DROP")
    a.sh(f"ping -c 200 -i 0.2 {bip} >/dev/null 2>&1 &")
    wait(lambda: "relay" in (a.peer("clientb") or {}).get("path", ""), "fallback to the relay", timeout=30)
    # The other side notices a few seconds later (once our traffic reaches it over the relay).
    wait(lambda: ping(a, bip, 2), "connectivity over the relay", timeout=30)


@test
def test_userspace(lab):
    """A container without NET_ADMIN/TUN: userspace mode, incoming TCP to local services, SOCKS and ssh out."""
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False)
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    box.mv(f"join {invite(hub)} --name box")
    box.up()
    wait(lambda: hub.online("box"), "box online")
    check(box.status().get("socks"), "box should run in userspace mode")
    box.sh("mkdir -p /srv && echo hello-box > /srv/index.html && (cd /srv && python3 -m http.server 8080 >/dev/null 2>&1 &)")
    hub.sh("mkdir -p /srv && echo hello-hub > /srv/index.html && (cd /srv && python3 -m http.server 8000 >/dev/null 2>&1 &)")
    time.sleep(1)
    check(ping(hub, "box.mesh"), "ping into userspace mode")
    check(wait(lambda: "hello-box" in hub.sh("curl -s -m5 http://box.mesh:8080/", ok=False).stdout, "http into the box", 20), "")
    p = hub.sh("curl -s -m5 http://box.mesh:9999/", ok=False)
    check(p.returncode == 7, f"closed port should be refused (curl 7), got {p.returncode}")
    out = hub.sh("for i in $(seq 10); do curl -s -m8 http://box.mesh:8080/ & done; wait", ok=False).stdout
    check(out.count("hello-box") == 10, f"parallel requests in: {out.count('hello-box')}/10")
    out = box.sh("curl -s -m5 -x socks5h://127.0.0.1:1055 http://hub.mesh:8000/")
    check("hello-hub" in out, "SOCKS out of the box")
    # integrity both ways
    hub.sh("head -c 20000000 /dev/urandom > /tmp/d")
    want = hub.sh("sha256sum /tmp/d | cut -c1-16").strip()
    box.sh("(nc -l -p 5000 | sha256sum | cut -c1-16 > /tmp/in) &")
    time.sleep(1)
    hub.sh("nc -N box.mesh 5000 < /tmp/d")
    wait(lambda: box.sh("cat /tmp/in", ok=False).stdout.strip() == want, "20 MB intact into the box", 30)


@test
def test_ssh_logins(lab):
    """Password-less SSH: per user, everyone, deny; keys only work from their node over the mesh."""
    net, (server, laptop) = mesh(lab, ["server", "laptop"])
    laptop.sh("useradd -m -s /bin/bash alice; useradd -m -s /bin/bash eve; "
              "for u in alice eve; do su $u -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'; done")
    server.sh("useradd -m -s /bin/bash bob")
    server.mv("ssh allow alice@laptop --as bob")
    wait(lambda: "alice@laptop" in server.mv("ssh-authorized-keys bob"), "server learns alice's key", 60)
    o = "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5"
    login = lambda user, target: laptop.sh(f"su {user} -c 'ssh {o} {target} whoami'", ok=False).stdout.strip()  # noqa: E731
    check(login("alice", "bob@server.mesh") == "bob", "alice -> bob should work")
    check(login("eve", "bob@server.mesh") != "bob", "eve must not get in")
    check(login("alice", "root@server.mesh") != "root", "alice must not get root")
    check(login("alice", f"bob@{server.net_ip(net)}") != "bob", "the key must only work over the mesh")
    server.mv("ssh deny alice@laptop")
    check(login("alice", "bob@server.mesh") != "bob", "deny didn't take effect")
    server.mv("ssh allow everyone --as bob")
    check(login("eve", "bob@server.mesh") == "bob", "allow everyone didn't take effect")


@test
def test_exec_cp(lab):
    """exec on tags with exit codes; cp up and down with intact data."""
    net, (ctl, g1, g2) = mesh(lab, ["ctl", "g1", "g2"], tags="gpu", join_args="--ssh-allow-all agent")
    ctl.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    for g in (g1, g2):
        wait(lambda g=g: "agent@ctl" in g.mv("ssh-authorized-keys agent"), f"{g.name} learns ctl's key", 60)
    r = ctl.mvj("exec tag:gpu -- hostname", user="agent")
    check(r["ok"] and sorted(x["stdout"].strip() for x in r["results"]) == ["g1", "g2"], f"exec: {r}")
    p = ctl.mv("exec all -- false", user="agent", ok=False)
    check(p.returncode == 1, "a failing node should give exit code 1")
    p = ctl.mv("exec g1 --timeout 2 -- sleep 10", user="agent", ok=False)
    check("timeout" in p.stderr + p.stdout, "timeout not reported")
    ctl.sh("mkdir -p proj/src && echo 'print(1)' > proj/src/t.py && head -c 3000000 /dev/urandom > proj/w.bin", user="agent")
    ctl.mv("cp ./proj tag:gpu:/home/agent/runs/", user="agent")
    want = sha(ctl, "proj", user="agent")
    for g in (g1, g2):
        check(sha(g, "/home/agent/runs/proj") == want, f"upload to {g.name} corrupted")
    ctl.mv("exec tag:gpu -- 'hostname > runs/proj/host.txt'", user="agent")
    ctl.mv("cp tag:gpu:/home/agent/runs/proj/host.txt ./out", user="agent")
    for g in ("g1", "g2"):
        check(ctl.sh(f"cat out/{g}/host.txt", user="agent").strip() == g, f"download from {g}")


@test
def test_launch(lab):
    """Distributed launch: rendezvous, failure stops the others, jobs stop / kill -9 leave nothing behind."""
    net, (ctl, g1, g2) = mesh(lab, ["ctl", "g1", "g2"], tags="gpu", join_args="--ssh-allow-all agent")
    ctl.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    for g in (g1, g2):
        wait(lambda g=g: "agent@ctl" in g.mv("ssh-authorized-keys agent"), f"{g.name} learns ctl's key", 60)
    time.sleep(22)  # first LAN check
    out = ctl.mv("launch tag:gpu -- torchrun train.py", user="agent", timeout=120)
    check("rendezvous complete: rank1" in out, f"no rendezvous:\n{out}")
    check("ifname=eth0" in out, "nodes on one LAN should use it")
    # The torchrun stand-in is a python3 script: count it by its command line.
    leftover = lambda: sum(  # noqa: E731
        int(g.sh("pgrep -fc '^python3 /usr/local/bin/torchrun' || true").strip() or 0) for g in (g1, g2)
    )
    p = ctl.mv("launch tag:gpu -- env FAIL_RANK=1 STEPS=30 torchrun t.py", user="agent", ok=False, timeout=120)
    check(p.returncode == 1 and "stopping the other nodes" in p.stderr, f"failure handling:\n{p.stderr}")
    wait(lambda: leftover() == 0, "no processes left after a failure", 20)
    job = ctl.mvj("launch tag:gpu --detach -- env STEPS=300 torchrun t.py", user="agent")
    wait(lambda: leftover() == 2, "detached job running", 20)
    ctl.mv(f"jobs stop {job['id']}", user="agent", timeout=40)
    wait(lambda: leftover() == 0, "jobs stop leaves nothing", 20)
    job = ctl.mvj("launch tag:gpu --detach -- env STEPS=300 torchrun t.py", user="agent")
    wait(lambda: leftover() == 2, "detached job running", 20)
    ctl.sh(f"kill -9 {job['pid']}")
    wait(lambda: leftover() == 0, "kill -9 of the launcher leaves nothing", 30)
    jobs = ctl.mvj("jobs list", user="agent")
    check(jobs[0]["id"] == job["id"], f"newest job first: {[j['id'] for j in jobs]}")
    check(jobs[0]["state"] == "lost", f"job should be 'lost': {jobs[0]}")


@test
def test_gpu_reservations(lab):
    """Reservations: race, all-or-nothing, expiry, launch --gpus."""
    net = lab.network("net")
    ctl, g1, g2 = (lab.node(n, [net]) for n in ("ctl", "g1", "g2"))
    g1.fake_gpus([("NVIDIA H100", 81559, 400, 0)] * 2)
    g2.fake_gpus([("NVIDIA A100", 81920, 500, 0), ("NVIDIA A100", 81920, 70000, 99), ("NVIDIA A100", 81920, 500, 0)])
    ctl.mv(f"init --name ctl --endpoint {ctl.c}:7870")
    ctl.up()
    for g in (g1, g2):
        g.mv(f"join {invite(ctl)} --name {g.name} --tag gpu --ssh-allow-all agent")
        g.up()
        wait(lambda g=g: ctl.online(g.name), f"{g.name} online")
    ctl.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    for g in (g1, g2):
        wait(lambda g=g: "agent@ctl" in g.mv("ssh-authorized-keys agent"), f"{g.name} learns ctl's key", 60)
    rows = ctl.mvj("gpu list", user="agent")
    check([r["state"] for r in rows if r["node"] == "g2"] == ["free", "busy", "free"], f"gpu states: {rows}")
    ctl.mv("gpu reserve g1 -n 1", user="agent")
    p = [threading.Thread(target=lambda: ctl.mv("gpu reserve g1 -n 1", user="agent", ok=False)) for _ in range(2)]
    [t.start() for t in p]
    [t.join() for t in p]
    reserved = lambda: [r for r in ctl.mvj("gpu list", user="agent") if r["state"] == "reserved"]  # noqa: E731
    wait(lambda: len(reserved()) == 2, "exactly one racer got the last GPU on g1", 20)
    p = ctl.mv("gpu reserve g1 g2 -n 1", user="agent", ok=False)
    check(p.returncode != 0, "g1 is full: must fail")
    time.sleep(2)
    check(not any(r["node"] == "g2" for r in reserved()), "all or nothing: g2 must not stay reserved")
    ids = sorted({r["reservation"]["id"] for r in reserved()})
    ctl.mv(f"gpu release {' '.join(ids)}", user="agent")
    wait(lambda: not reserved(), "released", 20)
    ctl.mv("gpu reserve g2 -n 1 --for 3s", user="agent")
    wait(lambda: not reserved(), "expired by itself", 30)
    out = ctl.mv("launch tag:gpu --gpus 2 -- torchrun t.py", user="agent", timeout=120)
    check("cuda=0,2" in out and "cuda=0,1" in out and "nproc=2" in out, f"launch --gpus env:\n{out}")
    wait(lambda: not reserved(), "launch releases its GPUs", 20)
    p = ctl.mv("launch tag:gpu --gpus 3 -- torchrun t.py", user="agent", ok=False)
    check(p.returncode != 0 and "rank" not in p.stdout, "must not start without enough GPUs")


@test
def test_share_fetch(lab):
    """Peer-to-peer datasets: fetch from several holders, intact, resume, repair, members only."""
    net, (a, b, c) = mesh(lab, ["a", "b", "c"])
    a.sh("mkdir -p /data/ds/train && head -c 30000000 /dev/urandom > /data/ds/train/s0 && echo x > /data/ds/labels")
    want = sha(a, "/data/ds")
    oid = a.mvj("share /data/ds")["id"]
    wait(lambda: any(o["id"] == oid for o in b.mvj("objects")), "b sees the object", 30)
    r = b.mvj(f"fetch {oid} /srv")
    check(sha(b, "/srv/ds") == want, "fetch on b corrupted")
    wait(lambda: len([o for o in c.mvj("objects") if o["id"] == oid][0]["holders"]) == 2, "b serves it too", 30)
    r = c.mvj(f"fetch {oid} /srv")
    check(len(r["from"]) == 2, f"c should fetch from both holders: {r['from']}")
    check(sha(c, "/srv/ds") == want, "fetch on c corrupted")
    c.sh("printf XXXX | dd of=/srv/ds/train/s0 bs=1 seek=5000000 conv=notrunc 2>/dev/null")
    r = c.mvj(f"fetch {oid} /srv")
    check(r["bytes"] <= 4300000 and sha(c, "/srv/ds") == want, f"repair should refetch one chunk: {r['bytes']}")
    p = c.sh(f"""python3 -c "
import socket,json; s=socket.create_connection(('{a.net_ip(net)}',7871),3); s.recv(32); s.sendall(b'\\0'*32)
s.sendall(json.dumps({{'manifest':{{'id':'{oid}'}}}}).encode()+b'\\n')
# refused: closed (b'') or reset (unread data left) - either way no data
try: print(len(s.recv(100)))
except ConnectionResetError: print(0)" """, ok=False)
    check(p.stdout.strip() == "0", f"a non-member got data: {p.stdout}{p.stderr}")


@test
def test_net_env(lab):
    """LAN detection, matrix, and the training environment: LAN only if every pair shares one."""
    net = lab.network("net")
    net2 = lab.network("net2")
    ctl = lab.node("ctl", [net, net2])
    g1, g2 = lab.node("g1", [net]), lab.node("g2", [net])
    g3 = lab.node("g3", [net2])
    ctl.mv(f"init --name ctl --endpoint {ctl.c}:7870")
    ctl.up()
    for g in (g1, g2, g3):
        g.mv(f"join {invite(ctl)} --name {g.name}")
        g.up()
    for g in ("g1", "g2", "g3"):
        wait(lambda g=g: ctl.online(g), f"{g} online", 60)
    time.sleep(25)
    edges = ctl.mvj("net matrix --measure --mb 4", timeout=120)
    pair = lambda a, b: next((e for e in edges if e["from"] == a and e["to"] == b), None)  # noqa: E731
    check(pair("g1", "g2") and pair("g1", "g2")["lan_ip"], f"g1-g2 share a LAN: {pair('g1', 'g2')}")
    check(not (pair("g1", "g3") or {}).get("lan_ip"), "g1-g3 share no LAN")
    e12 = g2.mvj("net env --master g1 g1 g2")
    check(e12["NCCL_SOCKET_IFNAME"] == "eth0" and e12["NODE_RANK"] == "1", f"LAN env: {e12}")
    e13 = g3.mvj("net env --master g1 g1 g3")
    check(e13["NCCL_SOCKET_IFNAME"] == "mesh0" and e13["MASTER_ADDR"].startswith("100."), f"mesh env: {e13}")


@test
def test_doctor(lab):
    """doctor finds a Tailscale conflict and a blocking firewall; healthy nodes are healthy."""
    _, (hub, a) = mesh(lab, ["hub", "a"])
    p = hub.mv("doctor", ok=False)
    check(p.returncode == 0, f"healthy node should pass:\n{p.stdout}")
    a.sh("ip link add tailscale0 type dummy; ip addr add 100.101.102.103/32 dev tailscale0; ip link set tailscale0 up; "
         "iptables -N ts-input; iptables -I INPUT 1 -j ts-input; iptables -A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP")
    checks = json.loads(a.mv("--json doctor", ok=False).stdout)
    fails = [c["name"] for c in checks if c["level"] == "fail"]
    check("address range" in fails and "firewall" in fails, f"doctor fails: {fails}")
    check(a.mv("doctor", ok=False).returncode == 1, "doctor should exit 1 on failures")


@test
def test_mcp(lab):
    """MCP over stdio: handshake, tools, a few calls, errors."""
    _, (ctl, g1) = mesh(lab, ["ctl", "g1"], tags="gpu", join_args="--ssh-allow-all agent")
    ctl.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    wait(lambda: "agent@ctl" in g1.mv("ssh-authorized-keys agent"), "g1 learns ctl's key", 60)
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_nodes", "arguments": {"selectors": ["tag:gpu"]}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "exec", "arguments": {"selectors": ["g1"], "command": "hostname"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "exec", "arguments": {"selectors": ["nope"], "command": "true"}}},
        {"jsonrpc": "2.0", "id": 6, "method": "nope"},
    ]
    out = ctl.sh("meshvpn mcp", user="agent", input="\n".join(json.dumps(m) for m in msgs) + "\n")
    r = {m["id"]: m for m in map(json.loads, out.splitlines())}
    check(r[1]["result"]["serverInfo"]["name"] == "meshvpn", "initialize")
    names = [t["name"] for t in r[2]["result"]["tools"]]
    check({"list_nodes", "exec", "launch", "gpu_reserve", "fetch", "doctor"} <= set(names), f"tools: {names}")
    check([n["name"] for n in json.loads(r[3]["result"]["content"][0]["text"])] == ["g1"], "list_nodes tag:gpu")
    check(json.loads(r[4]["result"]["content"][0]["text"])["results"][0]["stdout"].strip() == "g1", "exec")
    check(r[5]["result"]["isError"], "unknown node should be an error result")
    check(r[6]["error"]["code"] == -32601, "unknown method")


@test
def test_deploy_sh(lab):
    """deploy.sh from a jump host (nothing installed there) to a device without internet."""
    pub = lab.network("pub")
    priv = lab.network("priv", internal=True)
    hub = lab.node("hub", [pub])
    jump = lab.node("jump", [pub, priv], install=False)
    dev = lab.node("device", [priv])
    run(["docker", "cp", BINARY, f"{jump.c}:/tmp/meshvpn-bin"])
    run(["docker", "cp", DEPLOY_SH, f"{jump.c}:/tmp/deploy.sh"])
    jump.sh("chmod 644 /tmp/meshvpn-bin /tmp/deploy.sh; useradd -m -s /bin/bash op; su op -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    dev.sh("useradd -m -s /bin/bash admin; echo 'admin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/admin; useradd -m -s /bin/bash ubuntu; "
           "rm /usr/local/bin/meshvpn")
    dev.sh("su admin -c 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'", input=jump.sh("cat /home/op/.ssh/id_ed25519.pub"))
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("useradd -m -s /bin/bash alice; su alice -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    check(dev.sh("curl -sI -m 5 https://github.com >/dev/null && echo yes || echo no").strip() == "no", "device has internet")
    out = jump.sh(f"su op -c 'sh /tmp/deploy.sh --invite {invite(hub)} --binary /tmp/meshvpn-bin --ssh-allow-all ubuntu "
                  f"--jump op@{jump.net_ip(priv)} admin@{dev.net_ip(priv)}'", timeout=300)
    check("Done." in out, out)
    wait(lambda: hub.online("device"), "device joined over its own tunnel", 60)
    check(ping(hub, "device.mesh"), "ping the device")
    wait(lambda: "alice@hub" in dev.mv("ssh-authorized-keys ubuntu"), "device allows everyone as ubuntu", 60)
    o = "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5"
    check(hub.sh(f"su alice -c 'ssh {o} ubuntu@device.mesh whoami'").strip() == "ubuntu", "ssh into the device")
    check(jump.sh("command -v meshvpn || echo none").strip() == "none", "something got installed on the jump host")


@test
def test_install_proxy(lab):
    """install.sh from a mirror, through a proxy that is only configured in /etc/environment."""
    pub = lab.network("pub")
    priv = lab.network("priv", internal=True)
    web = lab.node("web", [pub], install=False)
    proxy = lab.node("proxy", [pub, priv], install=False)
    client = lab.node("client", [priv], caps=False, install=False)
    with tempfile.TemporaryDirectory() as d:
        run(["cp", BINARY, f"{d}/meshvpn"])
        name = "meshvpn-x86_64-unknown-linux-musl.tar.gz"
        run(["tar", "-czf", f"{d}/{name}", "-C", d, "./meshvpn"])
        digest = hashlib.sha256(open(f"{d}/{name}", "rb").read()).hexdigest()
        open(f"{d}/{name}.sha256", "w").write(f"{digest}  {name}\n")
        run(["docker", "exec", web.c, "mkdir", "-p", "/srv"])
        for f in (name, f"{name}.sha256"):
            run(["docker", "cp", f"{d}/{f}", f"{web.c}:/srv/{f}"])
    web.sh("(cd /srv && python3 -m http.server 8000 >/dev/null 2>&1 &)")
    proxy.sh("sed -i 's/^Allow .*/Allow 0.0.0.0\\/0/; s/^#\\?Port .*/Port 8888/' /etc/tinyproxy/tinyproxy.conf; tinyproxy")
    run(["docker", "cp", INSTALL_SH, f"{client.c}:/tmp/install.sh"])
    client.sh(f"echo 'https_proxy=\"http://{proxy.c}:8888\"' >> /etc/environment")
    check(client.sh(f"curl -s -m 5 http://{web.c}:8000/ >/dev/null && echo yes || echo no").strip() == "no",
          "client must not reach the mirror directly")
    out = client.sh(f"env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin MESHVPN_DOWNLOAD_URL=http://{web.c}:8000 sh /tmp/install.sh")
    check("from /etc/environment" in out and "Installed meshvpn" in out, out)
    check(client.sh("cat /etc/meshvpn/proxy.env").count(proxy.c) == 2, "proxy not saved for meshvpn")


@test
def test_builtin_ssh(lab):
    """No sshd in the container: meshvpn's own SSH server - logins, pty, exit codes, sftp/scp, -L, exec/cp."""
    net = lab.network("net")
    hub = lab.node("hub", [net])
    # userspace mode without any sshd process (and without OpenSSH's sftp-server: ours is used)
    box = lab.node("box", [net], caps=False, cmd=["sleep", "infinity"])
    box.sh("rm -f /usr/lib/openssh/sftp-server")
    # kernel mode, sshd not even installed
    kbox = lab.node("kbox", [net], cmd=["sleep", "infinity"])
    kbox.sh("rm -f /usr/sbin/sshd")
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    box.mv(f"join {invite(hub)} --name box --ssh-allow-all agent")
    # the same rule set before meshvpn ever ran
    kbox.mv(f"join {invite(hub)} --name kbox")
    p = kbox.mv("ssh allow alice@hub --as agent", ok=False)
    check(p.returncode != 0 and "doesn't know a node" in p.stderr, f"unknown node before the first start: {p.stderr}")
    check("takes effect" in kbox.mv("ssh allow everyone --as agent"), "ssh allow before up")
    for n in (box, kbox):
        n.up()
        wait(lambda n=n: n.status().get("ssh_server") == "built-in", f"{n.name}: built-in ssh server active")
        wait(lambda n=n: "agent@hub" in n.mv("ssh-authorized-keys agent", ok=False).stdout or n.peer("hub")
             and n.peer("hub")["online"], f"{n.name} knows hub", 60)
    for n in ("box", "kbox"):
        wait(lambda n=n: f"{n}.mesh" in hub.sh("cat /var/lib/meshvpn/known_hosts 2>/dev/null; true"),
             f"hub learns {n}'s host key", 60)
    # StrictHostKeyChecking=yes: only works because the host keys came with the records
    o = "-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=8"

    def ssh(target, cmd, user="agent", ok=False, input=None):
        return hub.sh(f"ssh {o} {target} {cmd}", user=user, ok=ok, input=input)

    for n in ("box", "kbox"):
        p = ssh(f"agent@{n}.mesh", "whoami")
        check(p.returncode == 0 and p.stdout.strip() == "agent", f"login to {n}: {p.stdout} {p.stderr}")
    p = ssh("root@box.mesh", "whoami")
    check(p.returncode != 0 and "root" not in p.stdout, "root must not be allowed")
    # refused logins say why (meshvpn ssh list, doctor)
    box.mv("ssh allow everyone --as ghost")
    check(ssh("ghost@box.mesh", "true").returncode != 0, "ghost does not exist")
    hub.sh("ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/other", user="agent")
    check(ssh("-i ~/.ssh/other -o IdentitiesOnly=yes agent@box.mesh", "true").returncode != 0, "unpublished key")
    refused = wait(lambda: (lambda t: t if t.count("min ago") >= 3 else None)(box.mv("ssh list")),
                   "refusals listed", 10)
    for why in ("no rule lets hub log in as root", "no user ghost here", "does not publish the offered key"):
        check(why in refused, f"missing reason {why!r}:\n{refused}")
    check("refused recently" in box.mv("doctor", ok=False).stdout, "doctor should mention refused logins")
    check(ssh("agent@box.mesh", "'exit 7'").returncode == 7, "exit code")
    check(ssh("agent@box.mesh", "cat", input="through stdin\n").stdout == "through stdin\n", "stdin")
    p = ssh("agent@box.mesh", "'echo out; echo err >&2'")
    check(p.stdout.strip() == "out" and p.stderr.strip() == "err", f"stdout/stderr: {p.stdout!r} {p.stderr!r}")
    env = ssh("agent@box.mesh", "'echo $HOME $USER; echo $SSH_CONNECTION'").stdout.split("\n")
    check(env[0] == "/home/agent agent" and env[1].startswith(hub.ip()), f"environment: {env}")
    p = ssh("-tt agent@box.mesh", "'tty; stty size'")
    check("/dev/pts/" in p.stdout, f"pty: {p.stdout!r} {p.stderr!r}")
    # scp (sftp protocol) both ways, sftp batch
    hub.sh("head -c 5000000 /dev/urandom > ~/blob", user="agent")
    want = hub.sh("sha256sum ~/blob | cut -c1-16", user="agent").strip()
    hub.sh(f"scp {o} ~/blob agent@box.mesh:/home/agent/up.bin", user="agent")
    check(box.sh("sha256sum /home/agent/up.bin | cut -c1-16").strip() == want, "scp upload corrupted")
    check(box.sh("stat -c %U /home/agent/up.bin").strip() == "agent", "uploaded file must belong to agent")
    hub.sh(f"scp {o} agent@box.mesh:/home/agent/up.bin ~/down.bin", user="agent")
    check(hub.sh("sha256sum ~/down.bin | cut -c1-16", user="agent").strip() == want, "scp download corrupted")
    out = hub.sh(f"sftp {o} -b - agent@box.mesh", user="agent",
                 input="mkdir d1\nrename up.bin d1/x.bin\nls d1\nrm d1/x.bin\nrmdir d1\n")
    check("d1/x.bin" in out, f"sftp: {out}")
    # -L forwarding to a service that only listens on the box's loopback
    box.sh("mkdir -p /srv && echo via-forward > /srv/index.html && "
           "(cd /srv && python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &)")
    time.sleep(1)
    hub.sh(f"ssh {o} -f -N -L 9090:127.0.0.1:8080 agent@box.mesh", user="agent")
    wait(lambda: "via-forward" in hub.sh("curl -s -m5 http://127.0.0.1:9090/", ok=False).stdout, "-L forward", 15)
    hub.sh("pkill -f '^ssh .*-L 9090' ; true")
    # meshvpn exec and cp ride on it
    r = hub.mvj("exec box kbox -- hostname", user="agent")
    check(r["ok"] and sorted(x["stdout"].strip() for x in r["results"]) == ["box", "kbox"], f"exec: {r}")
    hub.sh("mkdir -p proj && head -c 2000000 /dev/urandom > proj/w.bin", user="agent")
    hub.mv("cp ./proj kbox:/home/agent/runs/", user="agent")
    check(sha(kbox, "/home/agent/runs/proj") == sha(hub, "proj", user="agent"), "cp over the built-in server")
    doc = box.mv("doctor", ok=False).stdout
    check("built-in SSH server" in doc, doc)


@test
def test_desktop(lab):
    """meshvpn desktop: a container without any X server, through SSH - frames, apps, typing, clipboard, windows."""
    check(DESKTOP_BUNDLE, "needs --desktop-bundle (build it with desktop/build-bundle.sh)")
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, cmd=["sleep", "infinity"])  # no sshd: the built-in server
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    box.mv(f"join {invite(hub)} --name box --ssh-allow-all agent")
    box.up()
    wait(lambda: hub.online("box") and box.status().get("ssh_server") == "built-in", "box online with ssh")
    run(["docker", "cp", DESKTOP_BUNDLE, f"{box.c}:/tmp/desktop.tar.gz"])
    box.sh("chmod 644 /tmp/desktop.tar.gz")
    check("installed" in box.mv("desktop setup --from /tmp/desktop.tar.gz", user="agent"), "desktop setup")
    wait(lambda: box.mv("ssh-authorized-keys agent", ok=False).returncode == 0 and
         hub.sh("su agent -c 'ssh -o BatchMode=yes -o ConnectTimeout=5 agent@box.mesh true'", ok=False).returncode == 0,
         "ssh from hub to box", 60)
    hub.sh("cd /home/agent && (meshvpn desktop box --no-browser --port 18080 > /tmp/desktop.out 2>&1 &)", user="agent")
    out = wait(lambda: (lambda t: t if "#" in t else None)(hub.sh("cat /tmp/desktop.out", ok=False).stdout), "viewer link", 10)
    token = out.split("#", 1)[1].split()[0]
    p = hub.sh(f"python3 /usr/local/bin/desktop_client.py 18080 {token}", user="agent", ok=False, timeout=240)
    check(p.returncode == 0, f"desktop session: {p.stdout}{p.stderr}")
    r = json.loads(p.stdout.strip().splitlines()[-1])
    check(r["first_frame_tiles"].get("1", 0) + r["first_frame_tiles"].get("2", 0) >= 160, f"a full first frame: {r}")
    check(r["cursor"] and r["size"] == [800, 500], f"cursor and resize: {r}")
    check("XTerm" in r["apps"], f"installed apps should be listed: {r['apps']}")
    typed = box.sh("od -An -c /tmp/typed | tr -s ' '", ok=False).stdout
    check(box.sh("cat /tmp/typed", ok=False).stdout == "Hello Wörld €!\n", f"typed text: {typed}")
    # The session runs as the user who logged in, and its clipboard got the browser's text.
    xvfb = box.sh("ps -o user=,args= -C Xvfb", ok=False).stdout
    check(xvfb.startswith("agent "), f"Xvfb should run as agent: {xvfb}")
    clip = box.sh("cat /tmp/clip_in", ok=False).stdout
    check(clip == "from the browser ✓", f"clipboard from the browser: {clip!r}")
    check("ended" in box.mv("desktop stop", user="agent"), "desktop stop")
    wait(lambda: box.sh("pgrep -x Xvfb", ok=False).returncode != 0, "Xvfb gone after stop", 10)


@test
def test_console(lab):
    """meshvpn console: node list, shells on nodes as tabs (user as plain ssh picks it), desktop link with the ssh -L hint."""
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, cmd=["sleep", "infinity"])
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    box.mv(f"join {invite(hub)} --name box --ssh-allow-all agent")
    box.up()
    wait(lambda: hub.online("box") and box.status().get("ssh_server") == "built-in", "box online with ssh")
    # root on hub logs in to mesh hosts as agent (its ssh config says so), like `ssh box.mesh` does
    hub.sh("ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519 && printf 'Host *.mesh\\n  User agent\\n' > /root/.ssh/config")
    wait(lambda: hub.sh("ssh -o BatchMode=yes -o ConnectTimeout=5 box.mesh true", ok=False).returncode == 0,
         "plain ssh from hub to box", 60)
    steps = [
        "expect:NODE", "expect:box",
        "key:down", "key:enter", "expect:agent@box",
        "send:echo MARK-$(hostname)\\r", "expect:MARK-box",
        "send:\\x020", "expect:shells as",   # Ctrl+B 0: back to the node list
        "send:\\x021", "send:exit\\r", "expect:session ended",
        "key:enter", "send:d", "expect:ssh -L 7880:127.0.0.1:7880 -p 2222 root@10.1.2.3",
    ]
    quoted = " ".join("'" + s + "'" for s in steps)
    p = hub.sh(f"cd /root && SSH_CONNECTION='10.9.9.9 50000 10.1.2.3 2222' console_driver.py {quoted}", ok=False, timeout=120)
    check(p.returncode == 0, f"console: {p.stdout[-3000:]}{p.stderr[-500:]}")


@test
def test_small_mtu(lab):
    """A path that drops big UDP datagrams (VPN, WSL2): detected, packets split, TCP and ssh still work."""
    net, (hub, a, b) = mesh(lab, ["hub", "a", "b"], join_args="--ssh-allow-all agent")
    # b's network drops UDP datagrams of 1300 bytes and more; small probes still pass.
    for chain, port in (("INPUT", "--dport"), ("OUTPUT", "--sport")):
        b.sh(f"iptables -A {chain} -p udp {port} 7870 -m length --length 1300:65535 -j DROP")
    wait(lambda: "direct UDP" in (a.peer("b") or {}).get("path", ""), "direct UDP path a-b")
    wait(lambda: "splitting" in a.peer("b")["path"], "a notices the small path to b", 30)
    b.sh("mkdir -p /srv && head -c 5000000 /dev/urandom > /srv/blob && (cd /srv && python3 -m http.server 8080 >/dev/null 2>&1 &)")
    time.sleep(1)
    want = b.sh("sha256sum /srv/blob | cut -c1-16").strip()
    got = a.sh("curl -s -m 60 http://b.mesh:8080/blob | sha256sum | cut -c1-16", ok=False).stdout.strip()
    check(got == want, f"5 MB over the small path: {got!r} != {want!r}")
    check("direct UDP" in a.peer("b")["path"], f"should still go direct: {a.peer('b')['path']}")
    a.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    wait(lambda: a.sh("su agent -c 'ssh -o BatchMode=yes -o ConnectTimeout=8 agent@b.mesh echo ok'", ok=False).stdout.strip() == "ok",
         "ssh (big key exchange) over the small path", 60)
    # A normal path is not split.
    check("splitting" not in a.peer("hub")["path"], f"a-hub should carry full size: {a.peer('hub')['path']}")


@test
def test_container_install(lab):
    """meshvpn install in a container whose systemctl only says "Running in chroot, ignoring command"."""
    net, (hub,) = mesh(lab, ["hub"])
    box = lab.node("box", [net])
    box.sh("printf '#!/bin/sh\\necho \"Running in chroot, ignoring command \\047$1\\047\"\\n' > /usr/bin/systemctl && chmod 755 /usr/bin/systemctl")
    box.mv(f"join {invite(hub)} --name box")
    out = box.mv("install")
    check("in the background" in out and "entrypoint" in out, out)
    wait(lambda: hub.online("box"), "box online after install")
    out = box.mv("install")  # again: restarts it
    check("Stopped a meshvpn" in out, out)
    wait(lambda: hub.online("box"), "box online after reinstall")
    box.mv("uninstall")
    check(box.mv("status", ok=False).returncode == 3, "uninstall should stop it")


@test
def test_rootless(lab):
    """install.sh --user as a normal user: no root anywhere, background daemon, mesh in and out."""
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, install=False, cmd=["sleep", "infinity"])  # no sshd at all
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    with tempfile.TemporaryDirectory() as d:
        run(["cp", BINARY, f"{d}/meshvpn"])
        name = "meshvpn-x86_64-unknown-linux-musl.tar.gz"
        run(["tar", "-czf", f"{d}/{name}", "-C", d, "./meshvpn"])
        digest = hashlib.sha256(open(f"{d}/{name}", "rb").read()).hexdigest()
        open(f"{d}/{name}.sha256", "w").write(f"{digest}  {name}\n")
        box.sh("mkdir -p /tmp/rel")
        for f in (name, f"{name}.sha256"):
            run(["docker", "cp", f"{d}/{f}", f"{box.c}:/tmp/rel/{f}"])
    run(["docker", "cp", INSTALL_SH, f"{box.c}:/tmp/install.sh"])
    box.sh("chmod -R a+rX /tmp/rel /tmp/install.sh")
    out = box.sh(f"MESHVPN_DOWNLOAD_URL=file:///tmp/rel sh /tmp/install.sh --user join {invite(hub)} --name box",
                 user="agent")
    check("Rootless install" in out and "running in the background" in out, out)
    check(box.sh("test -e /etc/meshvpn -o -e /usr/local/bin/meshvpn && echo root || echo clean").strip() == "clean",
          "a rootless install must not touch system paths")
    mv = "/home/agent/.local/bin/meshvpn"
    check(box.sh(f"{mv} status", user="agent", ok=False).returncode == 0, "status as the user")
    wait(lambda: hub.online("box"), "box online at hub")
    st = json.loads(box.sh(f"{mv} --json status", user="agent"))
    check(st.get("socks"), "rootless node should run in userspace mode")
    # mesh -> services of the user, user -> mesh via SOCKS and ssh
    box.sh("mkdir -p ~/srv && echo hello-rootless > ~/srv/index.html && "
           "(cd ~/srv && python3 -m http.server 8080 >/dev/null 2>&1 &)", user="agent")
    hub.sh("mkdir -p /srv && echo hello-hub > /srv/index.html && (cd /srv && python3 -m http.server 8000 >/dev/null 2>&1 &)")
    wait(lambda: "hello-rootless" in hub.sh("curl -s -m5 http://box.mesh:8080/", ok=False).stdout,
         "http into the rootless node", 20)
    check("hello-hub" in box.sh("curl -s -m5 -x socks5h://127.0.0.1:1055 http://hub.mesh:8000/", user="agent"),
          "SOCKS out of the rootless node")
    o = "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8"
    p = box.sh(f"ssh {o} nobody@hub.mesh true", user="agent", ok=False)
    check("Permission denied" in p.stderr, f"ssh to hub.mesh should reach its sshd: {p.stderr}")
    # the owner may do what used to need root; system changes still need root
    box.sh(f"{mv} rename box2", user="agent")
    wait(lambda: hub.online("box2"), "rename seen by hub", 30)
    # password-less logins without root: the built-in SSH server, as this user only
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    box.sh(f"{mv} ssh allow agent@hub --as agent", user="agent")
    box.sh(f"{mv} ssh allow agent@hub --as root", user="agent")
    o = "-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=8"
    wait(lambda: hub.sh(f"ssh {o} agent@box2.mesh whoami", user="agent", ok=False).stdout.strip() == "agent",
         "login to the rootless node", 60)
    check(hub.sh(f"ssh {o} root@box2.mesh whoami", user="agent", ok=False).stdout.strip() != "root",
          "a rootless node must not log anyone in as root")
    doc = box.sh(f"{mv} doctor", user="agent", ok=False).stdout
    check("rootless install" in doc and "sudo" not in doc, doc)
    box.sh(f"{mv} uninstall", user="agent")
    check(box.sh(f"{mv} status", user="agent", ok=False).returncode == 3, "uninstall should stop it")
    check("meshvpn" not in box.sh("cat ~/.ssh/config 2>/dev/null; true", user="agent"), "ssh config block removed")
    box.sh(f"{mv} install", user="agent")
    wait(lambda: hub.online("box2"), "back after install", 30)


# =============================================================================================


def run_test(name, keep):
    lab = Lab(name)
    started = time.time()
    try:
        TESTS[name](lab)
        result = (name, True, "", time.time() - started)
    except Exception as e:  # noqa: BLE001
        detail = f"{e}" if isinstance(e, Failed) else traceback.format_exc()
        logs = ""
        for c in lab.containers:
            p = run(["docker", "exec", c, "sh", "-c", "tail -n 25 /var/log/meshvpn.log 2>/dev/null"], ok=False)
            if p.stdout.strip():
                logs += f"\n--- {c} meshvpn.log (tail)\n{p.stdout}"
        result = (name, False, detail + logs, time.time() - started)
    finally:
        if not keep:
            lab.cleanup()
    with print_lock:
        ok, detail, secs = result[1], result[2], result[3]
        print(f"{'PASS' if ok else 'FAIL'}  {name}  ({secs:.0f}s)", flush=True)
        if not ok:
            print("    " + detail.replace("\n", "\n    "), flush=True)
    return result


def main():
    global BINARY, DESKTOP_BUNDLE
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True, help="static meshvpn binary to test")
    ap.add_argument("--desktop-bundle", help="meshvpn-desktop-<arch>.tar.gz (desktop/build-bundle.sh) for the desktop test")
    ap.add_argument("-j", "--jobs", type=int, default=3, help="tests in parallel")
    ap.add_argument("--keep", action="store_true", help="keep containers of failed tests for debugging")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("tests", nargs="*")
    a = ap.parse_args()
    if a.list:
        for n, f in TESTS.items():
            print(f"{n:18} {f.__doc__.strip()}")
        return 0
    BINARY = os.path.abspath(a.binary)
    DESKTOP_BUNDLE = a.desktop_bundle and os.path.abspath(a.desktop_bundle)
    names = a.tests or list(TESTS)
    unknown = [n for n in names if n not in TESTS]
    if unknown:
        print(f"unknown tests: {unknown}; see --list")
        return 2
    print(f"building the test image ({IMAGE})...", flush=True)
    run(["docker", "build", "-q", "-t", IMAGE, HERE], timeout=900)
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        results = list(ex.map(lambda n: run_test(n, a.keep), names))
    failed = [r[0] for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed in {time.time() - started:.0f}s"
          + (f"; failed: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

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
FULL_RUN = None
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

    def network(self, name, internal=False, subnet=None, ipv6_only=False):
        full = f"{self.prefix}-{name}"
        args = ["docker", "network", "create"] + (["--internal"] if internal else []) + \
            (["--subnet", subnet] if subnet else []) + (["--ipv6", "--ipv4=false"] if ipv6_only else []) + [full]
        run(args)
        self.networks.append(full)
        return full

    def node(self, name, networks, caps=True, sysctls=(), ip=None, install=True, net_admin=False, cmd=None, image=IMAGE):
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
        run(args + [image] + (cmd or []))
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
    st = a.status()
    check(all(p["version"] == st["version"] for p in st["peers"]), f"peer versions: {[p['version'] for p in st['peers']]}")
    check(f"meshvpn {st['version']}" in a.mv("status") and "VERSION" in a.mv("nodes"), "versions shown")
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
def test_clients(lab):
    """A user's computer joins as a client for a time: reaches the nodes, relays nothing, is dropped when its time is up, renews."""
    net, (hub, a) = mesh(lab, ["hub", "a"])
    laptop = lab.node("laptop", [net])
    inv = json.loads(hub.mv("--json invite --client alice --client-for 75s"))
    check(inv["client_until_ms"], f"a client invite: {inv}")
    laptop.mv(f"join {inv['invite']} --name alice-laptop")
    laptop.up()
    wait(lambda: hub.online("alice-laptop") and a.online("alice-laptop"), "the client is in", 40)
    check(ping(laptop, "a.mesh"), "the client reaches a")
    check("(client: alice)" in hub.mv("status"), "status marks the client")
    st = laptop.status()
    check(st["client"]["user"] == "alice", f"the client knows it is one: {st.get('client')}")
    check("alice's computer" in laptop.mv("status"), "and says so")
    # Its time is up: every node drops it, and it can't reach anyone.
    wait(lambda: not hub.online("alice-laptop") and not a.online("alice-laptop"), "the client is dropped when its time is up", 120)
    check(not ping(laptop, "a.mesh", count=1), "an expired client still reaches a")
    check("renew" in laptop.mv("status"), "the client is told to renew")
    # Renewal: a new client invite for the same computer, same identity.
    old_id = laptop.status()["id"]
    inv = json.loads(hub.mv("--json invite --client alice --client-for 10m"))
    out = laptop.mv(f"join {inv['invite']}")
    check("client until" in out, f"renewed: {out}")
    wait(lambda: hub.online("alice-laptop"), "the renewed client is back", 60)
    check(laptop.status()["id"] == old_id and ping(laptop, "a.mesh"), "the same identity, reaching a again")
    # Nobody routes through a client.
    routes = a.status()["peers"]
    check(all("relay via alice-laptop" not in p["path"] for p in routes), f"routes through the client: {routes}")


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
    # Services only for the box itself stay private, the SOCKS proxy included.
    box.sh("(cd /srv && python3 -m http.server 8081 --bind 127.0.0.1 >/dev/null 2>&1 &)")
    time.sleep(1)
    check("hello-box" in box.sh("curl -s -m5 http://127.0.0.1:8081/"), "loopback service runs")
    p = hub.sh("curl -s -m5 http://box.mesh:8081/", ok=False)
    check(p.returncode != 0 and "hello-box" not in p.stdout, "a 127.0.0.1-only service must not be reachable")
    p = hub.sh("curl -s -m5 -x socks5h://box.mesh:1055 http://hub.mesh:8000/", ok=False)
    check("hello-hub" not in p.stdout, "the box's SOCKS proxy must not be reachable from the mesh")
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
def test_ssh_allow_key(lab):
    """ssh allow with a public key: through sshd and the built-in server, not depending on names; a shared name is refused."""
    net, (server, laptop, other) = mesh(lab, ["server", "laptop", "other"])
    box = lab.node("box", [net], caps=False, cmd=["sleep", "infinity"])  # no sshd: the built-in server
    box.mv(f"join {invite(server)} --name box")
    pair = lambda n, u, f: n.sh(f"su {u} -c 'ssh-keygen -q -t ed25519 -N \"\" -C {u}@device -f ~/{f}; cat ~/{f}.pub'").strip()  # noqa: E731
    server.sh("useradd -m -s /bin/bash bob")
    laptop.sh("useradd -m -s /bin/bash alice; useradd -m -s /bin/bash eve")
    # Not ~/.ssh/id_*: published by no node, so only this rule can let them in.
    alice = pair(laptop, "alice", "secret")
    pair(laptop, "eve", "secret")
    o = "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o IdentitiesOnly=yes -i ~/secret"
    login = lambda n, user, target: n.sh(f"su {user} -c 'ssh {o} {target} whoami'", ok=False).stdout.strip()  # noqa: E731
    check(login(laptop, "alice", "bob@server.mesh") != "bob", "no rule yet")

    # The way a .pub file is pasted: unquoted, with its comment.
    p = server.mv(f"ssh allow {alice} --as bob")
    check("this key may log in here as bob" in p, p)
    check("meshvpn:key:alice@device" in server.mv("ssh-authorized-keys bob"), "no authorized_keys line")
    check("alice@device" in server.mv("ssh list"), "ssh list should show the key")
    check(login(laptop, "alice", "bob@server.mesh") == "bob", "the key should get in through sshd")
    check(login(laptop, "eve", "bob@server.mesh") != "bob", "another key must not get in")
    check(login(laptop, "alice", "root@server.mesh") != "root", "only the account named")
    check(login(laptop, "alice", f"bob@{server.net_ip(net)}") != "bob", "only over the mesh")
    # From another device with the same key: the rule is the key, not the device.
    other.sh("useradd -m -s /bin/bash carol")
    run(["docker", "cp", f"{laptop.c}:/home/alice/secret", "/tmp/mv-e2e-secret"])
    try:
        run(["docker", "cp", "/tmp/mv-e2e-secret", f"{other.c}:/home/carol/secret"])
    finally:
        os.remove("/tmp/mv-e2e-secret")
    other.sh("chown carol /home/carol/secret; chmod 600 /home/carol/secret")
    check(login(other, "carol", "bob@server.mesh") == "bob", "the key from another node")

    # Nothing but a plain key gets into authorized_keys.
    p = server.mv(f"ssh allow 'command=\"id\" {alice}' --as bob", ok=False)
    check(p.returncode != 0, f"a key with options was accepted: {p.stdout}")
    p = server.mv("ssh allow ssh-ed25519 AAAAbroken --as bob", ok=False)
    check(p.returncode != 0 and "not one SSH public key" in p.stderr, f"a broken key: {p.stderr}")
    check("command=" not in server.mv("ssh-authorized-keys bob"), "options reached authorized_keys")

    server.mv(f"ssh deny {alice}")
    check(login(laptop, "alice", "bob@server.mesh") != "bob", "deny didn't take effect")

    # The built-in server; set before meshvpn ever ran, so the rule comes from the config.
    check("takes effect" in box.mv(f"ssh allow {alice} --as agent"), "ssh allow before the first start")
    box.up()
    wait(lambda: box.status().get("ssh_server") == "built-in", "built-in ssh server active")
    wait(lambda: laptop.online("box"), "box online at laptop")
    check(wait(lambda: login(laptop, "alice", "agent@box.mesh") == "agent" or None, "key through the built-in server", 60),
          "the key should get in through the built-in server")
    check(login(laptop, "eve", "agent@box.mesh") != "agent", "another key must not get in the built-in server")

    # A second device calling itself laptop: no guessing which one is meant.
    twin = lab.node("twin", [net])
    twin.mv(f"join {invite(server)} --name laptop")
    twin.up()
    wait(lambda: len([p for p in server.status()["peers"] if p["name"].startswith("laptop")]) == 2, "server sees both", 60)
    p = server.mv("ssh allow laptop --as bob", ok=False)
    check(p.returncode != 0 and "nodes match" in p.stderr, f"a shared name should be refused: {p.stdout}{p.stderr}")
    check("-> bob" not in server.mv("ssh list"), "no rule should be left behind")
    ident = [p for p in server.status()["peers"] if p["name"].startswith("laptop")][0]["id"]
    check("may now log in" in server.mv(f"ssh allow {ident} --as bob"), "by id should work")


@test
def test_ssh_authorized_keys(lab):
    """The built-in server takes keys from the account's authorized_keys, as sshd would, and only what it can honour."""
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, cmd=["sleep", "infinity"])  # no sshd: the built-in server
    off = lab.node("off", [net], caps=False, cmd=["sleep", "infinity"])
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    box.mv(f"join {invite(hub)} --name box")
    off.mv(f"join {invite(hub)} --name off")
    off.sh("sed -i 's/^ssh_authorized_keys = true/ssh_authorized_keys = false/' /etc/meshvpn/config.toml")
    for n in (box, off):
        n.up()
        wait(lambda n=n: n.status().get("ssh_server") == "built-in", f"{n.name}: built-in ssh server active")
        wait(lambda n=n: hub.online(n.name), f"{n.name} online")
    # Not id_*: published by no node, so no meshvpn rule can be what lets it in.
    pub = hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -C other-service -f ~/secret; cat ~/secret.pub'").strip()
    o = "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o IdentitiesOnly=yes -i ~/secret"
    login = lambda n: hub.sh(f"su agent -c 'ssh {o} agent@{n}.mesh whoami'", ok=False).stdout.strip()  # noqa: E731
    put = lambda n, line: n.sh(  # noqa: E731
        f"mkdir -p /home/agent/.ssh; cat > /home/agent/.ssh/authorized_keys <<'EOT'\n{line}\nEOT\n"
        "chown -R agent /home/agent/.ssh; chmod 700 /home/agent/.ssh; chmod 600 /home/agent/.ssh/authorized_keys")
    check(login("box") != "agent", "no key yet")
    put(box, pub)
    check(login("box") == "agent", "a key in authorized_keys should get in")
    # Options can't be honoured here: refused, not given more than they were meant to have.
    put(box, f'command="/bin/false" {pub}')
    check(login("box") != "agent", "a key limited by options must not get a shell")
    check("only sshd can apply" in box.mv("ssh list") + box.mv("doctor", ok=False).stdout, "should say why")
    # Writable by others: anyone could add themselves.
    put(box, pub)
    box.sh("chmod 666 /home/agent/.ssh/authorized_keys")
    check(login("box") != "agent", "a file others can write to must not count")
    box.sh("chmod 600 /home/agent/.ssh/authorized_keys")
    box.sh("chmod 777 /home/agent/.ssh")
    check(login("box") != "agent", "a directory others can write to must not count")
    box.sh("chmod 700 /home/agent/.ssh")
    check(login("box") == "agent", "back to normal")
    # Every account by its own file.
    box.sh("useradd -m -s /bin/bash victim; mkdir -p /home/victim/.ssh; "
           f"echo '{pub}' > /home/victim/.ssh/authorized_keys; chown -R victim /home/victim/.ssh; "
           "chmod 700 /home/victim/.ssh; chmod 755 /home/victim")
    check(hub.sh(f"su agent -c 'ssh {o} victim@box.mesh whoami'", ok=False).stdout.strip() == "victim",
          "each account uses its own file")
    box.sh("rm /home/victim/.ssh/authorized_keys")
    check(hub.sh(f"su agent -c 'ssh {o} victim@box.mesh whoami'", ok=False).stdout.strip() != "victim",
          "removed from the file: out")
    put(off, pub)
    check(login("off") != "agent", "ssh_authorized_keys = false turns it off")


@test
def test_net_why(lab):
    """net why: nothing wrong on a direct path; tells one-way from no way, from both ends."""
    pub = lab.network("pub", subnet="198.51.102.0/24")
    nets = {x: lab.network(f"lan{x}", internal=True) for x in "AB"}
    hub = lab.node("hub", [pub], ip="198.51.102.10")
    routers, clients = {}, {}
    for x in "AB":
        r = lab.node(f"nat{x}", [pub, nets[x]], caps=False, net_admin=True,
                     sysctls=["net.ipv4.ip_forward=1"], install=False)
        out_if = r.sh("ip -o -4 addr | awk '/198.51.102/ {print $2}'").strip()
        pub_ip = r.net_ip(pub)
        r.sh(f"""
            iptables -t nat -A POSTROUTING -o {out_if} -p udp --sport 7870 -j SNAT --to-source {pub_ip}:7870
            iptables -t nat -A POSTROUTING -o {out_if} -j MASQUERADE
            iptables -A INPUT -i {out_if} -m conntrack --ctstate NEW,INVALID -j DROP
        """)
        routers[x] = r
        c = lab.node(f"client{x.lower()}", [nets[x]])
        c.sh(f"ip route add default via {r.net_ip(nets[x])}")
        clients[x] = c
    hub.mv("init --name hub --endpoint 198.51.102.10:7870")
    hub.up()
    for c in clients.values():
        c.mv(f"join {invite(hub)} --name {c.name}")
        c.up()
    a, b = clients["A"], clients["B"]
    wait(lambda: a.online("clientb"), "clients see each other", timeout=60)
    wait(lambda: "UDP" in (a.peer("clientb") or {}).get("path", ""), "direct UDP path", timeout=90)

    # Nothing to find out.
    r = a.mvj("net why clientb", timeout=30)
    check(r["verdict"] == "direct-udp" and r["direct"], f"direct: {r}")
    check("nothing is wrong" in a.mv("net why clientb", timeout=30), "should say so")

    # Only B's packets are dropped, on the way into A's network: A's still reach B.
    b_pub = routers["B"].net_ip(pub)
    routers["A"].sh(f"iptables -I FORWARD -p udp -s {b_pub} -j DROP")
    wait(lambda: "UDP" not in (a.peer("clientb") or {}).get("path", ""), "A loses the path", timeout=60)
    wait(lambda: "UDP" not in (b.peer("clienta") or {}).get("path", ""), "B loses the path", timeout=60)
    p = a.mv("net why clientb --json", ok=False, timeout=30)
    r = json.loads(p.stdout)
    check(p.returncode == 1, "no direct connection: exit code 1")
    check(r["verdict"] == "one-way", f"one-way: {r}")
    check(r["there"] and r["there"]["heard"] > 0 and r["here"]["heard"] == 0, f"who heard whom: {r}")
    check(r["here"]["sent"] > 0 and r["there"]["sent"] > 0, f"both sides test: {r}")
    check("clienta's probes reach clientb" in r["why"], r["why"])

    # Now nothing gets through. Either side can ask.
    routers["A"].sh(f"iptables -I FORWARD -p udp -d {b_pub} -j DROP")
    p = b.mv("net why clienta --json", ok=False, timeout=30)
    r = json.loads(p.stdout)
    check(r["verdict"] == "firewall" and r["here"]["heard"] == 0 and r["there"]["heard"] == 0, f"no way: {r}")
    p = b.mv("net why clienta", ok=False, timeout=30)
    check(p.returncode == 1 and "Why:" in p.stdout and "tcpdump" in p.stdout and "relay" in p.stdout, f"says: {p.stdout}")

    # Unblocked, the test brings the path back at once: both sides probe together.
    routers["A"].sh(f"iptables -D FORWARD -p udp -d {b_pub} -j DROP; iptables -D FORWARD -p udp -s {b_pub} -j DROP")
    routers["A"].sh("conntrack -F 2>/dev/null; true")
    r = json.loads(a.mv("net why clientb --json", ok=False, timeout=30).stdout)
    check(r["verdict"] in ("direct-udp", "unstable"), f"after unblocking: {r}")

    # What can't be tested.
    p = a.mv("net why nosuchnode", ok=False, timeout=30)
    check(p.returncode != 0 and "no node named" in p.stderr, p.stderr)
    p = a.mv("net why clienta", ok=False, timeout=30)
    check(p.returncode != 0 and "this machine" in p.stderr, p.stderr)


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
    # The check before training: fine here, and it finds a firewall instead of a hang later.
    r = ctl.mvj("net check tag:gpu --mb 8", user="agent", timeout=180)
    check(r["ok"] and r["path"] == "lan" and r["slowest_mbps"] > 1, f"net check: {r}")
    check({e["NCCL_SOCKET_IFNAME"] for e in r["env"].values()} == {"eth0"}, f"net check env: {r['env']}")
    check(len(r["pairs"]) == 3, f"both directions and the master's port: {r['pairs']}")
    out = ctl.mv("net check tag:gpu --mb 8", user="agent", timeout=180)
    check("NCCL's TCP connections will work" in out and "slowest:" in out, f"net check says: {out}")
    g2.sh("iptables -I INPUT -p tcp --dport 40000:60000 -j DROP")
    p = ctl.mv("net check tag:gpu --mb 8", user="agent", ok=False, timeout=180)
    check(p.returncode == 1 and "problem:" in p.stdout and "a firewall on g2" in p.stdout, f"a firewall: {p.stdout}{p.stderr}")
    g2.sh("iptables -D INPUT -p tcp --dport 40000:60000 -j DROP")
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
def test_connect_outside(lab):
    """A node on the internet joins a firewalled network: the network connects to it (meshvpn connect)."""
    corp = lab.network("corp", internal=True)
    pub = lab.network("pub")
    hub = lab.node("hub", [corp, pub])  # inside, but may connect out
    a = lab.node("a", [corp])
    edge = lab.node("edge", [pub])
    edge_ip = edge.net_ip(pub)
    # The firewall: nothing from the internet gets into the hub, answers to its own connections do.
    hub.sh(f"iptables -A INPUT -s {edge_ip} -m conntrack --ctstate NEW -j DROP")
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    a.mv(f"join {invite(hub)} --name a")
    a.up()
    wait(lambda: hub.online("a"), "a online")
    edge.mv(f"join {invite(hub)} --name edge --endpoint {edge_ip}:7870")
    edge.up()
    wait(lambda: any("meshvpn connect" in w for w in edge.status().get("warnings", [])),
         "edge says how to connect it", 60)
    check(not hub.online("edge"), "edge should not get in by itself")
    hub.mv(f"connect {edge_ip}")
    wait(lambda: hub.online("edge") and edge.online("hub"), "edge admitted and linked", 60)
    wait(lambda: a.online("edge") and edge.online("a"), "a and edge learn about each other", 60)
    check(ping(a, "edge.mesh") and ping(edge, "a.mesh"), "a <-> edge through the hub")
    check(not any("meshvpn connect" in w for w in edge.status().get("warnings", [])), "warning should be gone")


@test
def test_exit_node(lab):
    """Exit nodes: internet through another node (kernel and userspace clients), never into its LAN."""
    net = lab.network("net", internal=True)  # the clients' network: no internet
    inet = lab.network("inet", subnet="11.11.11.0/24")  # stands in for the internet
    lan = lab.network("lan", internal=True)  # the exit's own LAN
    gw = lab.node("gw", [net, inet, lan], sysctls=["net.ipv4.ip_forward=1"])
    client = lab.node("client", [net])
    box = lab.node("box", [net], caps=False)
    web = lab.node("web", [inet], install=False)
    printer = lab.node("printer", [lan], install=False)
    for n in (web, printer):
        n.sh(f"mkdir -p /srv && echo hello-{n.name} > /srv/index.html && "
             "(cd /srv && python3 -m http.server 8000 >/tmp/http.log 2>&1 &)")
    web_ip, printer_ip, gw_inet = web.net_ip(inet), printer.net_ip(lan), gw.net_ip(inet)
    gw.mv(f"init --name gw --endpoint {gw.c}:7870")
    gw.up()
    for n in (client, box):
        n.mv(f"join {invite(gw)} --name {n.name}")
        n.up()
        wait(lambda n=n: gw.online(n.name), f"{n.name} online")
    get = lambda n, url, proxy="": n.sh(f"curl -s -m5 {proxy} {url}", ok=False).stdout  # noqa: E731
    check("hello-web" not in get(client, f"http://{web_ip}:8000/"), "client should have no internet yet")
    p = client.mv("exit use gw", ok=False)
    check(p.returncode != 0 and "exit offer" in p.stdout + p.stderr, f"gw doesn't offer yet: {p.stdout}{p.stderr}")
    gw.mv("exit offer")
    wait(lambda: any(e["name"] == "gw" for e in client.mvj("exit list")["exits"]), "client sees the exit", 30)
    client.mv("exit use gw")
    check("gw" in (client.status().get("exit_via") or ""), "status shows the exit")
    check("hello-web" in get(client, f"http://{web_ip}:8000/"), "internet through the exit")
    check(gw_inet in web.sh("cat /tmp/http.log"), "the web server should see the exit's address")
    check("hello-printer" not in get(client, f"http://{printer_ip}:8000/"), "the exit's LAN must stay closed")
    check(ping(client, "gw.mesh") and ping(gw, "client.mesh"), "the mesh keeps working")
    # userspace client: through the SOCKS proxy
    box.mv("exit use gw")
    check("hello-web" in get(box, f"http://{web_ip}:8000/", "-x socks5h://127.0.0.1:1055"), "SOCKS through the exit")
    check("hello-printer" not in get(box, f"http://{printer_ip}:8000/", "-x socks5h://127.0.0.1:1055"),
          "the exit's LAN must stay closed to SOCKS too")
    # off again, and nothing left behind
    client.mv("exit off")
    check("hello-web" not in get(client, f"http://{web_ip}:8000/"), "exit off should end it")
    check("7869" not in client.sh("ip rule"), "routing rules left behind")
    client.mv("exit use gw")
    client.stop()
    check("7869" not in client.sh("ip rule") and "meshvpn-exit" not in client.sh("iptables-save"),
          "stopping meshvpn should clean up")
    gw.mv("exit offer --stop")
    check("meshvpn-exit" not in gw.sh("iptables-save"), "exit rules left behind")


@test
def test_exit_routed(lab):
    """An exit client whose links and incoming connections use its default route: they stay off the exit."""
    wan1 = lab.network("wan1", internal=True, subnet="10.231.1.0/24")
    wan2 = lab.network("wan2", internal=True, subnet="10.231.2.0/24")
    inet = lab.network("inet", subnet="11.11.12.0/24")
    rtr = lab.node("rtr", [wan1, wan2], install=False, sysctls=["net.ipv4.ip_forward=1"])
    gw = lab.node("gw", [wan2, inet], sysctls=["net.ipv4.ip_forward=1"])
    client = lab.node("client", [wan1])
    outsider = lab.node("outsider", [wan2], install=False, net_admin=True)
    web = lab.node("web", [inet], install=False)
    web.sh("mkdir -p /srv && echo hello-web > /srv/index.html && (cd /srv && python3 -m http.server 8000 >/dev/null 2>&1 &)")
    client.sh("mkdir -p /srv && echo hello-client > /srv/index.html && (cd /srv && python3 -m http.server 8080 >/dev/null 2>&1 &)")
    # client -> rtr -> everything else: its only way out is the default route
    client.sh(f"ip route replace default via {rtr.net_ip(wan1)}")
    for n in (gw, outsider):
        n.sh(f"ip route replace 10.231.1.0/24 via {rtr.net_ip(wan2)}")
    gw.mv(f"init --name gw --endpoint {gw.net_ip(wan2)}:7870")
    gw.up()
    client.mv(f"join {invite(gw)} --name client")
    client.up()
    wait(lambda: gw.online("client"), "client online through the router")
    gw.mv("exit offer")
    wait(lambda: client.mvj("exit list")["exits"], "client sees the exit", 30)
    client.mv("exit use gw")
    web_url = f"http://{web.net_ip(inet)}:8000/"
    check("hello-web" in client.sh(f"curl -s -m5 {web_url}", ok=False).stdout, "internet through the exit")
    out = outsider.sh(f"curl -s -m5 http://{client.net_ip(wan1)}:8080/", ok=False).stdout
    check("hello-client" in out, "connections from outside must still be answered")
    # A fresh start dials the exit node's link with the exit route already in place.
    client.stop()
    client.up()
    wait(lambda: gw.online("client") and client.online("gw"), "link comes back with the exit active", 60)
    check("hello-web" in client.sh(f"curl -s -m5 {web_url}", ok=False).stdout, "internet through the exit after restart")
    check(ping(client, "gw.mesh"), "mesh after restart")


@test
def test_nat_ipv6(lab):
    """Behind a NAT that changes ports (mobile networks), IPv4 hole punching fails - IPv6 through firewalls works; the NAT check tells them apart."""
    pub = lab.network("pub", subnet="198.51.101.0/24")
    v6 = lab.network("v6", ipv6_only=True, subnet="2001:db8:77::/64")
    hub = lab.node("hub", [pub], ip="198.51.101.10")
    hub2 = lab.node("hub2", [pub], ip="198.51.101.11")
    clients = {}
    for x, hard in (("A", True), ("B", False)):
        lan = lab.network(f"lan{x}", internal=True)
        r = lab.node(f"nat{x}", [pub, lan], caps=False, net_admin=True,
                     sysctls=["net.ipv4.ip_forward=1"], install=False)
        out_if = r.sh("ip -o -4 addr | awk '/198.51.101/ {print $2}'").strip()
        pub_ip = r.net_ip(pub)
        # A: a new random port for every destination (like a mobile network); B: one port kept.
        nat = (f"iptables -t nat -A POSTROUTING -o {out_if} -j MASQUERADE --random-fully" if hard else
               f"iptables -t nat -A POSTROUTING -o {out_if} -p udp --sport 7870 -j SNAT --to-source {pub_ip}:7870\n"
               f"iptables -t nat -A POSTROUTING -o {out_if} -j MASQUERADE")
        r.sh(f"""
            {nat}
            iptables -A INPUT -i {out_if} -m conntrack --ctstate NEW,INVALID -j DROP
        """)
        c = lab.node(f"client{x.lower()}", [lan, v6])
        c.sh(f"ip route add default via {r.net_ip(lan)}")
        # IPv6 without NAT, behind a stateful firewall like a home router's: only answers get in.
        c.sh("""
            ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
            ip6tables -A INPUT -i lo -j ACCEPT
            ip6tables -A INPUT -j DROP
        """)
        clients[x] = c
    hub.mv("init --name hub --endpoint 198.51.101.10:7870")
    hub.up()
    hub2.mv(f"join {invite(hub)} --name hub2 --endpoint 198.51.101.11:7870")
    hub2.up()
    for c in clients.values():
        c.mv(f"join {invite(hub)} --name {c.name}")
        c.up()
    a, b = clients["A"], clients["B"]
    wait(lambda: a.online("clientb") and a.online("hub2"), "everyone online", timeout=60)
    wait(lambda: "[2001:db8:77:" in (a.peer("clientb") or {}).get("path", ""), "direct path over IPv6", timeout=90)
    check(ping(a, b.ip(), 3), "ping over the IPv6 path")
    wait(lambda: a.status().get("nat_hard"), "A's NAT recognised as changing ports", timeout=60)
    sa = a.status()
    check(sa["ipv6"] and "2001:db8:77:" in sa["ipv6"][0], f"A's IPv6 address: {sa['ipv6']}")
    wait(lambda: "keeps one port" in (b.status().get("nat") or ""), "B's NAT recognised as keeping ports", timeout=60)
    check(not b.status().get("nat_hard"), "B is not hard")
    d = json.loads(a.mv("--json doctor", ok=False).stdout)
    nat = [x for x in d if x["name"] == "nat"]
    check(nat and nat[0]["level"] == "info", f"doctor's NAT check with IPv6 around: {nat}")
    # Without IPv6 the port-changing NAT leaves only the relay: IPv4 hole punching can't get through.
    a.sh("ip6tables -I OUTPUT -p udp -j DROP")
    a.sh(f"ping -c 300 -i 0.2 {b.ip()} >/dev/null 2>&1 &")
    wait(lambda: "relay" in (a.peer("clientb") or {}).get("path", ""), "falls back to the relay", timeout=60)
    time.sleep(20)
    check("relay" in (a.peer("clientb") or {}).get("path", ""), "no direct IPv4 path through the hard NAT")


@test
def test_share_fetch(lab):
    """Peer-to-peer datasets: fetch from several holders, intact, resume, repair, members only."""
    net, (a, b, c) = mesh(lab, ["a", "b", "c"])
    a.sh("mkdir -p /data/ds/train && head -c 30000000 /dev/urandom > /data/ds/train/s0 && echo x > /data/ds/labels"
         " && cp /bin/true /data/ds/tool && chmod 4777 /data/ds/tool")
    want = sha(a, "/data/ds")
    oid = a.mvj("share /data/ds")["id"]
    wait(lambda: any(o["id"] == oid for o in b.mvj("objects")), "b sees the object", 30)
    r = b.mvj(f"fetch {oid} /srv")
    check(sha(b, "/srv/ds") == want, "fetch on b corrupted")
    mode = b.sh("stat -c %a /srv/ds/tool").strip()
    check(mode == "755", f"fetched files must not be setuid or writable by others: {mode}")
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
    # Throughput for every pair, also those talking only over UDP or through a relay (g1-g3).
    for x, y in (("g1", "g2"), ("g2", "g1"), ("g1", "g3"), ("g3", "g1")):
        e = pair(x, y)
        check(e and (e["mesh_mbps"] or 0) > 1 and e["rtt_ms"] is not None, f"{x} -> {y} measured: {e}")
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
    instr = r[1]["result"]["instructions"]
    check("You are on node **ctl**" in instr and "tag:gpu" in instr, f"instructions with the live state: {instr[-600:]}")
    guide = ctl.sh("meshvpn guide", user="agent")
    check("# meshvpn for agents" in guide and "**ctl**" in guide and "1 online" in guide, guide[:500])
    check(ctl.sh("meshvpn guide --skill", user="agent").startswith("---\nname: meshvpn\n"), "skill format")
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
    # An account made with plain useradd has /bin/sh (dash): interactive logins get bash anyway
    # (history, completion), commands keep the account's shell.
    box.sh("useradd -m plain")
    box.mv("ssh allow everyone --as plain")
    p = hub.sh(f"ssh {o} -tt plain@box.mesh", user="agent", ok=False, input="echo SHELLIS-$BASH_VERSION-$SHELL\nexit\n")
    check("SHELLIS-5" in p.stdout and "/bin/bash" in p.stdout, f"interactive login should be bash: {p.stdout[-300:]!r}")
    check(ssh("plain@box.mesh", "'echo X${BASH_VERSION}X'").stdout.strip() == "XX", "commands keep /bin/sh")
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
def test_desktop_full(lab):
    """The one-file installer on a bare image: Xfce and Chromium with no package manager, then removed again."""
    check(FULL_RUN, "needs --desktop-full (build it with desktop/make-run.sh)")
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, install=False, cmd=["sleep", "infinity"], image="debian:12-slim")
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    run(["docker", "cp", FULL_RUN, f"{box.c}:/tmp/full.run"])
    # No apt-get update ran in this image: nothing could have come from a package manager.
    out = box.sh(f"sh /tmp/full.run join {invite(hub)} --name box --ssh-allow-all agent", timeout=600)
    check("with Xfce and Chromium" in out, out[-500:])
    box.sh("useradd -m agent")
    wait(lambda: hub.sh("su agent -c 'ssh -o BatchMode=yes -o ConnectTimeout=5 agent@box.mesh true'", ok=False).returncode == 0,
         "ssh from hub to box", 60)
    hub.sh("cd /home/agent && (meshvpn desktop box --no-browser --port 18082 > /tmp/desktop.out 2>&1 &)", user="agent")
    out = wait(lambda: (lambda t: t if "#" in t else None)(hub.sh("cat /tmp/desktop.out", ok=False).stdout), "viewer link", 10)
    token = out.split("#", 1)[1].split()[0]
    p = hub.sh(f"python3 /usr/local/bin/desktop_client.py 18082 {token} full", user="agent", ok=False, timeout=300)
    check(p.returncode == 0, f"packed desktop: {p.stdout[-2000:]}{p.stderr[-1000:]}"
          + box.sh("tail -30 /tmp/meshvpn-desktop-*/session.log", ok=False).stdout)
    check("dpkg" in box.sh("cat /tmp/full_typed", ok=False).stdout,
          "a terminal of the packed desktop runs this machine's own programs")
    log = box.sh("cat /tmp/meshvpn-desktop-*/session.log", ok=False).stdout
    check("using the built-in desktop" not in log, f"Xfce should have stayed up: {log[-1000:]}")
    # What the licences of what's inside ask for, and none of the patented codecs.
    box.sh("test -s /opt/meshvpn-desktop-full/README && test -s /opt/meshvpn-desktop-full/THIRD-PARTY-LICENSES.txt "
           "&& ls /opt/meshvpn-desktop-full/licenses | grep -q ^glibc")
    found = box.sh("ls /nix/store | grep -E -- '-(x264|x265|openh264|ffmpeg|gst-plugins-bad|gst-plugins-ugly|gst-libav|fdk-aac|faad2|libde265|ldacBT|libfreeaptx|gtk4)-' ; true")
    check(not found.strip(), f"should not be shipped: {found}")
    # An old browser gets a warning, and stops nothing.
    check("Chromium" in box.mv("doctor", ok=False).stdout and "security fixes" not in box.mv("doctor", ok=False).stdout, "doctor names the browser")
    box.sh("sed -i 's/^date=.*/date=1000/' /opt/meshvpn-desktop-full/browser")
    check("missed security fixes" in box.mv("doctor", ok=False).stdout, "doctor warns about an old browser")
    # Removing it leaves meshvpn, and nothing of the desktop.
    box.sh("cd /home/agent; su agent -s /bin/sh -c 'meshvpn desktop stop'", ok=False)
    box.sh("sh /tmp/full.run --uninstall")
    left = box.sh("ls /usr/local/bin; ls /nix /opt/meshvpn-desktop-full 2>&1", ok=False).stdout
    check("chromium" not in left and "xfce4" not in left and "store" not in left, f"left behind: {left}")
    check("meshvpn" in left, "meshvpn stays")


@test
def test_desktop_full_user(lab):
    """The one-file installer without root in a stock container: no namespaces, nothing outside the home but a link."""
    check(FULL_RUN, "needs --desktop-full (build it with desktop/make-run.sh)")
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, install=False, cmd=["sleep", "infinity"], image="debian:12-slim")
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    box.sh("useradd -m dev && useradd -m other")
    run(["docker", "cp", FULL_RUN, f"{box.c}:/tmp/full.run"])
    box.sh("chmod 644 /tmp/full.run")
    # What this is for: this container doesn't allow user namespaces.
    p = box.sh("unshare -Urm true", user="dev", ok=False)
    check(p.returncode != 0, "this test should run where user namespaces are not allowed")
    # A daemon whose PATH doesn't have ~/.local/bin, as is usual.
    home = "export HOME=/home/dev; "
    out = box.sh(home + f"sh /tmp/full.run join {invite(hub)} --name box", user="dev", timeout=600)
    check("with Xfce and Chromium" in out and "for this user alone" in out, out[-800:])
    check(box.sh("test -e /nix -o -e /usr/local/bin/meshvpn -o -e /opt/meshvpn-desktop-full && echo root || echo clean").strip() == "clean",
          "without root nothing goes in the system's places")
    mv = "/home/dev/.local/bin/meshvpn"
    prefix = box.sh("cat /home/dev/.local/share/meshvpn/desktop-full/prefix").strip()
    check(len(prefix) == len("/nix/store") and prefix.startswith("/tmp/mv"), prefix)
    box.sh(home + f"{mv} ssh allow agent@hub --as dev", user="dev")
    wait(lambda: hub.online("box"), "box online at hub")
    o = "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8"
    wait(lambda: hub.sh(f"ssh {o} dev@box.mesh whoami", user="agent", ok=False).stdout.strip() == "dev",
         "login to the rootless node", 60)
    hub.sh("cd /home/agent && (meshvpn desktop box --user dev --no-browser --port 18083 > /tmp/desktop.out 2>&1 &)", user="agent")
    out = wait(lambda: (lambda t: t if "#" in t else None)(hub.sh("cat /tmp/desktop.out", ok=False).stdout), "viewer link", 30)
    token = out.split("#", 1)[1].split()[0]
    p = hub.sh(f"python3 /usr/local/bin/desktop_client.py 18083 {token} full", user="agent", ok=False, timeout=300)
    check(p.returncode == 0, f"packed desktop: {p.stdout[-2000:]}{p.stderr[-1000:]}"
          + box.sh("tail -30 /tmp/meshvpn-desktop-*/session.log", ok=False).stdout)
    check("dpkg" in box.sh("cat /tmp/full_typed", ok=False).stdout, "a terminal of this desktop runs the machine's programs")
    log = box.sh("cat /tmp/meshvpn-desktop-*/session.log", ok=False).stdout
    check("using the built-in desktop" not in log, f"Xfce should have stayed up: {log[-1000:]}")
    box.sh(home + f"{mv} desktop stop", user="dev", ok=False)
    # Licences and sources are as easy to find as with root.
    box.sh("cd /home/dev/.local/share/meshvpn/desktop-full/opt/meshvpn-desktop-full && test -s README "
           "&& test -s THIRD-PARTY-LICENSES.txt && ls licenses | grep -q ^glibc")
    # /tmp emptied: the link comes back. Someone else's link: refused, nothing of theirs runs.
    wrapper = "/home/dev/.local/bin/chromium --version"
    box.sh(f"rm -f {prefix}")
    box.sh(home + wrapper, user="dev")
    check(box.sh(f"stat -c %U {prefix}").strip() == "dev", "the link should be back")
    box.sh(f"rm -f {prefix}")
    box.sh(f"ln -s /home/other {prefix} && chown -h other {prefix}")
    p = box.sh(home + wrapper, user="dev", ok=False)
    check(p.returncode != 0 and "not ours" in p.stderr, f"someone else's link: {p.stdout}{p.stderr}")
    # Installing again gets out of the way of it.
    out = box.sh(home + "sh /tmp/full.run", user="dev", timeout=600)
    check("with Xfce and Chromium" in out, out[-500:])
    new = box.sh("cat /home/dev/.local/share/meshvpn/desktop-full/prefix").strip()
    check(new != prefix, "should have taken another name")
    box.sh(home + wrapper, user="dev")
    # A second user of the machine has their own.
    box.sh("export HOME=/home/other; sh /tmp/full.run", user="other", timeout=600)
    other = box.sh("cat /home/other/.local/share/meshvpn/desktop-full/prefix").strip()
    check(other != new, "two users, two links")
    # Removing it: the desktop goes, meshvpn stays, the other user's stays.
    box.sh(home + "sh /tmp/full.run --uninstall", user="dev")
    left = box.sh(f"ls /home/dev/.local/bin; ls /home/dev/.local/share/meshvpn; test -e {new} && echo LINK; true")
    check("xfce4" not in left and "chromium" not in left and "desktop-full" not in left and "LINK" not in left, f"left behind: {left}")
    check("meshvpn" in left, "meshvpn stays")
    box.sh("export HOME=/home/other; /home/other/.local/bin/chromium --version", user="other")


@test
def test_desktop_full_nameless(lab):
    """A container user that's only a number, not in /etc/passwd: installs, logs in, gets the desktop."""
    check(FULL_RUN, "needs --desktop-full (build it with desktop/make-run.sh)")
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, install=False, cmd=["sleep", "infinity"], image="debian:12-slim")
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    box.sh("mkdir /tmp/h; chown 54321:54321 /tmp/h")
    run(["docker", "cp", FULL_RUN, f"{box.c}:/tmp/full.run"])
    box.sh("chmod 644 /tmp/full.run")
    me = lambda c, **k: box.sh(f"setpriv --reuid=54321 --regid=54321 --clear-groups env HOME=/tmp/h sh -c '{c}'", **k)
    me(f"sh /tmp/full.run join {invite(hub)} --name box", timeout=600)
    wait(lambda: hub.online("box"), "box online at hub")
    me("/tmp/h/.local/bin/meshvpn ssh allow agent@hub --as 54321")
    o = "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8"
    wait(lambda: hub.sh(f"ssh {o} 54321@box.mesh id -u", user="agent", ok=False).stdout.strip() == "54321",
         "login under the number", 60)
    # Allowed names don't help: no other user, no other number, no root.
    me("/tmp/h/.local/bin/meshvpn ssh allow agent@hub --as 54322")
    me("/tmp/h/.local/bin/meshvpn ssh allow agent@hub --as root")
    for name in ("54322", "root"):
        p = hub.sh(f"ssh {o} {name}@box.mesh id -u", user="agent", ok=False)
        check(p.returncode != 0, f"{name} should not log in: {p.stdout}")
    hub.sh("cd /home/agent && (meshvpn desktop box --user 54321 --no-browser --port 18085 > /tmp/desktop.out 2>&1 &)", user="agent")
    out = wait(lambda: (lambda t: t if "#" in t else None)(hub.sh("cat /tmp/desktop.out", ok=False).stdout), "viewer link", 30)
    token = out.split("#", 1)[1].split()[0]
    p = hub.sh(f"python3 /usr/local/bin/desktop_client.py 18085 {token} full", user="agent", ok=False, timeout=300)
    check(p.returncode == 0, f"packed desktop: {p.stdout[-2000:]}{p.stderr[-1000:]}"
          + box.sh("tail -30 /tmp/meshvpn-desktop-*/session.log", ok=False).stdout)
    check("dpkg" in box.sh("cat /tmp/full_typed", ok=False).stdout, "a terminal of this desktop runs the machine's programs")


def full_user_session(hub, box, port, label):
    """A desktop on `box` as its user dev, opened from the hub, used and closed again."""
    o = "-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8"
    wait(lambda: hub.sh(f"ssh {o} dev@box.mesh whoami", user="agent", ok=False).stdout.strip() == "dev", f"{label}: login", 90)
    hub.sh(f"rm -f /tmp/desktop.out; cd /home/agent && (meshvpn desktop box --user dev --no-browser --port {port} > /tmp/desktop.out 2>&1 &)",
           user="agent")
    out = wait(lambda: (lambda t: t if "#" in t else None)(hub.sh("cat /tmp/desktop.out", ok=False).stdout), f"{label}: viewer link", 30)
    token = out.split("#", 1)[1].split()[0]
    p = hub.sh(f"python3 /usr/local/bin/desktop_client.py {port} {token} full", user="agent", ok=False, timeout=300)
    log = box.sh("tail -30 /tmp/meshvpn-desktop-*/session.log", ok=False).stdout
    check(p.returncode == 0, f"{label}: {p.stdout[-1500:]}{p.stderr[-800:]}{log}")
    check("dpkg" in box.sh("cat /tmp/full_typed", ok=False).stdout, f"{label}: a terminal runs the machine's programs")
    check("using the built-in desktop" not in log, f"{label}: Xfce should have stayed up: {log[-600:]}")
    box.sh("$HOME/.local/bin/meshvpn desktop stop", ok=False)


@test
def test_desktop_full_container(lab):
    """A non-root image: read-only root with the home on a volume, a restart, and the desktop built into an image."""
    check(FULL_RUN, "needs --desktop-full (build it with desktop/make-run.sh)")
    net = lab.network("net")
    hub = lab.node("hub", [net])
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    base, baked, vol = f"{lab.prefix}-base", f"{lab.prefix}-baked", f"{lab.prefix}-home"

    def start(image, *extra):
        c = f"{lab.prefix}-box"
        run(["docker", "rm", "-f", c], ok=False)
        run(["docker", "run", "-d", "--name", c, "--hostname", "box", "--network", net, *extra, image, "sleep", "infinity"])
        if c not in lab.containers:
            lab.containers.append(c)
        return Node(lab, "box", c)

    def up(box):
        run(["docker", "exec", "-d", box.c, "sh", "-c", "$HOME/.local/bin/meshvpn up >> /tmp/meshvpn.log 2>&1"])

    with tempfile.TemporaryDirectory(dir=os.path.dirname(FULL_RUN)) as d:
        os.link(FULL_RUN, f"{d}/full.run")
        open(f"{d}/Dockerfile", "w").write(
            "FROM debian:12-slim\nRUN useradd -m -u 1000 dev\nUSER dev\nENV HOME=/home/dev\n")
        run(["docker", "build", "-q", "-t", base, d], timeout=300)
        # What the README tells people to write.
        open(f"{d}/Dockerfile", "w").write(
            f"FROM {base}\nCOPY --chown=1000:1000 full.run /tmp/full.run\nRUN sh /tmp/full.run && rm -f /tmp/full.run\n")
        run(["docker", "build", "-q", "-t", baked, d], timeout=600)
    run(["docker", "volume", "create", vol])
    try:
        # Built into the image: /tmp is empty when it starts, and it joins only now.
        home = f"{vol}:/home/dev"
        box = start(baked, "--tmpfs", "/tmp", "-v", home)
        check(box.sh("id -u").strip() == "1000", "should run as the image's user")
        box.sh(f"$HOME/.local/bin/meshvpn join {invite(hub)} --name box")
        up(box)
        wait(lambda: hub.online("box"), "box online at hub")
        box.sh("$HOME/.local/bin/meshvpn ssh allow agent@hub --as dev")
        full_user_session(hub, box, 18086, "built into the image")
        # docker restart: started again by the entrypoint, as there's nothing else to do it.
        run(["docker", "restart", box.c])
        up(box)
        full_user_session(hub, box, 18087, "after a restart")
        # A new container, nothing writable but the home and /tmp: the same node.
        box = start(baked, "--read-only", "--tmpfs", "/tmp", "-v", home)
        up(box)
        full_user_session(hub, box, 18088, "read-only root, new container")
        nodes = [n["name"] for n in hub.mvj("nodes")]
        check(nodes.count("box") == 1, f"the same node, not a second one: {nodes}")
    finally:
        run(["docker", "rm", "-f", f"{lab.prefix}-box"], ok=False)
        run(["docker", "volume", "rm", vol], ok=False)
        run(["docker", "rmi", "-f", baked, base], ok=False)


@test
def test_desktop_xfce(lab):
    """meshvpn desktop setup --xfce, then an Xfce desktop: windows as tabs, typing, persistence, log out."""
    check(DESKTOP_BUNDLE, "needs --desktop-bundle (build it with desktop/build-bundle.sh)")
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, cmd=["sleep", "infinity"])
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    box.mv(f"join {invite(hub)} --name box --ssh-allow-all agent")
    box.up()
    run(["docker", "cp", DESKTOP_BUNDLE, f"{box.c}:/tmp/desktop.tar.gz"])
    out = box.mv("desktop setup --from /tmp/desktop.tar.gz --xfce", timeout=900)
    check("Xfce installed" in out, out[-500:])
    box.sh("chmod 644 /tmp/desktop.tar.gz")
    box.mv("desktop setup --from /tmp/desktop.tar.gz", user="agent")
    wait(lambda: hub.sh("su agent -c 'ssh -o BatchMode=yes -o ConnectTimeout=5 agent@box.mesh true'", ok=False).returncode == 0,
         "ssh from hub to box", 60)
    hub.sh("cd /home/agent && (meshvpn desktop box --no-browser --port 18081 > /tmp/desktop.out 2>&1 &)", user="agent")
    out = wait(lambda: (lambda t: t if "#" in t else None)(hub.sh("cat /tmp/desktop.out", ok=False).stdout), "viewer link", 10)
    token = out.split("#", 1)[1].split()[0]
    p = hub.sh(f"python3 /usr/local/bin/desktop_client.py 18081 {token} xfce", user="agent", ok=False, timeout=300)
    check(p.returncode == 0, f"xfce session: {p.stdout[-2000:]}{p.stderr[-1000:]}")
    r = json.loads(p.stdout.strip().splitlines()[-1])
    check(r["panels_hidden"], f"panels and the desktop should not be tabs: {r}")
    check(sorted(r["first"]) == sorted(r["again"]), f"windows should survive the browser: {r}")
    procs = box.sh("ps -o user=,comm= -u agent", ok=False).stdout
    for p_ in ("xfwm4", "xfce4-panel", "Xvfb"):
        check(p_ in procs, f"{p_} should run as agent: {procs}")
    check(box.sh("cat /tmp/xfce_typed", ok=False).stdout.strip() == "typed-in-xfce", "typing into the Xfce terminal")
    # Logging out of Xfce ends the session.
    sess = box.sh("ls -d /tmp/meshvpn-desktop-*", user="agent").strip()
    box.sh(f"DISPLAY=$(grep -o 'display :[0-9]*' {sess}/session.log | tail -1 | cut -c9-) XAUTHORITY={sess}/Xauthority "
           "xfce4-session-logout --logout --fast", user="agent", ok=False)
    wait(lambda: box.sh("pgrep -x Xvfb", ok=False).returncode != 0, "session ends after logging out", 30)


@test
def test_desktop_fallback(lab):
    """An Xfce that dies right after starting: the session falls back to the built-in desktop."""
    check(DESKTOP_BUNDLE, "needs --desktop-bundle (build it with desktop/build-bundle.sh)")
    box = lab.node("box", [lab.network("net")], caps=False, cmd=["sleep", "infinity"])
    box.sh("printf '#!/bin/sh\\necho broken >&2\\nexit 1\\n' > /usr/local/bin/xfce4-session && chmod 755 /usr/local/bin/xfce4-session")
    run(["docker", "cp", DESKTOP_BUNDLE, f"{box.c}:/tmp/desktop.tar.gz"])
    box.sh("chmod 644 /tmp/desktop.tar.gz")
    box.mv("desktop setup --from /tmp/desktop.tar.gz", user="agent")
    # The viewer reaches the session through `docker exec` here (no mesh needed for this).
    env = f"MESHVPN_DESKTOP_BRIDGE='su agent -c \"meshvpn desktop attach\"'"
    box.sh(f"cd /tmp && ({env} meshvpn desktop box --no-browser --port 18082 > /tmp/desktop.out 2>&1 &)")
    out = wait(lambda: (lambda t: t if "#" in t else None)(box.sh("cat /tmp/desktop.out", ok=False).stdout), "viewer link", 10)
    token = out.split("#", 1)[1].split()[0]
    p = box.sh(f"python3 /usr/local/bin/desktop_client.py 18082 {token} fallback", ok=False, timeout=180)
    check(p.returncode == 0, f"fallback: {p.stdout[-2000:]}{p.stderr[-1000:]}")


@test
def test_console(lab):
    """meshvpn console: node list, shells as tabs with each node's default user (or the one last used), desktop link."""
    net = lab.network("net")
    hub = lab.node("hub", [net])
    box = lab.node("box", [net], caps=False, cmd=["sleep", "infinity"])
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    hub.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    box.mv(f"join {invite(hub)} --name box --ssh-allow-all agent")
    box.up()
    wait(lambda: hub.online("box") and box.status().get("ssh_server") == "built-in", "box online with ssh")
    # root on hub has no ssh config: the console logs in as the user box announces (from
    # --ssh-allow-all agent), not as root.
    hub.sh("ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519")
    check("agent" in box.mv("ssh default-user"), "box should announce agent")
    wait(lambda: (hub.peer("box") or {}).get("login_user") == "agent", "hub learns box's default user", 30)
    wait(lambda: hub.sh("ssh -o BatchMode=yes -o ConnectTimeout=5 agent@box.mesh true", ok=False).returncode == 0,
         "ssh from hub to box", 60)

    def console(steps, env="SSH_CONNECTION='10.9.9.9 50000 10.1.2.3 2222'"):
        quoted = " ".join("'" + s + "'" for s in steps)
        p = hub.sh(f"cd /root && {env} console_driver.py {quoted}", ok=False, timeout=120)
        check(p.returncode == 0, f"console: {p.stdout[-3000:]}{p.stderr[-500:]}")

    console([
        "expect:NODE", "expect:box",
        "key:down", "expect:log in as agent", "key:enter", "expect:agent@box",
        "send:echo MARK-$(hostname)\\r", "expect:MARK-box",
        "send:\\x020", "expect:shells as",   # Ctrl+B 0: back to the node list
        "send:\\x021", "send:exit\\r", "expect:session ended",
        "key:enter", "send:d", "expect:ssh -L 7880:127.0.0.1:7880 -p 2222 root@10.1.2.3",
    ])
    # Another account once (u), and the console remembers it for this node.
    box.sh("useradd -m -s /bin/bash other")
    box.mv("ssh allow everyone --as other")
    console(["expect:box", "key:down", "send:u", "send:\\x7f\\x7f\\x7f\\x7f\\x7fother\\r", "expect:other@box",
             "send:echo WHO-$(whoami)\\r", "expect:WHO-other", "send:exit\\r", "expect:session ended", "key:enter"])
    console(["expect:box", "key:down", "key:enter", "expect:other@box", "send:echo WHO-$(whoami)\\r", "expect:WHO-other"])


@test
def test_small_mtu(lab):
    """A path that drops big UDP datagrams (VPN, WSL2): detected, packets split, TCP and ssh still work."""
    net = lab.network("net")
    hub, a, b = (lab.node(n, [net]) for n in ("hub", "a", "b"))
    # b's network drops UDP datagrams of 1300 bytes and more (small probes still pass) - from
    # the start, like a notebook behind such a network.
    for chain, port in (("INPUT", "--dport"), ("OUTPUT", "--sport")):
        b.sh(f"iptables -A {chain} -p udp {port} 7870 -m length --length 1300:65535 -j DROP")
    hub.mv(f"init --name hub --endpoint {hub.c}:7870")
    hub.up()
    for n in (a, b):
        n.mv(f"join {invite(hub)} --name {n.name} --ssh-allow-all agent")
        n.up()
    wait(lambda: "direct UDP" in (a.peer("b") or {}).get("path", ""), "direct UDP path a-b")
    wait(lambda: "splitting" in a.peer("b")["path"], "a notices the small path to b", 30)
    try:
        wait(lambda: "splitting" in b.peer("a")["path"], "b notices it too (the data flows b -> a)", 30)
    except Failed:
        raise Failed(f"b never splits towards a: b sees {b.peer('a')}, a sees {a.peer('b')['path']}")
    b.sh("mkdir -p /srv && head -c 5000000 /dev/urandom > /srv/blob && (cd /srv && python3 -m http.server 8080 >/dev/null 2>&1 &)")
    time.sleep(1)
    want = b.sh("sha256sum /srv/blob | cut -c1-16").strip()
    got = a.sh("curl -s -m 60 http://b.mesh:8080/blob | sha256sum | cut -c1-16", ok=False).stdout.strip()
    check(got == want, f"5 MB over the small path: {got!r} != {want!r}")
    check("direct UDP" in a.peer("b")["path"], f"should still go direct: {a.peer('b')['path']}")
    a.sh("su agent -c 'ssh-keygen -q -t ed25519 -N \"\" -f ~/.ssh/id_ed25519'")
    wait(lambda: a.sh("su agent -c 'ssh -o BatchMode=yes -o ConnectTimeout=8 agent@b.mesh echo ok'", ok=False).stdout.strip() == "ok",
         "ssh (big key exchange) over the small path", 60)
    # A normal path is not split ...
    check("splitting" not in a.peer("hub")["path"], f"a-hub should carry full size: {a.peer('hub')['path']}")
    # ... until its network changes (e.g. a VPN comes up): noticed at the next check (60 s).
    for chain, port in (("INPUT", "--dport"), ("OUTPUT", "--sport")):
        hub.sh(f"iptables -A {chain} -p udp {port} 7870 -m length --length 1300:65535 -j DROP")
    wait(lambda: "splitting" in a.peer("hub")["path"], "a notices that the path to hub got small", 90)


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
    global BINARY, DESKTOP_BUNDLE, FULL_RUN
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True, help="static meshvpn binary to test")
    ap.add_argument("--desktop-bundle", help="meshvpn-desktop-<arch>.tar.gz (desktop/build-bundle.sh) for the desktop test")
    ap.add_argument("--desktop-full", help="meshvpn-full-<arch>.run (desktop/make-run.sh), adds the desktop_full tests")
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
    FULL_RUN = a.desktop_full and os.path.abspath(a.desktop_full)
    names = a.tests or [n for n in TESTS if not n.startswith("desktop_full") or FULL_RUN]
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

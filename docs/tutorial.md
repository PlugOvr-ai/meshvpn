# meshvpn tutorial

This tutorial builds a complete network step by step: a server with a public address, workstations and GPU machines
(some behind firewalls), Docker containers (some without root) and a notebook running WSL. Along the way it shows the
everyday tools: SSH without passwords, the terminal console, the remote desktop in the browser, working on many nodes
at once, measuring the network, and what to do when something doesn't work.

Every section stands on its own; skip what you don't need. The [README](../README.md) is the short reference.

**Contents**

1. [How meshvpn works in two minutes](#1-how-meshvpn-works-in-two-minutes)
2. [Install meshvpn](#2-install-meshvpn)
3. [Create the network](#3-create-the-network)
4. [Add machines](#4-add-machines)
5. [Machines behind a firewall](#5-machines-behind-a-firewall)
6. [Docker containers](#6-docker-containers)
7. [SSH between nodes](#7-ssh-between-nodes)
8. [The console: the mesh in your terminal](#8-the-console-the-mesh-in-your-terminal)
9. [Remote desktop in the browser](#9-remote-desktop-in-the-browser)
10. [Working on many nodes at once](#10-working-on-many-nodes-at-once)
11. [Measuring the network](#11-measuring-the-network)
12. [Running the network](#12-running-the-network)
13. [Troubleshooting](#13-troubleshooting)
14. [Reference](#14-reference)

---

## 1. How meshvpn works in two minutes

* Every machine in the network is a **node**. Each node gets a fixed address in `100.64.0.0/10` (derived from its
  identity, so it never changes) and a name: `gpu1` becomes `gpu1.mesh`.
* There is **no central server**. Nodes find each other by gossip: each one tells its neighbours what it knows. Any
  node with a reachable address can be the first contact for new nodes; it is just a node like the others.
* Traffic takes the best **path** available, and `meshvpn status` shows which one:
  * `direct UDP …`: straight from node to node over UDP, also through most NATs (hole punching). The normal case.
  * `direct …`: over a TCP connection between the two nodes.
  * `relay via X`: through another node, when the two can't reach each other at all (firewalls, tunnels).
* Everything is **encrypted end to end** between the two nodes, whichever path it takes.
* By default a network is **managed**: the node that created it is the admin; only admins create invites and ban
  nodes. Each invite is single use and expires (default: 24 hours).
* meshvpn can run as root (it creates a network interface `mesh0`, every program can use the mesh) or **without
  root** (it runs a small network stack itself; see section 6).

## 2. Install meshvpn

On any Linux machine (x86_64, ARM64, ARMv7, Raspberry Pi). The binary is static and needs nothing else:

```sh
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh | sudo sh
```

The installer uses the machine's proxy if one is configured (environment, `/etc/environment`, desktop settings), so
it also works in company networks.

Other ways:

| Situation | Command |
|---|---|
| Debian, Ubuntu, Raspberry Pi OS | download the `.deb` from the release, `sudo apt install ./meshvpn_*.deb` |
| Fedora, RHEL, openSUSE | download the `.rpm`, `sudo dnf install ./meshvpn-*.rpm` |
| **No root / no sudo** | `curl -fsSL …/install.sh \| sh -s -- --user` (see section 6) |
| No internet on the machine | from a jump host with `deploy.sh` (see section 5) |
| Install and join in one go | `curl -fsSL …/install.sh \| sudo sh -s -- join mesh1-…` |

Check it: `meshvpn --version`.

## 3. Create the network

Start on the machine that is easiest to reach: a server with a public IP address or a DNS name. This is not a
special "server" for meshvpn, just a good first contact for the others.

```sh
sudo meshvpn init --network lab --endpoint vps.example.com:7870
sudo meshvpn install
```

* `--endpoint` is the address other nodes use to reach this one. Open **TCP and UDP port 7870** in the server's
  firewall (and the cloud provider's security group).
* `install` runs meshvpn as a service (systemd), so it starts at boot. Without systemd (containers) it runs meshvpn in
  the background instead and tells you how to start it with the container.
* `init` prints the first invite code (`mesh1-…`). This node is the network's admin.

Look at it:

```sh
$ meshvpn status
● vps  100.78.210.211  (3f9c21a0 on mesh0, network "lab", meshvpn 0.13.1)
  reachable at: vps.example.com:7870

No other nodes known yet.
```

`meshvpn status` works without sudo. If something looks wrong, run `sudo meshvpn doctor`; it checks the usual
problems and says how to fix them.

## 4. Add machines

On the admin node, create an invite for each new machine:

```sh
sudo meshvpn invite                 # single use, valid 24 h
sudo meshvpn invite --uses 5 --expires 7d   # for several machines
```

On the new machine:

```sh
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh | sudo sh -s -- join mesh1-…
```

(or, if meshvpn is already installed: `sudo meshvpn join mesh1-… && sudo meshvpn install`). The machine's host name
becomes its node name; choose another with `--name`, or later with `sudo meshvpn rename <name>`.

Within seconds:

```sh
$ meshvpn status
● workstation  100.122.144.177  (a69e03bd on mesh0, network "lab", meshvpn 0.13.1)

NAME      IP               STATUS      RTT  VERSION   PATH
vps       100.78.210.211   online     15ms  0.13.1    direct UDP 178.77.77.96:7870
gpu1      100.64.166.69    online      1ms  0.13.1    direct UDP 192.168.1.160:7870
```

Every program can now use the mesh: `ping gpu1.mesh`, `ssh gpu1.mesh`, `http://gpu1.mesh:8888` …

**Tags** group machines, so you can address them together later (`tag:gpu`):

```sh
sudo meshvpn join mesh1-… --tag gpu,trainer     # when joining
sudo meshvpn tag add gpu                        # or later, on the node itself
meshvpn nodes tag:gpu                           # list them, with CPUs, memory and GPUs
```

An invite that has expired or was already used is refused right away with a clear message; ask an admin for a new
one.

## 5. Machines behind a firewall

### The machine can make an SSH connection to some host

That is enough. meshvpn builds a reverse SSH tunnel and sends all its traffic through it:

```sh
sudo meshvpn join mesh1-… --ssh user@jump.example.com --ssh-remote-port 7871
```

* Outgoing, the node reaches every other node through the tunnel; nothing else has to be allowed.
* Incoming, other nodes connect to `jump.example.com:7871`. That needs `GatewayPorts clientspecified` in the jump
  host's `sshd_config`. Without it the node still works: it connects out, and others reach it through relays.
* `ssh user@jump.example.com` must work without a password as root (or pass `--ssh-identity /path/to/key`).

### The machine has no internet at all

If you can SSH into it from a jump host (often through an existing reverse tunnel such as `localhost:2222`), install
it **from the jump host**. Nothing is installed on the jump host itself:

```sh
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/deploy.sh \
  | sh -s -- --invite mesh1-… user@localhost -p 2222
```

The script uploads meshvpn, joins the network and sets up the tunnel back to the jump host. Run it again later to
update the device.

## 6. Docker containers

Three cases, depending on what the container may do.

### a) The container may have a network interface

Start it with `--cap-add=NET_ADMIN --device /dev/net/tun`. meshvpn then works exactly as on a normal machine. Without
systemd, `meshvpn install` starts meshvpn in the background and prints the line for the container's entrypoint, e.g.:

```sh
/usr/local/bin/meshvpn --dir /etc/meshvpn up &
```

Keep `/etc/meshvpn` on a volume, so the node keeps its identity when the container is recreated.

### b) Root, but no NET_ADMIN

meshvpn notices that it can't create an interface and switches to **userspace mode** by itself:

* Other nodes reach the services in the container normally: `ssh box.mesh`, `curl http://box.mesh:8080`.
* From inside the container, `ssh user@node.mesh` works directly. Other programs reach the mesh through the SOCKS
  proxy `socks5h://127.0.0.1:1055`, for example `ALL_PROXY=socks5h://127.0.0.1:1055 curl http://gpu1.mesh:8000`.

### c) No root, no sudo (rootless)

```sh
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh | sh -s -- --user join mesh1-…
```

meshvpn goes to `~/.local/bin`, its configuration to `~/.config/meshvpn`, nothing outside your home directory. It
runs in userspace mode (as in b). Commands that change only meshvpn itself (`status`, `rename`, `tag`, `ssh allow`,
`desktop`, `update`) work without sudo.

What a rootless install can't do: make `<name>.mesh` names known to every program (only ssh and the SOCKS proxy know
them), and log anyone in except its own user.

**No SSH server in the container?** No problem: meshvpn answers `ssh user@box.mesh` itself (section 7).

## 7. SSH between nodes

Each machine decides itself who may log in to it **without a password**. Every node publishes the public SSH keys of
its users (`~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`), and the rules on the target machine say which of them may log
in as which local account.

On the machine you want to log in **to**:

```sh
sudo meshvpn ssh allow alice@laptop --as alice     # alice on the laptop may log in as alice
sudo meshvpn ssh allow laptop --as ubuntu          # any user of the laptop may log in as ubuntu
sudo meshvpn ssh allow everyone --as ubuntu        # every node, also ones that join later
sudo meshvpn ssh deny alice@laptop                 # take it back
sudo meshvpn ssh                                   # an editor for all of this (full screen)
meshvpn ssh list                                   # rules, the keys this machine offers, refused logins
```

For machines everybody works on (cluster nodes, containers), set it when joining:
`sudo meshvpn join mesh1-… --ssh-allow-all ubuntu`. `ssh allow` also works before meshvpn runs for the first time
(e.g. in a Dockerfile); it writes the rule to the configuration.

Then, from the laptop: `ssh alice@server.mesh`. Host keys are known automatically, so there is no "are you sure?"
question.

**How it works on the target:** with an OpenSSH server, meshvpn adds a small configuration file that makes sshd ask
meshvpn for allowed keys. Without an SSH server (most containers), **meshvpn's built-in SSH server** answers instead:
shells with a terminal, commands, `scp`/`sftp`, `-L` port forwarding. It is only reachable through the mesh, and it
logs users in as themselves (a rootless meshvpn: only its own user). Accounts with a bare `/bin/sh` get bash for
interactive logins when it is installed.

**A login is refused?** On the target, `meshvpn ssh list` shows recent refusals with the reason, e.g.:

```
Recently refused logins (built-in SSH server):
  2 min ago: login as root from 100.84.224.109: no rule lets laptop log in as root (allow it: meshvpn ssh allow laptop --as root)
  1 min ago: login as ghost from 100.84.224.109: alice@laptop may log in as ghost, but there is no user ghost here
```

The most common causes: logging in with the wrong user name (`ssh node.mesh` uses your local name, while the rule
says `--as ubuntu`), and a machine without an SSH key (create one with `ssh-keygen`; it is published within a minute).

## 8. The console: the mesh in your terminal

Often all you have is an SSH login on one machine (for example the server, from outside the mesh). Type:

```sh
meshvpn
```

and you get a full-screen terminal desktop:

* **Tab 0** lists all nodes: online state, path, latency, GPUs, version and tags, and details of the selected node
  (OS, CPU, memory, disk, GPUs, LAN).
* **Enter** opens a shell on the selected node in a new tab, as the node's default user: set it on the node with
  `sudo meshvpn ssh default-user ubuntu` (nodes joined with `--ssh-allow-all ubuntu` announce `ubuntu` by themselves).
  A `User` in `~/.ssh/config` for the host wins; **u** logs in as another account, and the console remembers that
  choice for the node.
* **Switch tabs** with Alt+0…9 and Alt+←/→, or tmux-style with Ctrl+B and then `0…9`, `n`, `p`, `w` (close).
* **d** prints a link to the node's graphical desktop (next section).
* **Shift+PgUp** scrolls back; selecting and copying text works as usual.

## 9. Remote desktop in the browser

```sh
meshvpn desktop gpu1              # opens gpu1's desktop in your browser
meshvpn desktop box -u ubuntu     # as another account
```

This works on machines **without any graphical system** (containers, servers): meshvpn brings a small X server of
its own (downloaded once, about 5 MB; on machines without internet: `meshvpn desktop setup --from <file>`). The
logins are exactly those of section 7: whoever may `ssh ubuntu@box.mesh` may open ubuntu's desktop.

In the browser:

* The **bar** at the top lists the windows (click to switch, ✕ to close). **Apps** starts installed applications or
  any command. **Clipboard** shows what was copied on the desktop. ⛶ goes fullscreen (then shortcuts like Ctrl+W go to
  the desktop, not the browser). **⏻** ends the session.
* **Files** browses the node's files: images open in an **image viewer** (PNG, JPEG, GIF, WebP, SVG, BMP, AVIF; ← → go
  through the folder, the wheel zooms), text files in a preview, any file downloads with ⬇, and files dropped on the
  panel or the desktop are uploaded.
* The desktop always has the size of the browser window, and **sessions keep running** when you close the tab.

**A full desktop with Xfce:** the built-in desktop shows one application at a time. For a classic desktop with an
applications menu, a task bar and a file manager, install Xfce on the node once (needs root, about 300 MB):

```sh
sudo meshvpn desktop setup --xfce      # or add xfce4 to the Dockerfile
```

From then on `meshvpn desktop <node>` opens Xfce. A session that was started before Xfce was installed keeps the
built-in desktop: end it with ⏻ and reconnect.

**From outside the mesh:** if you are logged in on the server over SSH, `meshvpn desktop gpu1` notices and prints the
port forward to run on your computer, e.g.

```
ssh -L 7880:127.0.0.1:7880 you@vps.example.com
```

Then open the printed link in your local browser.

## 10. Working on many nodes at once

All commands take **selectors**: node names, `tag:<tag>`, `all`, mesh IPs. They run over the SSH logins of section 7,
and every one of them has `--json` for scripts and AI agents.

```sh
meshvpn exec tag:gpu -- nvidia-smi --query-gpu=name,utilization.gpu --format=csv
meshvpn cp ./project tag:gpu:/home/ubuntu/runs/        # copy to every GPU node
meshvpn cp gpu1:/home/ubuntu/runs/log.txt ./logs/      # and back
```

**Datasets and checkpoints:** share once, fetch in parallel from every node that has it (over the LAN where
possible); a node that fetched it serves it too.

```sh
sudo meshvpn share /data/imagenet          # prints an id
meshvpn objects                            # what is shared, and where
sudo meshvpn fetch <id> /data              # on another node
```

**GPUs:** reservations that never collide, because the node with the GPUs grants them.

```sh
meshvpn gpu list
meshvpn gpu reserve tag:gpu -n 2 --for 4h --note "experiment 42"
meshvpn gpu release <id>
```

**Distributed training:**

```sh
meshvpn launch tag:gpu --gpus 4 -- torchrun train.py
```

Every node gets `MASTER_ADDR`, `NODE_RANK`, `NCCL_SOCKET_IFNAME` and so on (the LAN between nodes where they share
one); torchrun gets `--nnodes`, `--node_rank` and the rendezvous added. If one node fails, the others are stopped.
`--detach` runs it in the background; `meshvpn jobs list`, `meshvpn jobs logs <id>` and `meshvpn jobs stop <id>`
follow up. For your own launcher: `eval $(meshvpn net env --master gpu1 tag:gpu)` on each node.
The [distributed training tutorial](distributed-training.md) walks through all of it with a runnable example.

**AI agents** (e.g. Claude Code) get all of this as tools: `claude mcp add meshvpn -- meshvpn mcp`.

## 11. Measuring the network

```sh
meshvpn net matrix --measure          # latency and throughput between every pair of nodes
meshvpn net matrix --measure gpu1 gpu2 --mb 100   # selected nodes, more test data for fast links
meshvpn net matrix                    # the last results again
```

The matrix measures the mesh's real paths (UDP, TCP or relay, with encryption) and shows where two nodes share a
LAN. It also works in rootless containers.

For a classic TCP test between two nodes (needs the mesh interface, i.e. not from a rootless container):

```sh
iperf3 -s                    # on gpu1
iperf3 -c gpu1.mesh          # on another node; -R for the other direction
iperf3 -c 192.168.1.160      # for comparison: the plain LAN, without meshvpn
```

Latency alone: `ping gpu1.mesh`, or the RTT column of `meshvpn status`.

## 12. Running the network

**Admins and invites.** Only admins invite and ban. Make another node an admin (so the network doesn't depend on one
machine), or step back:

```sh
sudo meshvpn admin add workstation
sudo meshvpn admin rm vps
meshvpn admin status
```

**Updates** are never installed automatically. `meshvpn status` shows each node's version (older ones highlighted)
and tells you when a new release is out:

```sh
sudo meshvpn update          # on each node (without sudo for rootless installs)
```

**Removing a machine:**

```sh
sudo meshvpn forget old-laptop      # an identity that is gone (e.g. a reinstalled machine)
sudo meshvpn forget --offline       # all nodes that are currently offline
sudo meshvpn ban stolen-laptop      # for good: every node drops it and the network gets a new key
```

After a ban, invites from before the ban stop working; members that were offline get the new key when they come
back.

**On a single node:** `sudo meshvpn rename <name>`, `sudo meshvpn doctor`, `sudo meshvpn uninstall` (stops the service,
keeps the configuration).

## 13. Troubleshooting

Start with `sudo meshvpn doctor` on the node in question. These are the problems that come up most:

| Symptom | Cause and fix |
|---|---|
| A node joins but nothing connects; doctor warns about `100.64.0.0/10` | Tailscale (or another CGNAT VPN) uses the same range. Uninstall it or run `tailscale down`. |
| `ssh` hangs at `expecting SSH2_MSG_KEX_ECDH_REPLY`, big downloads stall | The path can't carry full-size packets (VPN, mobile network, **WSL2**). meshvpn 0.12.2+ notices this and splits packets: update **both** nodes. `meshvpn status` then shows `(small MTU: splitting)`. Workaround on old versions: `mtu = 1200` in the config. |
| `Permission denied (publickey)` | `meshvpn ssh list` on the target names the reason: wrong user name, no rule for that node, or no published key (run `ssh-keygen` on the source). |
| The console logs in with the wrong user | Since 0.12.1 it uses your SSH config like plain `ssh`; set `User` in `~/.ssh/config` or press **u** in the console. |
| `Running in chroot, ignoring command` in a container | systemctl without systemd. `meshvpn install` (0.11+) handles it: it starts meshvpn in the background. |
| Rootless: `ssh node.mesh` works, `curl http://node.mesh` doesn't | Without root, only ssh and the SOCKS proxy know the names: `ALL_PROXY=socks5h://127.0.0.1:1055 curl …`. |
| The desktop shows the built-in desktop although Xfce is installed | The session started before Xfce was there. ⏻ (End session), then reconnect. |
| `this invite expired …` / `not admitted: … already been used` | Ask an admin for a new invite (`sudo meshvpn invite`). |
| The VERSION column shows `?` | The node where you run `meshvpn status` is older than 0.13.1 and doesn't report versions yet; update it. |

Logs: `journalctl -u meshvpn -f` (service), `/var/log/meshvpn.log` (background daemon without systemd),
`~/.config/meshvpn/meshvpn.log` (rootless). Desktop sessions log to `meshvpn-desktop*/session.log` in
`$XDG_RUNTIME_DIR` or `/tmp`.

## 14. Reference

**Ports**

| Port | What |
|---|---|
| TCP 7870 | connections between nodes (open it on nodes with a public address) |
| UDP 7870 | direct paths between nodes |
| TCP 7871 | `share`/`fetch`, only inside the mesh |
| 127.0.0.1:1055 | SOCKS proxy into the mesh (userspace mode) |
| 127.0.0.1:7880… | the desktop viewer on your machine |

**Files**

| Path | What |
|---|---|
| `/etc/meshvpn/config.toml` | configuration (rootless: `~/.config/meshvpn/config.toml`) |
| `/etc/meshvpn/state.json` | what the node knows about the network |
| `/etc/hosts` block `# BEGIN meshvpn` | the `<name>.mesh` names (root installs) |
| `/var/lib/meshvpn/known_hosts` | SSH host keys of the nodes |

**Settings in `config.toml`** (restart meshvpn after changing them)

| Setting | Meaning |
|---|---|
| `endpoints = ["host:7870"]` | addresses others use to reach this node |
| `udp = false` | no direct UDP paths (TCP and relays only) |
| `mtu = 1200` | smaller packets (only needed for old versions on difficult networks) |
| `manage_hosts = false` | don't write `<name>.mesh` into `/etc/hosts` |
| `publish_ssh_keys = false` | don't publish this machine's SSH keys |
| `ssh_server = "auto" / "always" / "never"` | meshvpn's built-in SSH server |
| `userspace = "auto" / "always" / "never"` | network interface or userspace mode |
| `socks_listen = "127.0.0.1:1055"` | the SOCKS proxy of userspace mode |

Every command explains itself with `--help`, and `meshvpn <command> --json` gives machine-readable output.

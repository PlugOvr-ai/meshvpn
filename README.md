# meshvpn

[![CI](https://github.com/PlugOvr-ai/meshvpn/actions/workflows/ci.yml/badge.svg)](https://github.com/PlugOvr-ai/meshvpn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/PlugOvr-ai/meshvpn)](https://github.com/PlugOvr-ai/meshvpn/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A decentralized, Tailscale-style mesh VPN written in Rust. It has **no coordination server**: nodes find each
other by gossip, pick their own addresses, and relay traffic for nodes that can't talk directly. It also
supports machines that can **only reach the internet through a reverse SSH tunnel**.

```
laptop (behind NAT) ───► server (public IP) ◄─── ssh -R ─── lab box (firewalled, SSH out only)
      100.122.64.143         100.94.140.208                        100.92.238.33
            └───────────── relayed through server, end-to-end encrypted ──────────┘
```

**New here? The [tutorial](docs/tutorial.md) builds a complete network step by step**, from the first node to
containers without root, SSH, the browser desktop and troubleshooting. **Training across machines?** See
[distributed training](docs/distributed-training.md), with a [small example](examples/distributed-training).

## Install

For any Linux machine: PCs, servers, VMs and Raspberry Pis (x86_64, ARM64, ARMv7, ARMv6). The binary is fully static
and has no dependencies:

```sh
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh | sudo sh
```

To install and join a network in one step (this also starts the service):

```sh
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh | sudo sh -s -- join mesh1-...
```

**Behind a proxy**, the installer uses it automatically. `sudo` drops your environment, so besides `https_proxy` /
`http_proxy` it also checks `/etc/environment`, `/etc/profile.d`, apt's and dnf/yum's proxy settings and the GNOME proxy
setting of the user who ran `sudo`. The proxy is saved in `/etc/meshvpn/proxy.env` (root-only), so the service's
automatic updates use it too. Proxy auto-configuration (PAC) isn't supported; set `https_proxy` in that case. Mesh
connections themselves don't go through the proxy.

The [releases page](https://github.com/PlugOvr-ai/meshvpn/releases/latest) also has `.deb` packages
(`sudo apt install ./meshvpn_*.deb`), `.rpm` packages and plain tarballs. To build from source, run
`cargo install --git https://github.com/PlugOvr-ai/meshvpn`.

## Quick start

On the first machine:

```sh
sudo meshvpn init --network home --endpoint my-server.example.com:7870
sudo meshvpn install        # runs as a systemd service, also after reboot
```

`init` prints an invite code. On every other machine:

```sh
sudo meshvpn join mesh1-eyJuZXR3b3Jr...
sudo meshvpn install
```

That's it. Every node gets a stable IP in `100.64.0.0/10` and a `<name>.mesh` host name:

```sh
$ meshvpn status
● laptop  100.122.64.143  (ef5a9cd4 on mesh0, network "home")

NAME     IP               STATUS      RTT  PATH
server   100.94.140.208   online     12ms  direct my-server.example.com:7870
labbox   100.92.238.33    online        -  relay via server

$ ssh labbox.mesh
```

Admins print more invites with `sudo meshvpn invite` (see *Admins and invites* below). Use `sudo meshvpn up` instead of
`install` to run in the foreground.

## Nodes behind a firewall (reverse SSH tunnel)

If a machine can only make an SSH connection to some jump host, let meshvpn manage the tunnel:

```sh
sudo meshvpn join mesh1-... --ssh user@jump.example.com --ssh-remote-port 7871
```

The daemon runs and supervises (reconnecting with backoff):

```
ssh -N -R :7871:127.0.0.1:7870 -D 127.0.0.1:1081 user@jump.example.com
```

* **Incoming:** other nodes connect to `jump.example.com:7871`, which forwards to this node. This needs
  `GatewayPorts clientspecified` in the jump host's `sshd_config` (otherwise the port is only open on the jump host's
  localhost, which is still fine if the jump host is itself a mesh node).
* **Outgoing:** the node connects to other nodes through the SOCKS proxy that the same SSH connection provides.
  Nothing else has to be allowed through the firewall.

Requirements: `ssh` must log in without a password as root, or pass `--ssh-identity /path/to/key`. Other options:
`--ssh-port`, `--ssh-public-host` (if others reach the jump host by a different name), `--ssh-no-socks`.

**The tunnel is already managed by someone else** (e.g. autossh): join with `--no-outbound --endpoint jump:7871`, then
on any node in the network run `sudo meshvpn add-peer jump.example.com:7871`. The address is remembered, and gossip tells
every other node about it.

## Devices without internet access

If a device can't reach the internet at all, but you can SSH into it from a jump host (e.g. through its existing reverse
tunnel on `localhost:2222`), install it **from the jump host**. Nothing is installed on the jump host:

```sh
# on the jump host; get the invite from `meshvpn invite` on any member
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/deploy.sh \
  | sh -s -- --invite mesh1-... user@localhost -p 2222
```

The script downloads the right binary on the jump host and uploads it. It then installs it on the device with `sudo`
and joins the network. The device gets its own SSH key, which the script adds to your `~/.ssh/authorized_keys` on the
jump host with `restrict,port-forwarding,command="echo meshvpn-ok"`: port forwarding only, no shell. Through that SSH
connection the device reaches the other nodes and GitHub (for updates). The script detects how the device reaches the
jump host; if it can't, pass `--jump user@host[:port]`. Run the script again to update the device.

## Containers without NET_ADMIN (userspace mode)

meshvpn normally creates a network interface (`mesh0`), which needs `/dev/net/tun` and the `NET_ADMIN` capability. In a
container that has neither, it switches to **userspace mode** by itself and runs a small TCP/IP stack in its own
process:

* **Into the container:** other nodes reach the services listening in the container directly (`ssh`, `curl
  http://box.mesh:8080`, ...); ping works. Ports where nothing listens are refused.
* **Out of the container:** programs reach the mesh (and, if they like, the internet) through the SOCKS5 proxy
  `socks5h://127.0.0.1:1055`, e.g. `ALL_PROXY=socks5h://127.0.0.1:1055 curl http://hub.mesh:8000`. `ssh user@host.mesh`
  works without any setup (meshvpn adds a `ProxyCommand` for `*.mesh` to `/etc/ssh/ssh_config.d`), and `meshvpn nc
  host port` connects stdin/stdout for other tools.

`meshvpn status` shows `mode: userspace`. Force it with `--userspace` (init/join) or `userspace = "always"`, or switch it
off with `userspace = "never"`. Limits: TCP and ping only (no UDP); programs that ignore proxy settings can't reach out to
the mesh; and it is slower than kernel mode (about 30-40 MB/s).
If you can change how the container is started, `--cap-add=NET_ADMIN --device=/dev/net/tun` gives the full kernel mode.

## Without root (rootless install)

No sudo on the machine? Install meshvpn for your user only (this is also what happens automatically when `sudo` is
missing):

```sh
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh | sh -s -- --user join mesh1-...
```

This puts the binary in `~/.local/bin`, the configuration in `~/.config/meshvpn` and nothing anywhere else (apart from a
marked `Host *.mesh` block in `~/.ssh/config`). It runs in userspace mode (above), so the same applies: other nodes
reach your services, you reach the mesh through `ssh user@node.mesh` or the SOCKS proxy. `meshvpn install` starts it as a
**systemd user service** (to keep it running when you are logged out an admin can run `sudo loginctl enable-linger
<user>`), or, where there is no systemd (containers), in the background with a `@reboot` crontab entry. `meshvpn status`,
`rename`, `tags`, `share`, `invite`, `ssh allow`, `update` and `uninstall` work without sudo.
Password-less logins *into* the machine go to meshvpn's built-in SSH server (below), as your own user only. What a
rootless install can't do: write `/etc/hosts` (names work through ssh and the proxy only). Only one rootless install per
machine can use the default ports.

## Password-less SSH between nodes

Each machine decides for itself who may log in to it without a password. Open the editor on the machine you want to log
in *to*:

```sh
sudo meshvpn ssh
```

```
Who may log in to server over SSH without a password
┌──────────────────────────────────────────────┐
│from \ as            bob    carol  root       │
│● laptop (any user)   [ ]    [ ]    [ ]        │
│●   alice@laptop      [ ]    [x]    [ ]        │
│●   eve@laptop        [ ]    [ ]    [ ]        │
└──────────────────────────────────────────────┘
↑↓←→ move   space allow/deny   s save   q quit
```

Then, on the laptop, alice just runs `ssh carol@server.mesh`. The same works from scripts:

```sh
sudo meshvpn ssh allow alice@laptop --as carol   # one user of a node
sudo meshvpn ssh allow laptop --as bob           # any user of a node
sudo meshvpn ssh allow everyone --as ubuntu      # every node, also ones that join later
sudo meshvpn ssh deny alice@laptop               # take it back
meshvpn ssh list                                 # show rules and the keys this machine offers
```

**Machines everybody should reach**, such as the nodes of a Docker cluster, can be opened up at install time. Every node
of the network, including ones that join later, may then log in as the named account(s):

```sh
curl -fsSL https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh \
  | sudo sh -s -- join mesh1-... --ssh-allow-all ubuntu
# devices without internet, from the jump host:
curl -fsSL .../deploy.sh | sh -s -- --invite mesh1-... --ssh-allow-all ubuntu user@localhost -p 2222
```

How it works: every node publishes the SSH public keys of its users (`~/.ssh/id_*.pub`) in its signed record; disable
with `publish_ssh_keys = false`. The first `allow` adds `/etc/ssh/sshd_config.d/meshvpn.conf`, which makes your normal
OpenSSH server ask meshvpn for additional keys at each login. meshvpn answers only with keys you allowed, each limited
to `from="<that node's mesh IP>"`, which meshvpn guarantees can't be spoofed. Rules are bound to the node's identity,
not its name. Your other SSH settings and existing logins stay as they are. Needs OpenSSH with `sshd_config.d` support
(Debian/Ubuntu/Fedora); a user without a key creates one with `ssh-keygen`.

### Machines without an SSH server (built-in SSH server)

Most Docker images have no sshd. meshvpn then answers `ssh user@node.mesh` itself, with the same rules as above
(`meshvpn ssh allow`, `--ssh-allow-all`): nothing to install in the image. It supports interactive shells with a
terminal, commands (exit codes, stdin/stdout/stderr), `scp`/`sftp`, `-L` port forwarding, and therefore `meshvpn
exec`/`cp`/`launch`. Sessions get the container's environment (PATH, CUDA, conda... from the image). `meshvpn status`
shows `ssh server: built-in` when it is active.

* It is only reachable through the mesh, and only keys you allowed get in, each only from its own node.
* As root it logs users in as themselves; a rootless install can only log in its own user.
* **When:** `ssh_server = "auto"` (default) uses it where no sshd serves port 22: in userspace mode when nothing
  listens on port 22, in kernel mode when no sshd is installed (so an sshd starting later never finds its port taken).
  `"always"` / `"never"` in the config force it on or off.
* **No host key prompts:** every node publishes the host key of whatever answers SSH there (the built-in server's key is
  derived from the node identity; for sshd its ed25519 host key), and meshvpn keeps them in
  `/var/lib/meshvpn/known_hosts`, which ssh reads through `/etc/ssh/ssh_config.d/meshvpn.conf`. `ssh` to a mesh node
  doesn't ask "are you sure?" and works with `StrictHostKeyChecking=yes`.
* Not supported: agent and X11 forwarding, `-R` remote forwarding.

## Remote desktop in the browser

```sh
meshvpn desktop gpu-box            # opens the desktop of gpu-box in your browser
meshvpn desktop gpu-box -u ubuntu  # as another account
```

Works on machines **without any X server or desktop**, typically containers: meshvpn brings a small, fully static
X server (its *desktop bundle*, about 5 MB, built in our CI and published with each release) and does everything else
itself: window manager, screen transfer (only what changed: sharp PNG for text and UI, JPEG for photos and video), mouse,
keyboard in any layout, clipboard both ways and the mouse cursor. Nothing needs to be installed in the image except the
applications you want to run.

* **Same logins as SSH:** the desktop is opened through `ssh <user>@<node>.mesh` (sshd or meshvpn's built-in server), so
  whoever may log in as `ubuntu` may open `ubuntu`'s desktop, and nobody else. It runs as that user.
* **The viewer** is served by meshvpn on `127.0.0.1` of your machine (with a secret token in the link) and needs no
  plugin. The bar on top lists the windows (click to switch, ✕ to close), **Apps** starts installed applications or any
  command, **Clipboard** shows what was copied on the desktop, ⛶ goes fullscreen (then Ctrl+W & co. go to the desktop).
  The desktop always matches the size of the browser window.
* **Files** (in the bar) browses the node's files as the logged-in user: images open in an image viewer (PNG, JPEG,
  GIF, WebP, SVG, BMP, AVIF; ← → through the folder, zoom with the wheel, drag to pan), text files in a preview, any
  file downloads with ⬇, files dropped onto the panel or the desktop are uploaded, and folders can be created,
  renamed and deleted. All of it works without any program installed on the node.
* **Sessions keep running** when you close the tab; open it again to continue. `meshvpn desktop stop` (on the node) or ⏻ in the
  bar ends the session and its applications.
* **First use** downloads the bundle by itself; on machines without internet copy `meshvpn-desktop-<arch>.tar.gz` from
  the release and run `meshvpn desktop setup --from <file>` (also handy in a Dockerfile).
* Apps get a UTF-8 locale and the bundled DejaVu fonts if the image has none. Not yet: OpenGL/GPU acceleration, sound.
* **A full desktop with Xfce:** `sudo meshvpn desktop setup --xfce` on the node (or `xfce4` in the Dockerfile) installs
  Xfce with the system's package manager (apt, dnf, apk, zypper; about 300 MB). From then on `meshvpn desktop <node>`
  opens an Xfce desktop: panel with the applications menu, file manager, terminal, windows you can move and resize.
  The tabs in the browser bar follow Xfce's windows; logging out of Xfce ends the session. `--plain` keeps the
  built-in minimal desktop, `--xfce` insists on Xfce. A running session keeps its desktop until `meshvpn desktop stop`.
* **Logged in over SSH** (e.g. on your main node from outside the mesh)? `meshvpn desktop` notices and prints the
  matching forward, e.g. `ssh -L 7880:127.0.0.1:7880 you@main-node` - run it on your computer (or add it to the open
  session with Enter `~C`), then open the link in your local browser.

## The console: the mesh in your terminal

```sh
meshvpn            # in a terminal, on a set-up machine (or: meshvpn console [-u user])
```

For when all you have is an SSH login: a full-screen terminal desktop. Tab **0** lists the nodes (status, path, RTT,
GPUs, tags; details of the selected one below). **Enter** opens a shell on the selected node in a new tab (ssh, or a
local shell for this machine), **u** as another user, **d** prints a desktop link (with the `ssh -L` hint).
Switch with **Alt+0..9**, **Alt+←/→**, or **Ctrl+B** and then `0..9`, `n`, `p`, `w` (close), `d` - like tmux.
**Shift+PgUp** scrolls back; text selection works as usual in your terminal.

**Which account?** Each node announces its default login: set it with `sudo meshvpn ssh default-user ubuntu` on the
node (a node joined with `--ssh-allow-all ubuntu` announces `ubuntu` by itself). The console logs in with that,
unless `~/.ssh/config` has a `User` for the host or you chose another account there with **u** - the console
remembers that per node. `meshvpn desktop` uses the same default.

## AI agents and multi-node work

meshvpn is built so that people and AI agents can work with many machines at once, including training models across
nodes. Every command takes `--json` (errors too), and exit codes are stable: 0 ok, 1 error, 2 usage, 3 meshvpn not
running, 4 needs root, 5 not found. Nodes are selected with **selectors**: `all`, `tag:<tag>`, node names or mesh IPs.

**MCP server:** connect an agent directly with `claude mcp add meshvpn -- meshvpn mcp` (any MCP client works). Tools:
`list_nodes`, `exec`, `copy_to_nodes`, `copy_from_nodes`, `network_matrix`, `training_env`, `launch`, `job_status`,
`job_stop`, `list_jobs`, `gpu_list`, `gpu_reserve`, `gpu_release`, `share`, `fetch`, `list_objects`, `set_tags`,
`node_status`, `doctor`.

| Command | What it does |
|---|---|
| `meshvpn nodes [selectors] [--free-gpus N]` | Nodes with tags and hardware: CPU, memory, disk, GPUs with memory/utilisation, driver and CUDA. Nodes publish this themselves; no login needed |
| `sudo meshvpn tag add gpu trainer` | Label this node (or `join --tag gpu,trainer`) |
| `meshvpn exec tag:gpu -- nvidia-smi` | Run a command on many nodes in parallel; output and exit code per node (uses the password-less SSH logins) |
| `meshvpn cp ./code tag:gpu:/srv/` / `meshvpn cp tag:gpu:/srv/out.log ./logs` | Copy to or from many nodes (the destination is a directory; downloads go to `logs/<node>/`) |
| `meshvpn net matrix --measure` | RTT, mesh throughput and **direct LAN paths** between all nodes |
| `meshvpn net route <node>` | The best address for heavy traffic to a node: its LAN address if both share one, otherwise the mesh |
| `eval $(meshvpn net env --master gpu1 tag:gpu)` | On each node of a training job: `MASTER_ADDR`, `NODE_RANK`, `NNODES`, `NCCL_SOCKET_IFNAME`... for torchrun. Uses the LAN only if every pair of nodes shares one (mixed paths make NCCL hang), otherwise the mesh |
| `meshvpn launch tag:gpu -- torchrun --nproc_per_node=8 train.py` | Start a distributed job on all selected nodes. Every node gets its environment (`MASTER_ADDR`, `NODE_RANK`, `NCCL_SOCKET_IFNAME`...), torchrun gets `--nnodes/--node_rank/--master_addr/--master_port` added, output is streamed and logged per node, and if one node fails the others are stopped. Ctrl+C, a lost connection or a killed launcher stop the job's whole process tree on every node |
| `meshvpn launch ... --detach`, `meshvpn jobs [show/logs/stop]` | The same in the background, for agents: returns a job id |
| `meshvpn gpu list` | Every GPU in the network: free, busy, or reserved (by whom, how long) |
| `meshvpn gpu reserve tag:gpu -n 2 [--for 2h] [--one]` | Reserve GPUs, so no other agent or job takes them: per node (all or nothing), or on the single best node. The node with the GPUs grants it, so reservations never collide. Prints `CUDA_VISIBLE_DEVICES`. Expires unless renewed (`gpu renew`), release with `gpu release`. Advisory, like Slurm without cgroups |
| `meshvpn launch --gpus 4 tag:gpu -- torchrun ...` | Reserve 4 GPUs per node for the job, set `CUDA_VISIBLE_DEVICES` and `--nproc_per_node`, release them at the end (they expire 15 min after a crashed launcher) |
| `sudo meshvpn share ./dataset` | Share a dataset or checkpoint (file or directory); prints its id |
| `sudo meshvpn fetch <id> /data` | Download it **from all nodes that have it at once**, over LAN paths where possible. Every 4 MB chunk is verified, interrupted downloads resume, and the node serves the data afterwards, so each node speeds up the next ones |
| `meshvpn objects` | Shared objects and which nodes have them |

Notes: a LAN path counts only if the other node actually answers on its LAN address (Docker bridges, VPNs and similar
interfaces are ignored). Throughput is measured over the encrypted mesh links, while several pairs may test at the same
time, so take the numbers as approximate. Shared data travels encrypted over the mesh; over a direct LAN path it is
authenticated (only network members can download) but not encrypted, like NCCL's own traffic. `share` and `fetch` need
root, because the daemon reads and writes the files; fetched files belong to the user who ran `sudo`.

## Everyday use

| Command | What it does |
|---|---|
| `meshvpn status` | This node and its peers (no sudo needed) |
| `sudo meshvpn doctor` | Checks the setup (daemon, Tailscale conflicts, firewalls, peers, UDP paths, SSH logins, admins, updates) and says how to fix each problem |
| `sudo meshvpn invite [--uses N] [--expires 24h]` | Print an invite code for a new machine (single-use and valid for 24 h by default) |
| `meshvpn admin status` / `sudo meshvpn admin add\|rm <node>` | Who the admins are; change them |
| `sudo meshvpn update` | Install the latest release. Nodes check for new releases every ~6 hours and show them in `meshvpn status` / `doctor`, but never install them by themselves |
| `sudo meshvpn forget <name>` | Remove an offline node (e.g. an old identity of a re-installed machine) from all nodes. `--offline` forgets all offline nodes. If an offline node's name is taken by a newer online node, it's forgotten automatically after 10 minutes |
| `sudo meshvpn ban <name>` | Throw a node out for good (see below) |
| `sudo meshvpn ssh` | Choose who may log in here over SSH without a password |
| `sudo meshvpn rename <name>` | Give this node a new name. It becomes `<name>.mesh` on every node within seconds; its IP, SSH permissions and links stay. Names already taken are refused |
| `sudo meshvpn add-peer host:port` | Connect to a node at an address, e.g. an inbound-only node |

### Admins and invites

New networks are **managed**: the node that ran `init` is the admin. Only admins can invite new nodes, ban nodes and
change the admins (`sudo meshvpn admin add <node>`, `admin rm <node>`). Every other member can still forget offline
nodes, tag and rename itself, share data and choose who may log in to it.

An invite holds a **ticket** signed by an admin. By default it admits one node within 24 hours (`--uses 5`,
`--expires 7d` to change that). The new node binds the ticket to its identity when it first connects. A second node
with the same invite is rejected, and so is a node that only has the network key (for example from an old invite).
The first member to see a new node countersigns its admission, so members that were offline at the time accept it later
too. Rejected attempts show up as warnings in the admins' logs.

Networks created before v0.7 (or with `init --open`) are **open**: everybody with the network key may invite and ban.
Make one managed with `sudo meshvpn admin enable` on your main node. That node becomes the admin, every node known at
that moment stays a member, and old invites stop working. Do it soon after updating: until then any member could run it
first.

### Banning a node

`sudo meshvpn ban <name>` works without setting the network up again. Every node drops the banned node and refuses it
from then on. The network key is also changed, and the new key is sent to every *other* member, sealed individually for
each one. That way the banned device can't rejoin under a new identity with the key it already has. Members that are
offline during the ban may connect once with the old key when they come back, and then receive the new one. Invites
created before the ban stop working, so create new ones with `meshvpn invite`. IP addresses and names stay the same.

## How it works

| Piece | Design |
|---|---|
| Identity | Each node has an ed25519 key (its node id) and an X25519 key. |
| Membership | A shared 32-byte network key from the invite. Links use Noise `XXpsk3` with it as the PSK: without the key, the handshake fails. Banning a node changes the key (the key is versioned). |
| Addresses | `100.64.0.0/10` + 22 bits of `blake3(node id)`. Deterministic, so no allocation server is needed. |
| Transport | TCP links (the only thing an SSH tunnel or proxy can carry) for control traffic, and **direct UDP paths** for data wherever possible. Nodes publish their address candidates (LAN, public address as other nodes see it) and keep sending authenticated probes to each other, which opens a path through both NATs (hole punching). Data then goes directly over UDP; if a path stops answering it falls back to TCP or a relay within seconds. |
| Discovery | Nodes sign a record (name, endpoints, neighbors, sequence number) and gossip all records they know. A new link gets the full table; changes are flooded. The state is saved to disk, so the mesh survives losing the bootstrap node. |
| Connectivity | Every node dials every other node's advertised endpoints (with backoff). Endpoints are configured, auto-detected (LAN IP, public IP as seen by peers) or the SSH tunnel's public port. |
| Relaying | Records list each node's neighbors. Nodes that can't connect directly are reached by a shortest path (BFS) through other nodes. |
| Encryption | Hop-by-hop Noise encryption, plus end-to-end XChaCha20-Poly1305 per packet (a static-static X25519 key bound to the network id). Relays can't read or forge traffic, and the inner source IP must match the sender. |
| Names | `<name>.mesh` entries in a marked block of `/etc/hosts` (`manage_hosts = false` to disable). |

Files: `/etc/meshvpn/config.toml` (settings and secret keys, mode 0600), `state.json` (known nodes) and `/run/meshvpn.sock`
(control socket: anyone may ask for the status, but changes need root). Use `--dir` or `MESHVPN_DIR` to put them elsewhere, e.g. to run several nodes on one machine.
Set `RUST_LOG=meshvpn=debug` for verbose logs.

## Security model and limitations

* In managed networks (the default since v0.7) only admins invite, ban and change the admins. In open networks every
  member can do all of that. Members are trusted either way: they can reach each other's services and share data.
  Treat invite codes like passwords until they are used or expire. If two admins ban nodes at the same moment, run the
  ban again.
* Updates are downloaded from this repository's GitHub releases and checked against the published SHA-256 checksums.
  That protects against corrupted downloads, but not against a compromised GitHub account. Nodes never install
  updates by themselves: only `meshvpn update` does.
* The end-to-end layer has no replay protection or forward secrecy (the hop-by-hop Noise links have both).
* IPv4 only, Linux only (the TUN setup and systemd integration).
* Direct UDP paths work through the common kinds of NAT (one public port per internal port, as most home routers do).
  "Hard" NATs that use a new port for every destination (some carrier-grade NATs and corporate firewalls) can't be
  punched through. Those nodes keep using TCP and relays, which is slower on lossy links (TCP-over-TCP). For the best
  results, allow UDP on port 7870 in front of public nodes, as you do for TCP. Switch it off with `udp = false`.
* The mesh is full-mesh by design, which suits networks of up to a few dozen nodes.
* Overlay IPs come from a 22-bit hash. A collision is unlikely in small networks; if one happens, the node with the
  lower id keeps the address.

## Development

```sh
cargo test
cargo build --release
```

**End-to-end tests** run real meshvpn nodes in Docker containers. They cover joining and invites, admins and bans,
NAT traversal through two routers, userspace mode, password-less SSH, `exec`/`cp`, launching jobs (including stopping
them), GPU reservations, sharing data, the network matrix, `doctor`, MCP, `deploy.sh` and `install.sh` behind a proxy.
They need Docker and a static binary:

```sh
cross build --release --target x86_64-unknown-linux-musl
tests/e2e/run.py --binary target/x86_64-unknown-linux-musl/release/meshvpn -j 4    # all, about 2-3 minutes
tests/e2e/run.py --binary ... --list                                                # what there is
tests/e2e/run.py --binary ... --keep nat_traversal                                  # one; keep its containers if it fails
```

They run on every push, and a release is only published when all of them pass.

To publish a release, push a tag (`git tag v0.2.0 && git push origin v0.2.0`). The release workflow then builds static
binaries for every architecture, `.deb`/`.rpm` packages and checksums, and attaches `install.sh`.

The end-to-end behavior was tested with three rootless network namespaces: a public node, a NAT'd node without a
listener, and a node whose firewall only allows SSH to a jump host. That covered direct links, relayed traffic, SSH
tunnel restarts, hub restarts and `add-peer` for inbound-only nodes.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

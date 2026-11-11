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

> **Early software, use at your own risk.** meshvpn is before version 1.0: it is still developing quickly,
> and its behaviour, configuration and protocol can change between releases. It is provided "as is", without
> warranty of any kind and with liability excluded as far as the law permits (Apache License 2.0, sections 7 and
> 8). Test it before you rely on it, keep other access to important machines, and don't use it where a failure
> could endanger people or cause serious damage.

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

**macOS** (Apple Silicon and Intel): the same command. meshvpn runs as a launch daemon and creates a `utunN`
interface.

**Windows 10/11** (x86_64): in an administrator PowerShell:

```powershell
irm https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.ps1 | iex
```

It installs to `C:\Program Files\meshvpn` with the [Wintun](https://www.wintun.net) driver, keeps its configuration
in `C:\ProgramData\meshvpn` and runs as a task that starts at boot. Run meshvpn's commands without `sudo`, in an
administrator terminal for the ones that change something. Windows Defender Firewall keeps blocking connections *into*
the machine from the mesh, as from any new network; to offer a service to the other nodes, allow its port, e.g.
`New-NetFirewallRule -DisplayName "meshvpn: my app" -Direction Inbound -Protocol TCP -LocalPort 8000 -RemoteAddress 100.64.0.0/10 -Action Allow`.
Use Windows Terminal or a normal PowerShell window, not PowerShell ISE: ISE can't run interactive console programs, so
questions (`meshvpn leave`) and `ssh`'s password prompt never show up there, and the command seems to hang.

| | Linux | macOS | Windows |
|---|---|---|---|
| Mesh, names (`<node>.mesh`), status, `connect` | ✓ | ✓ | ✓ |
| Userspace mode (no network interface) | ✓ | ✓ | ✓ |
| Service at boot | systemd | launchd | Task Scheduler |
| SSH logins *into* this machine | ✓ | ✓ (its sshd) | – |
| `ssh`, `exec`, `cp` with other nodes | ✓ | ✓ | ✓ ¹ |
| `launch`, GPUs, `share` / `fetch` | ✓ | ✓ ¹ | ✓ ¹ |
| Browser desktop of other nodes (`meshvpn desktop <node>`) | ✓ | ✓ ¹ | ✓ ¹ |
| Desktop sessions *on* this machine, exit nodes, terminal console, rootless install | ✓ | – | – |

¹ Built and type-checked for the platform; the first rows are tested on real Macs and Windows machines in CI, these
not yet end to end.

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

`sudo meshvpn restart` restarts the service the same way everywhere (systemd on Linux, the launch
daemon on macOS, the scheduled task on Windows), e.g. after changing its configuration.

That's it. Every node gets a stable IP in `100.64.0.0/10`, an IPv6 address in its network's own
private prefix (`fdxx:xxxx:xxxx::/64`), and a `<name>.mesh` host name for both:

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
on any node in the network run `sudo meshvpn connect jump.example.com:7871`. The address is remembered, and gossip tells
every other node about it.

## A node on the internet, the others behind a firewall

Joining works by the new node dialing the addresses in the invite. When the network sits behind a corporate firewall,
a node on the internet can't reach those - but the network can reach it. Let the connection start from inside:

```sh
# on the public node
sudo meshvpn join <invite> --name edge --endpoint 203.0.113.7:7870
sudo meshvpn up
# on any node of the network (port 7870 is the default)
sudo meshvpn connect 203.0.113.7
```

The address is remembered, and every other node learns about the public node and reaches it directly or through the
node that connected. Until then `meshvpn status` on the public node says that it can't reach the network and prints
this command. Note that a node on the internet can reach every service the other nodes offer on the mesh.

## Without any server: home routers and changing addresses

A network needs one node the others can reach. That can be a node at home, and its address may change every night:

* **Port opened by itself.** Behind a home router, a node that accepts connections (the default; not one joined
  with `--no-listen`) opens its port (TCP and UDP 7870) on the router with UPnP, PCP or NAT-PMP, and tells the
  others the router's public address. On a FRITZ!Box allow it once for that device: *Internet > Freigaben >
  Portfreigaben > Gerät > Selbstständige Portfreigaben für dieses Gerät erlauben*. `meshvpn status` shows
  `port mapping: TCP 7870 + UDP 7870 open on the router (UPnP, 192.168.178.1), public …`, or why it failed.
  The forward is leased for an hour, renewed while meshvpn runs and removed when it stops; routers that only
  allow permanent forwards are not used. The port is then reachable from the internet: only nodes with the
  network key get past the handshake, but if that isn't wanted (servers in a company or university network,
  notebooks on public Wi-Fi), switch it off with `port_mapping = false`, or join those with `--no-listen`.
* **Found again after a new address (DHT rendezvous, off by default).** A node others can reach puts its current
  address into BitTorrent's public DHT. Nodes that lost it (a notebook outside the company network, the other home
  after the nightly reconnect) look it up there and connect again. No DynDNS or server needed. The entry is
  encrypted with the network key and signed by the node: only members can read it, and they can't forge each
  other's entries. Where it is stored changes every day, and after a ban the banned node can't find it anymore.
  meshvpn only asks the DHT; it never stores or answers anything for others.

  It is off by default because firewalls and intrusion detection in company networks may take DHT traffic for
  BitTorrent. Switch it on **on the node that others connect to and on the nodes that should find it** (best: on
  all nodes outside company networks):

  ```sh
  sudo meshvpn dht on      # Windows: meshvpn dht on, in an administrator terminal
  ```

  It sets `dht = true` in the configuration and restarts meshvpn (`meshvpn dht off` switches it off again,
  `meshvpn dht` shows the setting).

  `meshvpn status` then shows `rendezvous: DHT, published …` on the reachable node, and the others log
  `rendezvous: <node> is at …` when they found it.

  Keep in mind: whoever has the network key can read the entries, also nodes that were removed without a ban
  (`meshvpn forget`) and clients whose access expired. They learn the current public address of every node that
  publishes, until the key changes with the next ban. And because all members share the key the entries are
  stored under, one member can block another's entry for a day (it can't change the address in it: that is
  signed by the node itself).
* **Its own public address.** While no other node tells it (none connected, or none reachable over UDP), a node
  asks STUN servers for its public address, at most every 5 minutes: Google's and Cloudflare's by default,
  `stun = [...]` in the config, `stun = []` for none. Each request tells the server's operator that this address
  runs meshvpn.

None of this goes through a configured proxy or SSH tunnel: those nodes keep using only them.

* **Hole punching over IPv6.** Two nodes that both can't accept connections (a home router without a port
  forward, a mobile network) connect anyway if both have IPv6: each sends to the other's IPv6 address from its own
  port 7870 at the same time, so each one's firewall lets the other's packets in. That gives the direct UDP path
  and, by TCP simultaneous open, the link that carries records and control. The addresses come from the DHT
  rendezvous (with `dht = true`; nodes put their *temporary* IPv6 addresses into their entry, which change every
  day or so and don't identify the machine, also nodes nobody can connect to) or, while they still hold, from the
  node's last record. Tried for nodes heard of in the last day: for a quarter of an hour all the time, then only in
  the first minute of every five by the clock (so both sides try at the same moment). The log says
  `hole punching: TCP link to <node> via [...]`. Off with `punch = false` (e.g. on a company notebook, where
  repeated connection attempts to home addresses may stand out).

* **Joining that way too.** An invite made on a node with `dht = true` carries a join hint: a secret slot, the
  node's id and its IPv6 addresses. A new node that can't reach the inviting node puts its own IPv6 addresses into
  the DHT at the slot (sealed and signed like a rendezvous entry; it uses the DHT for this one meeting whatever its
  own setting) and tries the inviting node's addresses; the inviting node looks there while the invite is open
  (every 30 seconds for the first half hour, then every two minutes) and tries back. The join then runs over the
  punched link as usual. The new node logs `joining: waiting for the inviting node at ...`, the inviting one
  `joining: a new node (...) waits at ...`.

What these features can't do: if the router has no public IPv4 address itself (DS-Lite, carrier-grade NAT, most
mobile networks), no port can be opened on it. `meshvpn status` says so. Then IPv6 hole punching usually still
connects; two nodes that both have only IPv4 behind carrier-grade NAT need a third node with a public address,
e.g. a small VPS or a free cloud VM.

## Internet through another node (exit nodes)

One node offers its internet connection, others send their internet traffic through it - e.g. to
appear with an office's address, or to give machines without internet access a way out:

```sh
sudo meshvpn exit offer          # on the node with the internet connection (kernel mode)
sudo meshvpn exit use office     # on the nodes that should use it
meshvpn exit list                # who offers it, which one is used
sudo meshvpn exit off            # back to direct
```

* All internet traffic of the machine goes through the exit. LANs, Docker networks and the mesh stay
  direct, and so do meshvpn's own connections and replies to connections from outside (an SSH
  session from the internet keeps working).
* In userspace mode, connections through the SOCKS proxy go through the exit.
* The exit forwards only to public internet addresses - never into its own LAN or to cloud metadata
  addresses. It needs `iptables`; in a container, start it with `--sysctl net.ipv4.ip_forward=1`.
* DNS keeps using the machine's resolver, and internet IPv6 isn't carried (only the mesh's own
  IPv6 addresses are).
* While the exit node is offline there is no internet (status shows a warning), so nothing leaks
  out directly. The setting survives restarts.

## Several networks on one machine

A notebook can be in two independent networks at once, e.g. your lab's and a customer's. Join the
second one as you joined the first:

```sh
sudo meshvpn join mesh1-...       # an invite of another network: set up next to the first one
meshvpn networks                  # the networks of this machine, their addresses and state
meshvpn exec gpu1 -- nvidia-smi   # commands find each node's network by its name
sudo meshvpn --net lab invite     # anything else for a further network takes --net
sudo meshvpn networks leave lab   # leave it again; the first network doesn't notice
```

* The networks know nothing of each other: nothing is routed or relayed between them, and a node
  of one can't reach the other through this machine.
* Each one has its own interface (`mesh1`, ...), port (7872, ...), service (`meshvpn-lab`) and
  names: the nodes of a further network are `<node>.lab.mesh` (and `<node>.lab`), the first
  network's stay `<node>.mesh`. Its name comes from the invite; `--net <name>` on `join` sets it.
* `meshvpn install` and `uninstall` take care of all networks of the machine, or the one of `--net`.
  `ssh user@<node>.lab.mesh` works as usual, and so do `meshvpn ssh allow` and the built-in SSH
  server: each network's logins come only from its own nodes.
* IPv6 addresses can't clash: each network has its own prefix. IPv4 addresses are from the same
  range in every network. The first network routes the range as a whole; a further network adds a
  route per node of its own, so the other nodes of both need nothing new. IPv4 addresses are 22
  bits of a hash, so the same one can turn up in both networks: about once in 400 for two networks
  of 100 nodes each, and likely for two of a thousand. Then the first network's node keeps the
  address here, and the further network's node is reached over IPv6: its name points there only.
  (Without IPv6 on the machine, the further network's node wins, and status and the log name both.)
* Linux and macOS (not Windows yet), and exit nodes only in the first network. On macOS the mesh
  has no IPv6, so a node whose IPv4 address clashes can't be reached from the Mac. Without root, the networks are
  the user's own, in userspace mode, each with its own SOCKS port (1055, 1056, ...).

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
`rename`, `tag`, `share`, `invite`, `ssh allow`, `update` and `uninstall` work without sudo.
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
sudo meshvpn ssh allow ssh-ed25519 AAAA... --as carol   # whoever holds this key, from any node
sudo meshvpn ssh allow 3f9a2c81 --as carol       # a node by its id
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
not its name, and if two nodes match a name, `allow` refuses and lists their ids instead of guessing. A key allowed
directly doesn't have to be published by any node, and also works from nodes that join later, but only from inside the
network. Your other SSH settings and existing logins stay as they are. Needs OpenSSH with `sshd_config.d` support
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
* **Keys already on the machine:** it also accepts the keys in the account's `~/.ssh/authorized_keys`, for example ones
  an image or another SSH service put there, as sshd would. They work from mesh nodes only. Lines with options
  (`command=`, `restrict`...) don't count, because only sshd can apply those, and neither does a file others can write to;
  `meshvpn ssh list` and `doctor` show why a login was refused. Off with `ssh_authorized_keys = false`; always off with the
  enterprise edition, whose rules decide who logs in.
* **No host key prompts:** every node publishes the host key of whatever answers SSH there (the built-in server's key is
  derived from the node identity; for sshd its ed25519 host key), and meshvpn keeps them in
  `/var/lib/meshvpn/known_hosts`, which ssh reads through `/etc/ssh/ssh_config.d/meshvpn.conf`. `ssh` to a mesh node
  doesn't ask "are you sure?" and works with `StrictHostKeyChecking=yes`.
* Not supported: agent and X11 forwarding, `-R` remote forwarding.

## Remote desktop in the browser

```sh
meshvpn desktop gpu-box            # prints a link to gpu-box's desktop (--open: open a browser too)
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
* Apps get a UTF-8 locale and the bundled DejaVu fonts if the image has none. Not yet: sound. GPU: see `setup --gpu` below.
* **A full desktop: Xfce, MATE or Cinnamon.** `sudo meshvpn desktop setup --desktop mate` on the node (or `xfce`,
  `cinnamon`; also at install time: `install.sh --desktop mate`) installs it with the system's package manager (apt,
  dnf, zypper; Xfce and MATE also apk) and makes it the node's choice: from then on `meshvpn desktop <node>` opens it,
  with its panel, applications menu, file manager and terminal. The tabs in the browser bar follow its windows; logging
  out of it ends the session. `--session xfce|mate|cinnamon|plain` asks for another one (`--plain`: meshvpn's built-in
  minimal desktop). A running session keeps its desktop until `meshvpn desktop stop`. Cinnamon draws with OpenGL, so it
  runs on the system's Xvfb with Mesa's software rendering (installed with it): fine for office work, slower than the
  others. Screen lockers don't start in Xfce and MATE sessions (they would lock a desktop only a browser shows);
  Cinnamon starts its own, so an idle Cinnamon session can lock and then needs the account's password.
* **Xfce or MATE without root,** for example in a Docker image where you aren't root:
  `curl -fsSL .../install.sh | sh -s -- --user --desktop xfce join mesh1-...` (or `--desktop mate`; or `sh
  meshvpn-full-<arch>.run [--desktop mate] join mesh1-...` from the release, for machines without internet). Without a
  package manager, Xfce and MATE come packed together with the Chromium browser and all their libraries: any
  distribution, x86_64 and ARM64, about 750 MB to download, 2.3 GB in `~/.local` per user. `--desktop` picks the one
  `meshvpn desktop <node>` starts by default; the other is there too (`meshvpn desktop <node> --desktop mate`). It needs no privileges, user namespaces or changes to how the container is started. The
  installer changes the path built into the programs to one of the same length, a link like `/tmp/mvx7k` that points to
  your files, so `/tmp` must be writable, and `HOME` must be set and writable. If `/tmp` is emptied the link comes back
  when a desktop program starts; if another user has taken the name, nothing runs and installing again picks a new one.
  Terminals keep using the machine's own programs. Allow logins with `meshvpn ssh allow <user>@<node> --as <you>`, then
  `meshvpn desktop <node> --user <you>` from the other node. Container users with no name (not in `/etc/passwd`, such
  as `docker run --user 54321`) log in by number: `--as 54321`, with `HOME` set. Without `/dev/net/tun` this runs in
  userspace mode, see above.
  **It doesn't update itself:** a new meshvpn release brings a new browser, so install the newest release regularly
  (`meshvpn doctor` warns when the browser is over 30 days old). The browser is Chromium as nixpkgs builds it; where the
  machine blocks user namespaces (default Docker) it runs without its sandbox and shows a warning, so only open sites
  you trust there. Licences are in `~/.local/share/meshvpn/desktop-full/opt/meshvpn-desktop-full`, the complete source
  is on the release page as `meshvpn-full-sources-<arch>.tar.gz.part*`. `sh meshvpn-full-<arch>.run --uninstall`
  removes the desktop and keeps meshvpn. (With root, `install.sh --full` installs the same for the whole machine, in
  `/nix/store`; the package manager's desktop above is the better choice there.)
* **Built into a Docker image,** so that nobody has to install it and the 2.3 GB survive new containers (use your
  image's user in `--chown`: without it, a non-root user can't delete the file from `/tmp`):
  ```dockerfile
  COPY --chown=1000:1000 meshvpn-full-x86_64.run /tmp/full.run
  RUN sh /tmp/full.run && rm -f /tmp/full.run
  ```
  Containers usually have no systemd or cron, so **nothing starts meshvpn after a restart: run `~/.local/bin/meshvpn up`
  in the background from your entrypoint.** Join when the container first starts, not in the Dockerfile, or all
  containers of the image would be the same node, and keep `~/.config/meshvpn` on a volume so that a new container stays
  that node. A read-only root works (`--read-only --tmpfs /tmp`) as long as the home is writable.
* **The GPU for 3D and for the picture:** `sudo meshvpn desktop setup --gpu` on the node installs VirtualGL, ffmpeg and
  the system's Xvfb. From then on OpenGL programs in desktop sessions render on a GPU the user may use (VirtualGL with
  EGL, for every program of the session, the desktop's compositor included; with bookings the booked GPU, since only its
  device is accessible) instead of on the CPU, and the GPU encodes the picture as H.264 (NVENC on NVIDIA, VA-API on
  Intel/AMD), which browsers with WebCodecs decode (Chrome, Edge, Safari 17+): much less data and CPU than picture
  tiles with moving content or at high resolutions. Without an encoder or in other browsers it stays tiles. To choose:
  `MESHVPN_DESKTOP_GPU=/dev/dri/card1` (or `off`) and `MESHVPN_DESKTOP_ENCODER=nvenc|vaapi|off` in the node's
  environment; in the browser `localStorage["meshvpn.video"] = "off"` keeps tiles. The session log says what it uses
  (`3D: VirtualGL on …`, `video: NVENC`). Fedora's own ffmpeg has no H.264 encoder: there use RPM Fusion's.
* **The machine's own screen:** `meshvpn desktop <node> --screen` shows the desktop you are logged in to at that
  machine, with its windows and programs as they are (your Chrome included), instead of a desktop of its own. It keeps the
  monitor's size (the browser scales it); with several monitors the bar shows *Screen 1*, *Screen 2*, … and *All*,
  starting with the primary one. It stays visible at the machine while shared (with a notification there), and ends
  when you close the tab; the programs keep running. X11 desktops only (Xorg: Cinnamon, MATE, Xfce, KDE or GNOME on X11);
  a Wayland session is refused with a note. Chrome in a desktop of its own uses a separate profile while your usual one
  is open on the machine's screen, because Chrome would otherwise open its windows there.
* **Your desktop at the desk, too:** `sudo meshvpn desktop setup --login` adds *meshvpn desktop* to the login screen.
  Logging in with it shows your meshvpn desktop on the monitor, the same one `meshvpn desktop <node>` opens in a browser.
  It runs in its own X server, so it keeps running when you leave the desk (**Ctrl+Alt+End**, back to the login screen)
  and while someone else logs in there with theirs: each person gets their own desktop, at the desk or in a browser,
  at the same time. The keyboard layout of the desk is used. Not yet: sound, USB devices at the desk.
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

**Instructions for agents:** `meshvpn guide` prints how to work with meshvpn - the rules (`--json`, selectors, what
to ask a human first, cleaning up reservations and jobs), the commands for each task, and the network right now
(this node, the other nodes, tags, free GPUs). Point your agent at it, e.g. in `AGENTS.md`/`CLAUDE.md`: *"Run
`meshvpn guide` before working with other machines."* For Claude Code, install it as a skill:
`mkdir -p ~/.claude/skills/meshvpn && meshvpn guide --skill > ~/.claude/skills/meshvpn/SKILL.md`. MCP clients get the
same instructions automatically when they connect.

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
| `sudo meshvpn net matrix --measure <nodes>` | RTT, mesh throughput and **direct LAN paths** from this node to the named nodes (at most 16; test data only over direct paths), with the LAN path's own throughput (4 streams straight to the other node, as NCCL uses it). A LAN path is a shared subnet, or a peer's own private address that the mesh's direct path already reaches (pods of a cluster). Without `--measure`: what every node measured itself (each checks its direct paths every 5 minutes) |
| `meshvpn net why <node>` | **Why there's no direct connection** to a node: tests from both ends for about 10 seconds, says what got through and what to do. Exit code 1 without a direct connection; both nodes need this version for the full answer |
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
| `meshvpn status [--all]` | This node and its peers (no sudo needed); in networks over 32 nodes those with a direct path and a summary, `--all` lists every node |
| `sudo meshvpn doctor` | Checks the setup (daemon, Tailscale conflicts, firewalls, peers, UDP paths, SSH logins, admins, updates) and says how to fix each problem |
| `sudo meshvpn invite [--uses N] [--expires 24h]` | Print an invite code for a new machine (single-use and valid for 24 h by default) |
| `meshvpn admin status` / `sudo meshvpn admin add\|rm <node>` | Who the admins are; change them |
| `sudo meshvpn update` | Install the latest release. Nodes check for new releases every ~6 hours and show them in `meshvpn status` / `doctor`, but never install them by themselves |
| `sudo meshvpn forget <name>` | Remove an offline node (e.g. an old identity of a re-installed machine) from all nodes. `--offline` forgets all offline nodes. If an offline node's name is taken by a newer online node, it's forgotten automatically after 10 minutes |
| `sudo meshvpn ban <name>` | Throw a node out for good (see below) |
| `sudo meshvpn ssh` | Choose who may log in here over SSH without a password |
| `sudo meshvpn rename <name>` | Give this node a new name. It becomes `<name>.mesh` on every node within seconds; its IP, SSH permissions and links stay. Names already taken are refused |
| `sudo meshvpn exit offer` / `exit use <node>` / `exit off` | Internet through another node (exit nodes) |
| `meshvpn networks` / `sudo meshvpn networks leave <name>` | The networks this machine is in ([several networks](#several-networks-on-one-machine)); `--net <name>` picks one for any command |
| `sudo meshvpn leave` | Leave the network (or the one of `--net`): the other nodes forget this one, meshvpn stops for it and its configuration and keys are removed. If it was the machine's first network, the next one becomes the first (its names are then `<node>.mesh`). The only admin of a managed network makes another node admin first (`sudo meshvpn admin add <node>`); an admin that leaves hands the role to the others. `meshvpn status` lists the admins. |
| `sudo meshvpn connect host[:port]` | Connect the network to a node it can reach but that can't reach it (alias: `add-peer`) |

**Tab completion** (bash) comes with `meshvpn install`: commands and options, and the names and tags of the nodes as they
are right now (`meshvpn exec gp<Tab>`, `ssh allow alice@<Tab>`, `cp ./data gpu1:<Tab>`). Where the bash-completion
package isn't installed (many container images), install adds one marked line to `~/.bashrc`; `uninstall` removes it.
Elsewhere: `source <(meshvpn completion bash)`, in zsh after `autoload bashcompinit; bashcompinit`.

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
| Addresses | `100.64.0.0/10` + 22 bits of `blake3(node id)`. Deterministic, so no allocation server is needed. Two nodes may get the same address by chance (about 1 network in 9 at 1000 nodes): an address two nodes claim belongs to nobody from then on (so no node can take over another's by claiming it too), and both restart with their next of 16 candidate addresses, which their record names. IPv6: `fd00::/8` + 40 bits of a hash of the network id (a /64 for each network) + 64 bits of a hash of the node id. Nodes say in their record whether they have IPv6 (it's off with `ipv6 = false` in the config, where the machine has IPv6 off, and in userspace mode); names point to the IPv6 address only of those that do. Inbound filtering by the extension and anti-spoofing apply to both. |
| Transport | TCP links (the only thing an SSH tunnel or proxy can carry) for control traffic, and **direct UDP paths** for data wherever possible. Nodes publish their address candidates (LAN, public address as other nodes see it) and keep sending authenticated probes to each other, which opens a path through both NATs (hole punching). Data then goes directly over UDP; if a path stops answering it falls back to TCP or a relay within seconds. IPv6 addresses are candidates too: without NAT on the way, probes from both sides get through stateful firewalls, also where IPv4 hole punching can't (NATs that change the port per destination, typical for mobile networks - `meshvpn status` and `doctor` say which kind of NAT a node is behind). |
| Discovery | Nodes sign a record (name, endpoints, neighbors, sequence number) and gossip all records they know. A new link gets the full table; changes are flooded. The state is saved to disk, so the mesh survives losing the bootstrap node. |
| Connectivity | Every node dials every other node's advertised endpoints (with backoff). Endpoints are configured, auto-detected (LAN IP, public IP as seen by peers or STUN servers, the port opened on the home router with UPnP/PCP/NAT-PMP) or the SSH tunnel's public port. |
| Hole punching (IPv6) | Towards nodes without a link: UDP probes and TCP connects from the fixed port (`listen` port) to their global IPv6 addresses, from the rendezvous or the node's record (heard of within a day); stateful firewalls let the crossing packets in. Both ends get the TCP connection from connect() (simultaneous open), so the lower node id starts the Noise handshake. |
| Rendezvous | Nodes with endpoints (and every node with global IPv6 addresses, for hole punching) put them into BitTorrent's Mainline DHT (BEP 44 mutable item, every 30 minutes and when they change): under a key and salt derived from the network key, the node id and the day; XChaCha20-Poly1305 with a key from the network key; signed by the node and dated (older than 75 minutes is ignored). After a put, the node looks its entry up itself and puts it again soon if a lookup still finds an older one. Nodes look up those they lost (every 2 minutes while they have no link or the node has been gone less than 15 minutes, 10 minutes otherwise, hourly for nodes gone for a day) and dial the addresses found first; for hole punching they use the newer of entry and record, all addresses at once. The DHT client never answers or stores anything for others. |
| Relaying | Records list each node's neighbors. Nodes that can't connect directly are reached by a shortest path (BFS) through other nodes. |
| Encryption | Hop-by-hop Noise encryption, plus end-to-end XChaCha20-Poly1305 per packet (a static-static X25519 key bound to the network id). Relays can't read or forge traffic, and the inner source IP must match the sender. |
| Names | `<name>.mesh` entries in a marked block of `/etc/hosts` (`manage_hosts = false` to disable); `<name>.<network>.mesh` for a further network of the machine. |

Files: `/etc/meshvpn/config.toml` (settings and secret keys, mode 0600), `state.json` (known nodes) and `/run/meshvpn.sock`
(control socket: anyone may ask for the status, but changes need root). Use `--dir` or `MESHVPN_DIR` to put them elsewhere, e.g. to run several nodes on one machine. A further network of the
machine lives in `/etc/meshvpn/networks/<name>/`.
Set `RUST_LOG=meshvpn=debug` for verbose logs.

## Security model and limitations

Found a vulnerability? Please report it privately, see [SECURITY.md](SECURITY.md). Every release has SHA-256 checksums,
from 0.27.0 on signed (`SHA256SUMS.sig`), and a CycloneDX software bill of materials (`meshvpn-<version>.cdx.json`).
What changed in each release: [CHANGELOG.md](CHANGELOG.md).

* In managed networks (the default since v0.7) only admins invite, ban and change the admins. In open networks every
  member can do all of that. Members are trusted either way: they can reach each other's services and share data.
  Treat invite codes like passwords until they are used or expire. If two admins ban nodes at the same moment, run the
  ban again.
* Updates are downloaded from this repository's GitHub releases. From 0.27.0 on, `meshvpn update` installs a release
  only if its checksums carry a valid signature of the release key, which the build machines don't hold (so a
  compromised GitHub account alone can't ship an update). Nodes never install updates by themselves: only
  `meshvpn update` does.
* The end-to-end layer has replay protection (since 0.24.0) but no forward secrecy (the hop-by-hop Noise links have
  both).
* Invites are bearer secrets: whoever has one can join (until it is used up or expires). Members see the tickets in
  each other's admissions, but can't use them: a ticket counts only together with the invite's one-time key.
* The first network has IPv4 and IPv6 mesh addresses (macOS: IPv4 only). Platform differences: see the table at the
  top.
* Direct UDP paths work through the common kinds of NAT (one public port per internal port, as most home routers do).
  "Hard" NATs that use a new port for every destination (some carrier-grade NATs and corporate firewalls) can't be
  punched through. Those nodes keep using TCP and relays, which is slower on lossy links (TCP-over-TCP). For the best
  results, allow UDP on port 7870 in front of public nodes, as you do for TCP. Switch it off with `udp = false`.
  `meshvpn net why <node>` tells you which case you're in.
* Every node keeps a link to every other node. Tested with up to 200 nodes on one machine (about 46 kB/s per
  node at rest, see `docs/design-scaling.md`); much larger networks need links on demand, which isn't built yet.
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

To publish a release, add its section to [CHANGELOG.md](CHANGELOG.md), then push a tag
(`git tag -a v0.2.0 -m "meshvpn v0.2.0" && git push origin v0.2.0`; only maintainers may create `v*` tags). The
release workflow refuses a tag without a changelog section, builds static binaries for every architecture,
`.deb`/`.rpm` packages, checksums and the SBOM, runs the end-to-end tests, signs `SHA256SUMS` with the release key
(GitHub environment `release`) and publishes it all with the changelog section at the top of the release notes.

The release key's certificate (`release-key.cert`) runs out after about a year; the workflow warns 30 days ahead.
Renew it where the root key is: `scripts/certify-release-key.sh release-key.pub.pem 400 > release-key.cert`, commit.
If the release key leaked: make a new one, store it as the secret `MESHVPN_RELEASE_KEY` of the environment
`release`, certify it, and add the old one to `REVOKED_KEYS` in `src/update.rs`. In an emergency a root key can sign
a release itself: `scripts/sign-release.sh PlugOvr-ai/meshvpn vX.Y.Z`.

The end-to-end behavior was tested with three rootless network namespaces: a public node, a NAT'd node without a
listener, and a node whose firewall only allows SSH to a jump host. That covered direct links, relayed traffic, SSH
tunnel restarts, hub restarts and `connect` for inbound-only nodes.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

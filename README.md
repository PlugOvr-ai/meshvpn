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

Any member can print a new invite with `sudo meshvpn invite`. Use `sudo meshvpn up` instead of `install` to run in the
foreground.

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

## Everyday use

| Command | What it does |
|---|---|
| `meshvpn status` | This node and its peers (no sudo needed) |
| `sudo meshvpn invite` | Print an invite code for a new machine |
| `sudo meshvpn update` | Install the latest release now. Nodes also update themselves automatically: they check every ~6 hours; disable with `auto_update = false` |
| `sudo meshvpn forget <name>` | Remove an offline node (e.g. an old identity of a re-installed machine) from all nodes. `--offline` forgets all offline nodes. If an offline node's name is taken by a newer online node, it's forgotten automatically after 10 minutes |
| `sudo meshvpn ban <name>` | Throw a node out for good (see below) |
| `sudo meshvpn ssh` | Choose who may log in here over SSH without a password |
| `sudo meshvpn rename <name>` | Give this node a new name. It becomes `<name>.mesh` on every node within seconds; its IP, SSH permissions and links stay. Names already taken are refused |
| `sudo meshvpn add-peer host:port` | Connect to a node at an address, e.g. an inbound-only node |

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
| Transport | TCP (the only thing an SSH tunnel can carry), with one link per pair of nodes. |
| Discovery | Nodes sign a record (name, endpoints, neighbors, sequence number) and gossip all records they know. A new link gets the full table; changes are flooded. The state is saved to disk, so the mesh survives losing the bootstrap node. |
| Connectivity | Every node dials every other node's advertised endpoints (with backoff). Endpoints are configured, auto-detected (LAN IP, public IP as seen by peers) or the SSH tunnel's public port. |
| Relaying | Records list each node's neighbors. Nodes that can't connect directly are reached by a shortest path (BFS) through other nodes. |
| Encryption | Hop-by-hop Noise encryption, plus end-to-end XChaCha20-Poly1305 per packet (a static-static X25519 key bound to the network id). Relays can't read or forge traffic, and the inner source IP must match the sender. |
| Names | `<name>.mesh` entries in a marked block of `/etc/hosts` (`manage_hosts = false` to disable). |

Files: `/etc/meshvpn/config.toml` (settings and secret keys, mode 0600), `state.json` (known nodes) and `/run/meshvpn.sock`
(control socket: anyone may ask for the status, but changes need root). Use `--dir` or `MESHVPN_DIR` to put them elsewhere, e.g. to run several nodes on one machine.
Set `RUST_LOG=meshvpn=debug` for verbose logs.

## Security model and limitations

* Everyone with the network key is a trusted member, and all members are equal: any member can ban any other. Treat
  invite codes like passwords. Banning is covered above; if two members ban nodes at the same moment, run the ban again.
* Updates are downloaded from this repository's GitHub releases and checked against the published SHA-256 checksums.
  That protects against corrupted downloads, but not against a compromised GitHub account. Set `auto_update = false`
  if you want to update manually.
* The end-to-end layer has no replay protection or forward secrecy (the hop-by-hop Noise links have both).
* IPv4 only, Linux only (the TUN setup and systemd integration).
* The TCP transport means TCP-over-TCP, which works well on good links but degrades on lossy ones. There's no UDP hole
  punching; NAT'd nodes that can't reach each other go through a relay instead.
* The mesh is full-mesh by design, which suits networks of up to a few dozen nodes.
* Overlay IPs come from a 22-bit hash. A collision is unlikely in small networks; if one happens, the node with the
  lower id keeps the address.

## Development

```sh
cargo test
cargo build --release
```

To publish a release, push a tag (`git tag v0.2.0 && git push origin v0.2.0`). The release workflow then builds static
binaries for every architecture, `.deb`/`.rpm` packages and checksums, and attaches `install.sh`.

The end-to-end behavior was tested with three rootless network namespaces: a public node, a NAT'd node without a
listener, and a node whose firewall only allows SSH to a jump host. That covered direct links, relayed traffic, SSH
tunnel restarts, hub restarts and `add-peer` for inbound-only nodes.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

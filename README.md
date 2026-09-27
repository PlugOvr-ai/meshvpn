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

## How it works

| Piece | Design |
|---|---|
| Identity | Each node has an ed25519 key (its node id) and an X25519 key. |
| Membership | A shared 32-byte network key from the invite. Links use Noise `XXpsk3` with it as the PSK: without the key, the handshake fails. |
| Addresses | `100.64.0.0/10` + 22 bits of `blake3(node id)`. Deterministic, so no allocation server is needed. |
| Transport | TCP (the only thing an SSH tunnel can carry), with one link per pair of nodes. |
| Discovery | Nodes sign a record (name, endpoints, neighbors, sequence number) and gossip all records they know. A new link gets the full table; changes are flooded. The state is saved to disk, so the mesh survives losing the bootstrap node. |
| Connectivity | Every node dials every other node's advertised endpoints (with backoff). Endpoints are configured, auto-detected (LAN IP, public IP as seen by peers) or the SSH tunnel's public port. |
| Relaying | Records list each node's neighbors. Nodes that can't connect directly are reached by a shortest path (BFS) through other nodes. |
| Encryption | Hop-by-hop Noise encryption, plus end-to-end XChaCha20-Poly1305 per packet (a static-static X25519 key mixed with the network key). Relays can't read or forge traffic, and the inner source IP must match the sender. |
| Names | `<name>.mesh` entries in a marked block of `/etc/hosts` (`manage_hosts = false` to disable). |

Files: `/etc/meshvpn/config.toml` (settings and secret keys, mode 0600), `state.json` (known nodes) and `meshvpn.sock`
(control socket). Use `--dir` or `MESHVPN_DIR` to put them elsewhere, e.g. to run several nodes on one machine.
Set `RUST_LOG=meshvpn=debug` for verbose logs.

## Security model and limitations

* Everyone with the network key is a fully trusted member. You can't revoke a single node; to remove one, create a new
  network and re-invite the others. Treat invite codes like passwords.
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

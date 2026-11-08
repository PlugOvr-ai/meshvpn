# Changelog

All notable changes to meshvpn. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/) (before 1.0, a minor version may change
behaviour). Every release must have a section here: the release workflow refuses a tag without one and
puts the section at the top of the release notes.

Sections: **Added**, **Changed**, **Fixed**, **Security**, **Removed**. Security fixes say what an
attacker needed and what they could do.

## [Unreleased]

## [0.27.2] - 2026-11-08

### Added
- `desktop setup --gpu` takes the VirtualGL package from `MESHVPN_VIRTUALGL_DIR` if it is there (machines
  without internet); it is checked against the same checksum as a download.

### Changed
- README: a note that meshvpn is early (before 1.0) software, provided as is, at your own risk.
- `net matrix`: the age of a measurement in the largest unit that fits (`17m`, `5h`, `2d`), not in
  seconds. `--json` still gives seconds.
- The end-to-end tests take VirtualGL from a cache instead of GitHub (a GitHub outage failed
  them for 0.27.0 and 0.27.1).

## [0.27.1] - 2026-11-08

The first release with the changes of 0.27.0: that tag's build failed on macOS and was not
published.

### Fixed
- The macOS build (an SSH-server helper that only Linux uses).
- `desktop setup --gpu` tries the VirtualGL download again when GitHub's servers answer with an
  error.

## [0.27.0] - 2026-11-08 [not released]

### Security
- **Signed releases.** From this version on, every release has `SHA256SUMS.sig`, an Ed25519
  signature of `SHA256SUMS` made with a release key that the build machines don't hold.
  `meshvpn update` and `meshvpn desktop setup` install a release from 0.27.0 on only if the
  signature verifies against the keys built into meshvpn. The signature names the version, so an
  older release's checksums can't pass for a newer one's. Before, the checksums came from the same
  release as the files, so whoever could change a release could also change its checksums. How to
  check a download by hand: `SECURITY.md`.
- **Invite tickets are bound to the invite.** Admission tickets travel inside every claim, so every
  member of a managed network saw them, and could use a multi-use ticket's remaining uses, or
  race a new node's claim during its first hour. A ticket now names a one-time key whose secret
  is only in the invite, and a claim counts only if that key signed it for this node and this
  time. Invites made before 0.27.0 still work. A new node needs 0.27.0 to join with a new invite.
- **SSH server: locked and expired accounts.** The built-in SSH server let accounts in with keys
  after `passwd -l` (on an account that had a password) or after the account expired
  (`chage -E`, `usermod -e`). Both now refuse the login, as sshd does with PAM. Accounts without
  a password (`!` or `*` in `/etc/shadow`) can still log in with keys.
- **Windows: `C:\ProgramData\meshvpn` belongs to the administrators.** It was readable by every
  local user (with the node's private keys), and a folder planted there before installation
  stayed the planter's. Now its owner is the Administrators group, and only Administrators and
  SYSTEM can open it or anything in it, also if it existed before. Windows is not released at
  the moment; this has to hold before it is.
- **UDP probes: replays aren't answered.** A recorded probe sent again, from any address, made
  the node send answers at that address (a reflection). Probes seen before, or more than two
  minutes behind the sender's newest, now get no answer.
- **Split UDP datagrams: no crowding out.** The id prefix in a datagram's parts is no secret, so
  anyone could fill a node's room for unfinished datagrams in another node's name. Parts from a
  node's current UDP path now always find room, every sending address has its own limit, and
  the parts of one datagram must all come from one address.
- **Several networks: address clashes are checked again when the first network changes.** A node
  that joined the machine's first network later, with an address a further network already used,
  wasn't noticed until that further network's own nodes changed.

### Changed
- The release workflow refuses a tag without a section in this changelog, and puts that section
  at the top of the release notes.
- GitHub Actions are pinned to commit SHAs, not tags.

### Added
- `scripts/sign-release.sh`: signs a published release (run where the release key is).
- `CHANGELOG.md`.

## [0.26.0] - 2026-11-07

### Added
- **Joining through hole punching.** A new node meets the inviting node even if neither can
  reach the other (a home router without a port forward, a mobile network). The invite carries
  a join hint: a secret slot, the inviting node's id and IPv6 addresses. Until it has met
  anyone, the new node puts its addresses into the DHT at a place derived from the network key
  and the slot, and tries the inviting node's. The inviting node looks there while the invite
  is open. Needs `dht = true` on the inviting node; the new node uses the DHT for this one
  meeting, whatever its own setting.

## [0.25.2] - 2026-11-07

### Changed
- Rendezvous: lookups every 2 minutes while a node is alone or a peer has been offline for less
  than 15 minutes. After a publish, a read-back checks that the entry is there. Republishes
  after 2 minutes if fewer than 8 DHT nodes stored it.
- Hole punching tries all known addresses of a node at once, and takes them from the newer
  source: the DHT entry or the node's record.

## [0.25.1] - 2026-11-07

### Security
- Only temporary (privacy) IPv6 addresses go into the DHT entry, never the stable one that
  would let anyone with the network key follow a machine around.

### Added
- `punch = false` switches hole punching off.

### Changed
- Slower retries towards nodes that stay offline: eagerly for 15 minutes, then only in the first
  minute of every five (by the clock, so both sides try at the same time).

## [0.25.0] - 2026-11-07

### Added
- **Hole punching over IPv6.** Two nodes behind stateful firewalls (no port forward, mobile
  networks) connect directly: UDP probes, and a TCP simultaneous open from the listen port that
  becomes the link. The addresses come from the rendezvous and the nodes' records. On by
  default, off with a socks proxy or `no_outbound`.

## [0.24.1] - 2026-11-07

### Added
- `meshvpn leave` and `meshvpn networks leave <name>`: leave a network, also the machine's
  first one. The last admin must make another node admin first; an admin with other admins
  hands over.
- `status` shows who is admin.
- The status hint when a router refuses automatic port forwarding.

### Security
- Port mapping: answers only from the gateway, size limits, router texts cleaned before they are
  shown, no permanent leases, mappings removed at shutdown.
- STUN: answers count only with the right transaction id and from the server that was asked.

## [0.24.0] - 2026-11-07

### Added
- **Automatic port forwarding** on the home router (PCP, NAT-PMP, UPnP IGD), for nodes with a
  listen port. Off with `port_mapping = false`.
- **STUN**: a node learns its public address while no peer tells it.
- **DHT rendezvous** (off by default, `dht = true`): nodes find each other again after their
  addresses change, without a server. Each node publishes an encrypted, signed entry in the
  BitTorrent Mainline DHT, at a place only members can derive.

### Security
Fixes from the audit of 7 November 2026:
- Forgetting a node needs a signature: by an admin in managed networks. Before, any member could
  erase any node, admins too, from the whole mesh for good.
- Witnessed claims: expiry and dates are checked, witnesses must be admins, or members while the
  ticket is valid, and a late claim can't push out an earlier one. Before, a member could reuse
  any ticket it had seen to admit new identities.
- Duplicate names are settled by admission order, not by a sequence number the sender chooses
  (which let a member take over another node's name in `/etc/hosts` and `known_hosts`).
  `admin add` and `exit use` refuse an ambiguous name.
- Replay protection for data packets: a window per sender, the sender's id in the nonce, the
  session number kept on disk. A replayed datagram used to move a direct path to the attacker.
- Several networks on one machine: addresses that clash with the first network are withheld,
  and spoofed sources from them dropped.
- A LAN path is proven by an authenticated UDP answer, not by any TCP answer.
- Relay routes use only links both ends name.
- Limits: fragment sizes and slots, handshakes before authentication (per IPv4 address or IPv6
  /64), measurements (none from clients, one every 20 s). Loopback, link-local and v4-mapped
  endpoints are filtered.
- Built-in SSH server: proxy credentials aren't passed to sessions, port forwards are opened as
  the account, `nologin`/`false` accounts can't log in, `authorized_keys` is opened without
  following links.
- Sharing: chunks are served only if their hash matches, from regular files only. `fetch` hands
  only what it created to the user and refuses destinations others can change.
- Desktop: pinned VirtualGL checksums in a private temporary directory, `zypper` checks
  signatures again, the viewer link token is single-use, the desk locks after 15 minutes idle,
  desk-only messages are refused in `--screen` mode, setuid bits are stripped from the bundle.
- GPU leases belong to whoever made them. Env names are checked in `launch`. The install and
  deploy scripts fail without a checksum tool; `deploy.sh` no longer uses `/tmp`.
- Dependency updates (rustls, rustls-webpki, webpki-roots, tokio and others with advisories).
- Workflows: read-only permissions by default.

## [0.23.0] - 2026-11-06
### Added
- Desktop at the desk (the login screen), Xfce, MATE and Cinnamon, 3D on the GPU (VirtualGL),
  H.264 encoded on the GPU.

## [0.22.5] - 2026-11-06
### Added
- `meshvpn desktop --screen`: share the machine's own screen, one monitor at a time.

## [0.22.4] - 2026-11-06
### Fixed
- Desktop: Chrome opens in the remote desktop, not on the machine's own screen.

## [0.22.3] - 2026-11-06
### Added
- `net matrix` shows the LAN path's own throughput next to the mesh's.
### Changed
- `desktop setup` takes the bundle from meshvpn's own releases, also in the enterprise build.

## [0.22.2] - 2026-11-06
### Added
- Tab completion for bash (commands, options, node names, tags).
### Fixed
- Desktop: AltGr characters, proxy settings for desktop programs.

## [0.22.1] - 2026-11-06
### Fixed
- LAN paths between pods; accounts with large uids count as people (keys published).

## [0.22.0] - 2026-11-06
### Added
- IPv6 in the mesh: every node has an address in its network's own prefix.
- macOS and Windows builds, CI and releases again.

## [0.21.0] - 2026-11-06
### Added
- Several networks on one machine.

## [0.20.0] - 2026-11-05
### Added
- `net why`: why there's no direct connection to a node.
- `ssh allow` takes public keys; the built-in server honours `authorized_keys`.
### Changed
- Packed desktop: Chromium instead of LibreWolf.

## [0.19.1] - 2026-11-05
### Fixed
- Release: the packed desktop's files arrive as files.

## [0.19.0] - 2026-11-04
### Added
- `install.sh --full`: everything in one file (Xfce and a browser), with or without root.
- Extensions see where nodes accept connections.

## [0.18.0] - 2026-11-01
### Added
- Clients: a user's computer as a member for a time (`invite --client <user> --client-for 12h`).
- `net check` before distributed training.
### Changed
- CI and releases for Linux only for now (macOS and Windows paused).

## [0.17.0] - 2026-10-31
### Added
- `SECURITY.md` (private reporting, response times); a CycloneDX SBOM in every release.
- Extensions: extra host names, torchrun arguments.

## [0.16.1] - 2026-10-31
### Added
- meshvpn as a library with an extension interface; `install.sh --enterprise`.
### Fixed
- `install.ps1` in Windows PowerShell 5.1.

## [0.16.0] - 2026-10-30
### Added
- Direct paths over IPv6; a NAT check in `status` and `doctor`.

## [0.15.1] - 2026-10-30
### Fixed
- `meshvpn ssh` on macOS offers the Mac's user accounts.

## [0.15.0] - 2026-10-24
### Added
- macOS (utun, launchd) and Windows (Wintun, scheduled task) support.

## [0.14.1] - 2026-10-15
### Fixed
- Desktop bundle: fallback source for X.org, checksums verified.

## [0.14.0] - 2026-10-15
### Added
- Exit nodes: internet through another node of the mesh.

## [0.13.5] - 2026-10-11
### Added
- `meshvpn connect`: a firewalled network connects to a node outside it.

## [0.13.4] - 2026-10-11
### Security
- Stricter record validation, address ownership, safer file transfers.
### Added
- `meshvpn guide`: instructions for AI agents.

## [0.13.3] - 2026-10-08
### Added
- Default login user per node.

## [0.13.2] - 2026-10-06
### Added
- Distributed training tutorial; throughput tests over the data path.

## [0.13.1] - 2026-10-06
### Added
- Desktop file browser and image viewer; versions in `status`.
### Fixed
- Small-MTU paths.

## [0.13.0] - 2026-10-06
### Added
- Xfce desktops.

## [0.12.2] - 2026-10-06
### Fixed
- Direct UDP paths with a small MTU: big datagrams are split.

## [0.12.1] - 2026-10-06
### Changed
- No automatic updates; `console` logs in like plain ssh.

## [0.12.0] - 2026-10-06
### Added
- `meshvpn console`; desktop links over SSH.

## [0.11.0] - 2026-10-05
### Added
- `meshvpn desktop`: remote desktops in the browser.

## [0.10.1] - 2026-10-05
### Added
- Reasons for refused SSH logins and turned-away nodes; expired invites fail at join.

## [0.10.0] - 2026-10-05
### Added
- Built-in SSH server for machines without sshd.

## [0.9.0] - 2026-10-05
### Added
- Rootless installs; the end-to-end test suite.

## [0.8.0] - 2026-10-04
### Added
- `meshvpn doctor`; GPU reservations.

## [0.7.0] - 2026-10-04
### Added
- Managed networks: admins, single-use expiring invites.

## [0.6.0] - 2026-10-04
### Added
- Direct UDP paths with NAT traversal.

## [0.5.1] - 2026-10-04
### Added
- Training launcher (`launch`, `jobs`).

## [0.5.0] - 2026-10-04
### Added
- Tags, inventory, `exec`, `cp`, `--json`; network matrix, LAN paths; sharing datasets; MCP server.

## [0.4.0] - 2026-10-04
### Added
- Userspace mode for containers without NET_ADMIN or `/dev/net/tun`.

## [0.3.4] - 2026-10-04
### Added
- The system's proxy in `install.sh` and for updates.

## [0.3.3] - 2026-10-02
### Added
- `meshvpn rename`.

## [0.3.2] - 2026-09-28
### Fixed
- SSH logins: keys without a .pub file are published, no duplicate key lines.

## [0.3.1] - 2026-09-28
### Added
- SSH logins for everyone, settable at install time.

## [0.3.0] - 2026-09-27
### Added
- Password-less SSH between nodes, with a console editor.

## [0.2.2] - 2026-09-27
### Fixed
- Installing the service takes over from a meshvpn started by hand; "Resource busy" explained.

## [0.2.1] - 2026-09-27
### Fixed
- `deploy.sh` unpacks the release archive correctly.

## [0.2.0] - 2026-09-27
### Added
- Banning nodes, self-update, `deploy.sh` for offline devices, forgetting offline nodes.

## [0.1.1] - 2026-09-27
### Added
- A warning when another interface (e.g. Tailscale) uses the mesh address range.

## [0.1.0] - 2026-09-27
### Added
- First release: a decentralized mesh VPN with reverse SSH tunnels.

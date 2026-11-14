# Changelog

All notable changes to meshvpn. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/) (before 1.0, a minor version may change
behaviour). Every release must have a section here: the release workflow refuses a tag without one and
puts the section at the top of the release notes.

Sections: **Added**, **Changed**, **Fixed**, **Security**, **Removed**. Security fixes say what an
attacker needed and what they could do.

## [Unreleased]

## [0.33.1] - 2026-11-14

Fixes from a security audit: the share server asks who is fetching, a node that is online keeps its name, and
invites keep working after the admins changed.

### Security
- **A malformed node id could stop a node for good:** a node id of 64 bytes with a non-ASCII character in it made
  the parser panic while the node's state was locked. The process stayed up, but everything that needs the state
  failed from then on (no status, no new links) until a restart. One frame per node was enough. Needed: membership;
  in a managed network the network key alone (through an admission). Ids are now parsed digit by digit, and a node
  whose state can no longer be used ends itself, so that the service starts it again.
- **The network key alone no longer opens the share server:** the server for shared objects (port 7871, also on the
  LAN) served everybody who could make a tag from a network key the node ever had: a banned node, a client whose
  time was up, or whoever kept an invite that was used long ago could download every shared object for as long as
  the node ran, and make it read data without limit. Needed: such a key and a route to the port. Every connection
  now starts with a hello signed by the fetching node, and only nodes that are members now are served. Test data is
  read for 60 seconds at most, idle connections close after 5 minutes.
- **A node that is online keeps its name:** if two nodes published the same name, the name (`gpu1.mesh` in
  `/etc/hosts`, and the SSH host key that goes with it) went to the one admitted first or, in open networks and
  among the nodes of the roster, to the one with the newer record. A member could so take the name of a running node
  and get the connections meant for it; a machine set up again was always the one admitted last. Needed:
  membership; a client invite was enough, also to make every node forget a node that was offline for 10 minutes. Now
  the node that has a name keeps it while it is online, whatever another node publishes. Once it is offline, a node
  of that name that is online gets it and keeps it (a machine set up again takes over from its old identity as
  before, with no step for anybody). A client (`invite --client`) never gets a name a node has, online or not, and
  never makes the others forget a node. `localhost`, `wpad`, `isatap`, `metadata` and the like are entered with
  `.mesh` only: as plain names they never point into the mesh. What stays as it is: a node (not a client) can take
  the name of a node that is offline - names are as trustworthy as the machines admitted as nodes.
- **A node no longer stays without admins when its invite's admins didn't sign the list in force:** a node took
  the list of admins (the roster) only if an admin it knew had signed it: a new node knew the admins its invite
  named, a node that was away those of the list it had. If another admin had changed the list since - one added
  later, or one that has left - the node never took it. A new node then stayed an open network for itself: every
  member could ban nodes on it, and `sudo meshvpn admin enable` there made it its own admin. A node that came back
  stayed with its old list, with admins that had been removed. Needed: nothing but an invite made before the admins
  changed, or a node that was off at the time. Now every admin gives its signed word for the list in force
  (kept and passed on with it), and a node takes a list that an admin it knows signed or gave its word for. A node
  that joined with an admin's invite is managed from the start: until the list arrives, only the admins of its
  invite are admins for it, and `admin enable` is refused. The admins need this version for their word to exist;
  older nodes ignore it.
- **Two lists of admins are reported:** every admin can remove every other, so a node that was offline when an
  admin was removed still follows that admin - if the removed admin reaches it first with a list of its own, the
  node keeps that list, and so do two halves of a network whose admins changed the list at the same moment. That
  can't be decided by the nodes themselves and stays as it is (README, Security). New: a node that sees a member
  with another list of its version, or a later one no admin it knows stands for, or that is turned away by a member
  as not admitted, warns in `meshvpn status` and its log: `<node> has another list of admins than this node`, with
  the way out (`sudo meshvpn join --force <invite>` on the node that is wrong).
- **Clients no longer become members for good:** when an admin changed the admins (`admin add`, `admin rm`) or left,
  every client known at that moment was written into the roster as a member, without an end. Needed: a client
  invite, and waiting. Clients now stay what their invite says. A client that got into the roster before is listed
  by `meshvpn status` without `(client: ...)`: `sudo meshvpn ban <name>` removes it.
- **`meshvpn cp`: a file name starting with `-` is a file:** in an upload, such a name reached `tar` as an option, and
  one of them runs a command. Needed: a file with such a name in a directory the user uploads with `dir/*` (also
  through the MCP tool `copy_to_nodes`). The name is now passed as `./-name`.
- **Built-in SSH server: 2 minutes to log in, and limits before that:** a connection that never logged in stayed open
  for as long as the other side liked, without a limit on their number: a member could use up the daemon's open
  files, after which `meshvpn status` and other commands failed until a restart (the control socket stopped
  accepting at the first error). Needed: membership; for the control socket a local account. Now a connection has
  120 seconds to log in, at most 16 per node and 256 in all may be waiting to, and the control socket and the SOCKS
  proxy go on accepting after an error.
- **Refused logins: the user name is filtered:** the name a client asked to log in as went unfiltered (up to about
  32 kB) into the log, `meshvpn ssh list`, `meshvpn doctor` and the MCP results: forged log lines, escape sequences
  for the terminal, text for an agent. Needed: membership (no login rule, no key). A name that isn't a valid user
  name is now shown as `(invalid name)`.
- **A shared object's name can't cut a node off:** a node that fetched an object advertised it under the name in its
  manifest, unchecked - with a name of more than 128 bytes or with control characters, every other node refused its
  record from then on, across restarts, until `meshvpn unshare`. Needed: membership, and the other node fetching the
  object (a shared file with a long name did the same without an attacker). Such a manifest is now refused, `meshvpn
  share` asks for `--name`, and objects stored with such a name are no longer advertised.
- **Exit node: no forwarding to Azure's and IBM's internal addresses:** 168.63.129.16, 161.26.0.0/16 and
  166.8.0.0/14 are public ranges, but answer only inside those clouds (as 169.254.169.254 does everywhere, which was
  refused already). Needed: membership and an exit node there.
- **Releases from before the signatures are never installed:** a release older than 0.27.0 was accepted with its
  checksum file alone, which whoever can change the release can change too. Official builds never took that path;
  a build from source could (it reports an old version). Needed: control of the releases on GitHub. A build from
  source now takes the desktop components of the newest release.
- **`deploy.sh`: one key line only:** the script checked only how the key returned by the device begins; a second
  line would have been written into `authorized_keys` on the jump host without `restrict` and `command=`. Needed:
  control of the device being set up. The key must now be a single `ssh-ed25519` line of base64, and is written
  from its parts.
- **`install.sh --full` stops without a checksum tool:** without `sha256sum` it went on unchecked (the normal
  path stopped). It now also takes `shasum`, and stops if there is neither.
- **russh 0.65.1** (RUSTSEC-2026-0495, in the SSH agent server of the library, which meshvpn doesn't use).

### Changed
- **Fetching from a node with this version needs this version:** an older node gets `could not get the manifest ...
  from any holder`, and its `net matrix --measure` shows no LAN throughput towards newer nodes. This version fetches
  from older nodes as before.

## [0.33.0] - 2026-11-13

A progress bar for meshvpn cp.

### Added
- **Progress bar for `meshvpn cp`:** on a terminal, `cp` shows how much of the copy is done, the rate and the time
  left, over all nodes at once (`to 2 nodes [########--------]  45%  54.0 MB / 120.0 MB  35.2 MB/s  0:02 left`),
  then a summary line. Uploads estimate the size from the files, downloads ask the other node first. Without a
  terminal, with `--json` and through MCP, nothing changes.

## [0.32.2] - 2026-11-13

Records can no longer make every node connect to other people's addresses.

### Security
- **Records can't make the network flood other people's addresses:** every node dialed every address a record named
  (up to 32), again and again while that node was offline, for up to a week. A member could list somebody else's
  server and the whole network kept connecting to it (here 4 connections per address and node within 90 s). Needed:
  membership. Now a node dials at most 8 addresses per record, each with its own backoff shared by all records that
  name it, and an address that answers without a meshvpn handshake isn't dialed again for 30 minutes. A host name
  counts with at most 4 of its addresses.

## [0.32.1] - 2026-11-13

Open networks: no admin without confirmation; saved rosters kept across restarts.

### Security
- **No admin takeover in open networks:** in a network created with `init --open` (or before 0.7), any member could
  run `admin enable` (or send a self-signed roster) and every node accepted it: that member became everyone's only
  admin and could leave out nodes, which then dropped out. Needed: the network key. Now a first roster from another
  node only applies once the owner of each machine confirms its signer with `sudo meshvpn admin trust <node>`;
  until then the node stays open and `status` / `admin status` show who wants to be admin. Networks created managed
  (the default since 0.7) were not affected: their invites name the admins.

### Fixed
- A restarted node could lose its saved roster and act as if the network were open: the node that created the network
  after any `admin add`/`rm`, and other nodes once a roster was signed by an admin their invite didn't name. The saved
  roster was checked against the first admins again; now it is restored as accepted before.

## [0.32.0] - 2026-11-12

3D on the GPU in desktop sessions without root.

### Added
- **3D on the GPU without root:** `meshvpn desktop setup --gpu` as a normal user installs VirtualGL for that user
  (in `~/.local/share/meshvpn/virtualgl`), and their desktop sessions render OpenGL on the GPU. On NVIDIA no system
  Xvfb is needed any more (VirtualGL drives NVIDIA's EGL without GLX in the session's X server), also in containers
  with only `/dev/nvidia*`. With the packed desktop (Xfce or MATE without root) OpenGL programs are started with
  `vglrun <program>`, since the desktop's own programs can't load VirtualGL. Tested on an RTX 3090 in Docker as a
  normal user.
- `meshvpn desktop setup --desktop xfce|mate` without root picks the desktop of the packed one instead of failing.

### Changed
- Private vulnerability reporting through GitHub is the preferred channel (`SECURITY.md`).

## [0.31.1] - 2026-11-11

Addresses without collisions and the rest of the scaling plan (1000 nodes: about 20 kB/s per node, computed).

### Changed
- **No more lost addresses when two nodes share one.** Mesh addresses are a 22-bit hash of the node
  id, so two nodes can get the same one (about 1 network in 9 at 1000 nodes); until now neither was
  reachable over IPv4 then. Both now restart with their next of 16 candidate addresses, which their
  record names. The shared address belongs to nobody from then on, so a member can't take over
  another node's address by claiming it too. Nodes before 0.31.1 still can't reach a moved node
  over IPv4 (over IPv6 they can: those addresses stay as they are).
- `meshvpn status` in networks over 32 nodes lists the nodes with a direct path and sums up the others;
  `meshvpn status --all` lists every node.
- The saved state (records of all nodes, a few MB at 1000 nodes) is written only when it changed, compact,
  and every 5 minutes instead of every minute in networks over 32 nodes.
- Networks beyond ~1500 nodes no longer lose their links every 10 s: a digest too large for one link
  message is not sent (logged once). Digests in parts are the next step for such sizes.

## [0.31.0] - 2026-11-11

Large networks no longer keep a full mesh, plus the remaining audit fixes for messages one member could abuse.

### Changed
- **Links on demand in networks over 32 nodes.** A node keeps links to 4 ring neighbours and 4 random nodes,
  and opens a direct path to any other node only when it sends to it; a path unused for 5 minutes closes.
  Before, every node kept a link to every other one. `net env` and `net matrix --measure` open the paths
  they need first. Networks of up to 32 nodes stay a full mesh. Link changes are announced in batches.

### Security
- **In open networks any member could hide any node** for 5 minutes at a time, again and again, with a
  forget message (every member may forget there). A node now forgets on another's word only nodes that are
  offline here, and in open networks only a version of the record it has (the node's next record brings it
  back). Tombstones of nodes it never knew are kept up to 4096.
- Admission claims sent again cost no signature checks (before: 3-4 per copy, from any member).
- Relayed packets and extension messages carry at most 8 hops, whatever the sender set (before: up to 255),
  and clients no longer pass on extension messages.
- The reason a node gives for turning another away is shown without control characters (no terminal escapes).

## [0.30.2] - 2026-11-11

More messages from one node that made others do far more than the sender's own traffic (found by an audit
after 0.30.1). Each needed a member node or client; items marked *local* also a user without root on a member
machine. **Upgrade all nodes**: older nodes still act on these messages.

### Security
- **`meshvpn net why` flooded the network** (*local*): a request and its answer went over every link of every
  node, as sent (padded to 64 KB: about 128 MB of traffic per request at 200 nodes). Both now go only along
  the route to the node they are for, re-encoded.
- **A key rotation could circle the mesh endlessly**: a node that could not open its copy of the new key
  passed the rotation on without remembering it, so every copy came back as new. In an open network any
  member could start that; in a managed one a ban could by accident. Such a rotation is no longer passed on.
- **No limit on new versions of a node's record or details** (*local*, through an empty measurement or GPU
  reservations): every version was checked and passed on by every node. Each node now takes a burst of 5
  new versions of another node's record (and of its details), then one per second; the digests bring the
  newest version a little later. A measurement towards no node no longer re-signs the record.
- **A node could be hidden from the network for up to 30 days** (*local*): 65 GPU reservations of no GPU made
  its record too big for the others to accept. A reservation now needs at least one GPU, each once.
- **Small requests, big answers**: an empty digest made a node send all records, and a request naming one
  record 2047 times got it 2047 times. Digests are now answered at most every 4 s per link, and each record
  is sent once per request.
- **Unbounded memory from throughput-test start markers**: each new test id was kept for 2 minutes. Now at
  most 16 tests at a time, 2 per sender.

## [0.30.1] - 2026-11-11

### Security
- **`meshvpn net matrix --measure` could flood the whole network.** Any user on any member machine (no root
  needed) or any member node could ask every node to send up to 256 MB of test data to every other node, also
  through relays, and repeat that every 20 s: enough to make links time out and nodes drop out (at 50 nodes,
  about 600 GB per request). Outsiders and clients could not. Now a node measures only from itself and only when
  its own owner asks: requests from other nodes are ignored and not passed on, test data needs root or the
  node's owner and named nodes (at most 16), goes only over direct paths (never through a relay) and stops at
  64 MB or 3 s per node. **Upgrade all nodes**: older nodes still act on such requests.

### Changed
- `meshvpn net matrix` shows what every node measured itself; `--measure` measures from this node to the
  named nodes. Each node checks round trips and LAN paths to the nodes it has a direct path to every 5
  minutes (before: to every node, also through relays). `--measure --mb 0` (round trips and LAN paths only)
  needs no root.

## [0.30.0] - 2026-11-11

### Changed
- **Networks of 200 nodes at under 50 kB/s per node** (0.29.2: 175 kB/s; 100 nodes 21 kB/s instead of
  64). A node's details (hardware and load, measurements, shared objects, GPU reservations) are
  signed and sent apart from its record, and again only when something others act on changes, else
  every 5 minutes. The record itself goes out every 5 minutes instead of every 30 s; who is online
  comes with the digests the nodes exchange every 10 s. A new link no longer sends all records
  (about 4 MB at 200 nodes, once per link): the new node pulls what it lacks, once. Nodes of 0.29.2
  and older keep getting full records every 30 s and see everything as before.

### Added
- **MATE without root**: `install.sh | sh -s -- --user --desktop mate` (or `sh meshvpn-full-<arch>.run
  --desktop mate`). The packed desktop now holds MATE next to Xfce (about 90 MB more: 750 MB to
  download, 2.3 GB unpacked); `--desktop` picks the one `meshvpn desktop` starts by default.

### Fixed
- Packed desktop: programs started from the browser bar found no session bus (MATE's terminal
  exited at once). The session's bus is now also at `$XDG_RUNTIME_DIR/bus`, where they look.

## [0.29.2] - 2026-11-10

0.29.0 and 0.29.1 were tagged but never released: their tests found bugs in the new gossip, fixed
here. A new node's name reached `/etc/hosts` and its route was set up up to 10 s late, and SSH keys
added just before a node linked up reached it up to 2 s late. In networks of up to 32 nodes, records
now spread as in 0.28 (every link-up re-announces at once).

### Fixed
- A client renewing its time (`meshvpn join <new client invite>`) could stay unreachable for up to
  a minute: the others had dropped its record when its time was up and refused the copy that came
  before the renewal. It now sends its record again right after the renewal.
- Two networks on one machine could lose each other's names in `/etc/hosts`: both meshvpn
  processes rewrote the file at the same moment, each without the other's block. The rewrite now
  takes a lock (`/etc/hosts.meshvpn-lock`).

### Added
- **Xfce without root again**: `install.sh | sh -s -- --user --desktop xfce` puts meshvpn, Xfce and
  Chromium into `~/.local`, for machines and Docker images without root. It is the packed desktop
  of 0.22 (`--full`), which 0.23 had dropped by mistake. `meshvpn doctor` warns when its browser is
  older than 30 days. The README shows how to build it into a Docker image.
- `tests/load/run.py`: a load test with one container per node (and `--old-binary` for a network in
  mid-upgrade); the numbers are in `docs/design-scaling.md`.

### Changed
- **Networks of 100 and more nodes.** Records of other nodes are no longer flooded to every link:
  nodes exchange digests (which record versions they have) and pull what they miss, and forward a
  record only to a few links. A node lists at most 32 of its links in its record, and re-announces
  it at most every 2 s while links come and go. Records that bring nothing new are dropped before
  the signature check. Measured at rest per node: 50 nodes 17 kB/s instead of 738 kB/s, 100 nodes
  66 kB/s instead of 10 MB/s; 200 nodes now work (175 kB/s), where before the test machine ran out
  of memory. Networks with older nodes keep working: those still get every record as before.
- `install.sh --desktop` without root no longer aborts the whole install: Xfce comes as the packed
  desktop, MATE and Cinnamon are skipped with a warning and meshvpn is installed without them.

## [0.28.2] - 2026-11-09

### Changed

- `meshvpn desktop <node>` and `d` in the console no longer open a browser by themselves (under WSL
  that started an X browser). They print the link, clickable in the terminal; `--open` opens a
  browser as before. `--no-browser` is still accepted.

## [0.28.1] - 2026-11-08

The first release that meshvpn update verifies through the release key alone. Machines on 0.27.x
can't check that and refuse it: reinstall there (`curl -fsSL
https://github.com/PlugOvr-ai/meshvpn/releases/latest/download/install.sh | sudo sh`, configuration
kept). 0.28.0 updates as usual; 0.26.0 and older don't check signatures and update as before.

### Added
- `meshvpn dht on|off`: switches DHT rendezvous on or off and restarts meshvpn, on every system. Before,
  the README said to add `dht = true` to the configuration, which already holds `dht = false`: the
  key twice, and meshvpn refused to start ("duplicate key").
- `meshvpn restart`: restarts meshvpn's service the same way on Linux (systemd, or the background
  daemon without it), macOS (launch daemon) and Windows (scheduled task); all of the machine's
  networks, or the one of `--net`.
- **Several networks on macOS**, as on Linux: `sudo meshvpn --net <name> init` (or `join`) puts a
  Mac that is in a network already into a further one. Each further network gets its own
  interface, a route per node of it, its own names (`<node>.<name>.mesh`) and its own launch daemon
  (`ai.plugovr.meshvpn.<name>`, log `/var/log/meshvpn-<name>.log`).

### Changed
- **Nodes find each other again faster after one of them moved** (another Wi-Fi, a mobile network):
  in the first quarter of an hour after a node is gone, the others look it up in the DHT every 30
  seconds instead of every 2 minutes, and a running hole punching attempt switches to addresses
  found meanwhile instead of keeping the old ones for a minute. Before, this took 5 to 6 minutes.
- `meshvpn status` shows what happens meanwhile: `reconnecting to <node> (last seen …, looked up …
  ago, trying …)`, and on a new node `joining: waiting for the inviting node at …`.
- Windows: the DHT entry carries the machine's temporary IPv6 addresses (as on Linux and macOS),
  so a Windows node that moved can be found again over IPv6.

### Fixed
- **`init --force` and `join --force` now really leave the old network.** Before, the running
  meshvpn (service, launch daemon or scheduled task) kept going with the old keys, so the machine
  stayed reachable in the old network, and it kept writing the old network's state over the new
  one (an `init --force` could lose its admin that way). Now the old meshvpn stops before the new
  configuration is written, and the service starts again with the new one.
- `meshvpn leave` no longer hangs when the running meshvpn doesn't answer: after 15 seconds it
  leaves without telling the network, and stops meshvpn as usual.
- macOS: password-less SSH logins work again after an update. meshvpn's own sshd entry from before
  (with `/usr/local/bin/meshvpn`, a link there) was taken for someone else's ("sshd already uses
  AuthorizedKeysCommand ... meshvpn can't add its own"); it is now brought up to date.
- The warning about another interface in 100.64.0.0/10 no longer names this machine's own other
  networks on macOS (whose interfaces macOS names `utunN` itself).

## [0.28.0] - 2026-11-08

### Security
- **Releases are signed automatically, with two levels of keys.** Offline root keys (built into
  meshvpn) certify a release key until a date (`release-key.cert`, in every release); the release
  workflow signs with that key, which only `v*` tags can use, on GitHub's own runners. A release
  key that leaks is replaced without an update of meshvpn: it stops counting at its expiry date,
  and at once where it is listed as revoked. An expired key never signs an update. Releases
  signed by a root key still verify.
- Only maintainers may create, move or delete `v*` tags.

### Added
- `scripts/verify-release.sh`: checks a release by hand, as `meshvpn update` does.
- `scripts/certify-release-key.sh`: certifies a release key with a root key.

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

# Design: meshvpn for 1000 nodes

Status: proposal, 2026-11-09. Steps 0 and 1 are built: 1.1 and 1.3 in 0.29.2 (2026-11-10), 1.2 and 1.4
(2026-11-11) not released yet.

## Where it breaks today

Every number below is from the code as of 0.28.2.

| Mechanism | Today | Cost with N nodes |
|---|---|---|
| Links | every node dials every node that has an endpoint (`dial_candidates`) | N−1 TCP+Noise links per node |
| Pings | `T_PING` on every link every 10 s (`TICK`) | (N−1)/10 per second per node |
| Announce | own record every 30 s (`REANNOUNCE`), also on every address change | N records per 30 s in the network |
| Gossip | a new record is flooded to **all** links except the sender (`handle_gossip`) | each node gets every record up to N−1 times: **N² records per 30 s per node** |
| Record size | `NodeInfo` carries `neighbors` (all direct links) and `perf` (one row of the matrix) | both grow with N: a record is O(N) bytes |
| New link | sends the full table (`full_table`) | N records per new link |
| Addresses | 22-bit hash of the node id (`keys::overlay_ip`) | P(any collision) ≈ N²/2²³: 1 % at 300, **11 % at 1000** |

Together the gossip is O(N³) bytes per announce interval network-wide. With records of ~10 KB
at 1000 nodes (999 neighbor ids alone are ~65 KB of JSON), a node would have to take in hundreds
of MB per 30 s. In practice the limit is already noticeable somewhere between 50 and 100 nodes.

## Measured (step 0, 2026-11-10, v0.28.2)

`tests/load/run.py`: one container per node on one machine, userspace mode, idle network, 120 s
window after the mesh settled. Traffic is per node, in (out is the same).

| Nodes | Traffic per node | CPU per node | Memory per node | All see all | New node seen | Record |
|---|---|---|---|---|---|---|
| 5 | 1.8 kB/s | 0.05 % | 11 MB | 10 s | 9 s | – |
| 20 | 61 kB/s | 0.3 % | 19 MB | 4 s | 2 s | 5.8 kB |
| 50 | 738 kB/s | 2.2 % | 44 MB | 7 s | 2 s | 9.9 kB |
| 100 | 10.1 MB/s | 18 % | 786 MB | 27 s | 16 s | 11 kB |
| 200 | – (the machine ran out of its 125 GB of memory) | | | | | |

Traffic grows like N³ from 50 to 100 nodes (2× nodes, 14× traffic): N² copies of records that
themselves grow with N. Memory grows even faster, probably queued gossip frames on busy links.
The practical limit today is about 50 nodes; 100 work but cost 10 MB/s per idle node.

## Measured after step 1 (partly built, 2026-11-10)

Built so far: digests and fan-out (1.1), a bounded neighbor list (1.3), and four things the
measurements showed were needed:

* records that bring no news (same or older seq) are dropped before the signature check;
* the IP map, routes and hosts file are rebuilt only when a record changes something they use
  (name, keys, neighbors, endpoints, host key), not on every heartbeat;
* a link coming up or going down re-announces the record only when it changes, at most every
  2 s (while 200 nodes connect, every node used to send ~200 full records to ~200 links);
* the record carries its owner's link count, and a node forwards someone else's record only
  with the probability that some node has no link to the owner (in a full mesh: almost never;
  the digests catch the rest within one round).

Same test as step 0:

| Nodes | Traffic per node | CPU per node | Memory per node | All see all | New node seen | Record |
|---|---|---|---|---|---|---|
| 50 | 17 kB/s (step 0: 738) | 0.31 % (2.2) | 30 MB (44) | 4 s | 7 s | 8.6 kB |
| 100 | 66 kB/s (10 100) | 0.76 % (18) | 67 MB (786) | 5 s | 7 s | 17 kB |
| 200 | 175 kB/s (out of memory) | 1.7 % | 227 MB | 24 s | 8 s | 22 kB |

Traffic now grows about like N² (each node gets each record about once, and records still
grow with N): what remains is mostly `perf` (up to 128 rows) and the 30 s heartbeat, i.e.
1.2 and 1.4. The 1000-node goal (< 50 kB/s) still needs those and step 2. 200 is the most this
machine (20 cores, one container per node) can run.

Mixed versions (`--old-binary`, 60 nodes, half of them on 0.28.2): every node sees every other
within 7 s and a new node within 7 s; 600 kB/s per node, about what 0.28.2 alone costs. The
saving comes once the nodes are updated.

## Measured after all of step 1 (2026-11-11)

Built: the details (inventory, perf, measured, objects, leases) apart from the record, signed on
their own, again only when something others act on changes (reservations, objects, a finished
measurement, GPUs, LAN paths) or every 5 minutes (1.2); the record every 5 minutes instead of
30 s, with liveness in the digests (`T_DIGEST2`: how long ago the sender last heard from each
node), as long as no older node is online (1.4). And one thing the measurements showed: a new
link no longer sends the whole table (4 MB at 200 nodes, received once per link, so a new node
got ~800 MB), but the node's own record, the last 5 s of records and a digest; the rest is
pulled once.

| Nodes | Traffic per node | CPU | Memory | All see all | New node seen |
|---|---|---|---|---|---|
| 50 | 9 kB/s (0.29.2: 17) | 0.37 % | 17 MB | 3 s | 3 s |
| 100 | 21 kB/s (64) | 0.68 % | 28 MB | 3 s | 3 s |
| 200 | 46 kB/s (175) | 1.5 % | 51 MB | 11 s (24) | 3.5 s (8) |

(50 nodes measured with 1.2 only.) What's left is mostly not gossip: every link sends a TCP ping
and a UDP keepalive every 10 s in both directions, about 150–200 B/s per peer, so 15–20 kB/s at
100 nodes and ~40 kB/s at 200. That grows with the number of links, i.e. with N in a full mesh:
about 200 kB/s at 1000 nodes even with no gossip at all. Step 2 (about 8 permanent links) is
what removes it.

Mixed versions (60 nodes, half on 0.29.2): all see all within 11 s, 20 kB/s per node (with an
older node online the record goes out every 30 s, as those decide who is online by fresh
records). Older nodes get full records from the owner directly and see the new nodes' details;
records without details never go to them.

## Estimate at 1000 nodes (after steps 2-4, 0.31.1; computed, not measured)

The last load test with links on demand (200 nodes, before 0.30.1) showed 313 kB/s per node, but
from two things fixed since: the automatic measurement pinged every node (now only direct ones,
0.30.1), and every link change was announced at once (now in batches). It was stopped before a
rerun because it overloaded the test machine, so these numbers come from the protocol, per node at
rest:

| What | Rule | At 1000 nodes |
|---|---|---|
| Keepalives | TCP ping + UDP keepalive per link every 10 s, ~150–200 B/s per link; ~8 links | ~1.5 kB/s |
| Digests | one to a random neighbor every 10 s, 42 B per node (`T_DIGEST2`) | ~4 kB/s out, ~4 kB/s in |
| Records | each node's core record every 5 min (`HEARTBEAT`), ~1–1.5 KB with 8 neighbor ids, pulled once by digest | ~5 kB/s |
| Details | every 5 min or on change, pulled like records | ~5 kB/s |
| **Total** | | **~20 kB/s** (goal: < 50) |

Address collisions: about 1 network in 9 at 1000 nodes has a pair; both move (step 3). The saved
state is a few MB, written every 5 minutes when it changed (step 4).

**Next limit, at about 1500 nodes:** a digest is one link message (at most 64 KiB, `link::MAX_MSG`),
42 B per node. Beyond ~1500 nodes it has to go in parts, and a node may then send only the records
in the part's range (today it sends every record the digest doesn't name).

## Goals

* 1000 nodes per network, each node using < 50 kB/s and < 1 % CPU for the mesh at rest.
* A node that wants to talk to another one has a direct path within ~2 s (as now when a link
  exists), and data flows through a relay meanwhile.
* No server, no special nodes: every node runs the same rules (as now).
* Mixed versions during the upgrade: old and new nodes in one network keep working.

## Plan, in steps that each ship on their own

### Step 0: measure (first, ~2 days)

A load test that starts 20, 50, 100, 200 nodes in userspace mode (one process per node, many per
container) and records bytes/s, frames/s, CPU and memory per node, and the time until a new node
is reachable from all others. Without this, the steps below are guesses about their gain. It
also gives the real current limit to put in the README instead of "a few dozen".

### Step 1: cheaper gossip (big win, small change)

1. **Digest instead of flood.** A node sends its own new record to all its links (as now), but
   forwards other nodes' records only to a few links (fan-out ~4, random). Every 30 s each link
   exchanges a digest — `(id, seq)` pairs, 16 bytes per node, 16 KB at 1000 — and each side pulls
   the records the other has newer. That is anti-entropy: every record still reaches everybody
   within a few rounds, but each node gets each record about once or twice instead of N−1 times.
2. **Small core record, details apart.** Split `NodeInfo` into
   * *core* (id, keys, name, endpoints, udp, udp6, seq, tags, ssh host key, flags): what routing
     and names need, a few hundred bytes;
   * *details* (inventory, perf, objects, leases, ssh user keys): versioned and signed apart,
     announced only on change, at most every 5 minutes, and fetched on demand by the commands that
     need them (`nodes`, `gpu list`, `net matrix`, `objects`).
3. **Bounded neighbor list.** `neighbors` keeps at most 16 entries (the links that are good relays:
   public, low latency). Routing needs a connected graph, not the full one.
4. **Slower heartbeat.** The record is re-announced every 5 minutes instead of 30 s. "Online" is
   decided by the digest: a node whose seq advanced in the last 2 digest rounds is online.

Expected: per-node gossip drops from O(N²) to O(N) records per interval, records from O(N) to
O(1) size. That alone should carry a few hundred nodes, still with a full mesh of links.

### Step 2: links on demand (the step that makes 1000 work)

* **Structural links:** each node keeps about 8 permanent links: some to its successors on a ring
  ordered by node id (keeps the graph connected), some random, preferring reachable public nodes.
  These carry gossip and relayed traffic.
* **Traffic links:** when a packet for node X comes from the TUN and there is no link to X, the
  node sends it through the relays at once and opens a direct link (or UDP path) to X in the
  background. Idle traffic links close after 5 minutes. LAN paths, hole punching and the DHT
  rendezvous stay as they are, but run only for pairs that talk.
* Pings run only on open links. Status shows "idle" for nodes without a link that are online by
  gossip — not "offline".

Risk: the first packets to a new peer take the relay path, so latency-sensitive things (NCCL
setup) must open links ahead: `launch` and `net check` already know the group of nodes and
can ask for the links before starting.

### Step 3: addresses without collisions

*Done in 0.31.1, differently from the plan below:* both claimants move (to their next candidate,
`blake3(derive "meshvpn ipv4 candidate v1", id ‖ k)`, k < 16, named by `ip_index` in the core
record), and the contested address is burned: nobody's from then on, also when only one claimant
is left. With "lower id keeps it", a member could grind an id with a lower value and someone's
address and take it over. A node takes its new address by restarting in place (`restart`, as for
updates): the TUN device, the userspace stack and the SSH server have it from the start. No
admin-signed addresses in managed networks: the rule needs no coordinator, and the admin can ban
a member who keeps forcing others to move. Older nodes compute addresses from the id: to them a
moved node stays contested (unreachable, as before), never misrouted.

The mesh IPv4 stays in 100.64.0.0/10, but becomes a claim instead of a pure hash:

* A node starts with the hash address (as now, so nothing changes for existing nodes).
* If it sees another record with the same address and a lower id, it takes the next candidate
  `hash(id ‖ counter)` and announces the address in its core record.
* In managed networks the address is part of the admission the admin signs, so two nodes can't
  race for it; the admin's node picks one that is free.
* Everything that today recomputes the address from the id (`overlay_ip(&id)` — hosts file,
  known_hosts, routes, `range_conflicts`) reads it from the record instead.

IPv6 mesh addresses have enough bits and stay hashes.

### Step 4: the rest of what grows with N

*Done in 0.31.1:* `/etc/hosts` and `known_hosts` were already written only on change. `status` lists
the nodes with a direct path and a summary above 32 nodes (`--all` for every node); `nodes` already
has selectors and `--online`/`--free-gpus`, and `net matrix` measures only on request (0.30.1). The
saved state is written only when it changed, compact, every 5 minutes above 32 nodes.

* `/etc/hosts` and `known_hosts` are rewritten only when a name, address or host key changed
  (check whether that's already the case before touching it).
* `meshvpn status` shows a summary line per state and the nodes this node talks to; `--all` lists
  all of them. `nodes` and `net matrix` get filters and paging.
* `net matrix` measures only on request and only for the selected nodes (it is O(N²) pairs).
* The saved state (`SavedState`) is written only on change, not every 60 s.

## Compatibility

* Step 1: new nodes still accept full records and old-style floods. They send core+details only to
  nodes that announce support (version check, as for UDP fragmentation with `FRAG_VERSION`),
  full records to the others. A network can upgrade node by node.
* Step 2: an old node keeps dialing everybody; new nodes accept those links. The benefit comes
  when most nodes are new.
* Step 3: unchanged for every node without a collision. A node that moves its address shows that in
  status and the log; old nodes that compute it from the id would reach the wrong node, so the
  move is only done when all nodes in the network announce support.

## Rough effort

| Step | Work | Risk |
|---|---|---|
| 0 load test | 2–3 days | low |
| 1 gossip | 1–2 weeks | medium: the core of the protocol; mixed versions |
| 2 on-demand links | 2–3 weeks | high: changes when and how paths come up |
| 3 addresses | 1 week | medium: everything that assumes address = hash(id) |
| 4 the rest | 3–5 days | low |

Recommendation: do 0 and 1 first. They help every network size, carry a few hundred nodes, and
show with real numbers whether step 2 is needed for the customers there are.

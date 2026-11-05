//! `meshvpn net why <node>`: why is there no direct connection?
//!
//! A hole only opens while both sides send, so both start probing at once and count, for a few
//! seconds, what they sent and what arrived. The two sets of counts tell most causes apart; the
//! NAT kinds and addresses explain the rest. The request and the answers travel over the mesh,
//! which works whatever the direct path does. An answer comes from another member of the network
//! and is only ever shown to whoever asked.

use super::*;

/// How long the test takes. The far side answers a little earlier, so its answer is there in time.
const WINDOW: Duration = Duration::from_secs(10);
const PEER_WINDOW: Duration = Duration::from_secs(8);
const LATE_ANSWER: Duration = Duration::from_secs(3);
/// Tests other nodes may have running here at once.
const MAX_RUNNING: u32 = 4;

#[derive(Default, Clone, Copy)]
pub struct WhyCount {
    pub sent: u32,
    pub heard: u32,
    pub answers: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WhyReport {
    pub node: String,
    /// What carries traffic to the node now (as in `meshvpn status`).
    pub path: String,
    /// Connected directly, over UDP or TCP.
    pub direct: bool,
    /// Stable name of the cause, for scripts.
    pub verdict: String,
    pub why: String,
    #[serde(rename = "try")]
    pub to_try: Vec<String>,
    pub here: WhySide,
    /// None: the node didn't answer (older meshvpn, or the mesh lost the message).
    pub there: Option<WhySide>,
}

impl WhyReport {
    pub fn render(&self) -> String {
        let mut o = format!("{} -> {}: {}\n\n", self.here.name, self.node, self.path);
        let there = self.there.clone().unwrap_or_default();
        let answered = self.there.is_some();
        let cell = |v: String| if answered { v } else { "?".to_string() };
        o.push_str(&format!("  {:<18} {:<14} {}\n", "", self.here.name, self.node));
        let mut row = |label: &str, a: String, b: String| {
            o.push_str(&format!("  {label:<18} {a:<14} {}\n", cell(b)));
        };
        let on = |s: &WhySide| if s.udp_on { "on" } else { "off" }.to_string();
        row("UDP", on(&self.here), on(&there));
        row("NAT", self.here.nat.clone(), there.nat.clone());
        let v6 = |s: &WhySide| if s.ipv6.is_empty() { "no" } else { "yes" }.to_string();
        row("IPv6", v6(&self.here), v6(&there));
        row("probes sent", self.here.sent.to_string(), there.sent.to_string());
        row("probes received", self.here.heard.to_string(), there.heard.to_string());
        row(
            "answers received",
            self.here.answers.to_string(),
            there.answers.to_string(),
        );
        o.push_str(&format!("\nWhy: {}\n", self.why));
        if !self.to_try.is_empty() {
            o.push_str("\nWhat to do:\n");
            for t in &self.to_try {
                o.push_str(&format!("  * {t}\n"));
            }
        }
        if !self.here.candidates.is_empty() {
            o.push_str(&format!(
                "\nAddresses tried for {}: {}\n",
                self.node,
                self.here.candidates.join(", ")
            ));
        }
        o
    }
}

/// The cause, from what both sides saw: (verdict, why, what to do).
pub(crate) fn diagnose(
    path: &str,
    here: &WhySide,
    there: Option<&WhySide>,
    node: &str,
    same_lan: bool,
) -> (&'static str, String, Vec<String>) {
    let me = &here.name;
    if path.starts_with("direct UDP") {
        return (
            "direct-udp",
            format!("nothing is wrong: {me} and {node} are connected directly over UDP."),
            vec![],
        );
    }
    let tcp = path.starts_with("direct ");
    let over = if tcp {
        "Traffic uses a direct TCP connection, which works but is slower on lossy links.".to_string()
    } else {
        "Traffic is relayed by another node for now, which works but is slower.".to_string()
    };
    if !here.udp_on {
        return (
            "udp-off",
            format!("direct UDP paths are off on {me}. {over}"),
            vec![format!(
                "On {me}, check for `udp = false`, an SSH tunnel or a SOCKS proxy (`meshvpn doctor`)."
            )],
        );
    }
    let Some(there) = there else {
        let seen = if here.heard > 0 {
            format!(
                " Its probes do arrive here ({}), so UDP gets through in that direction.",
                here.heard
            )
        } else {
            String::new()
        };
        return (
            "no-answer",
            format!("{node} didn't report what it saw, so only this side is known.{seen} {over}"),
            vec![
                format!("Update {node}: it needs this version of meshvpn to take part."),
                format!("Or run `meshvpn doctor` on {node}."),
            ],
        );
    };
    if !there.udp_on {
        return (
            "udp-off",
            format!("direct UDP paths are off on {node}. {over}"),
            vec![format!(
                "On {node}, check for `udp = false`, an SSH tunnel or a SOCKS proxy (`meshvpn doctor`)."
            )],
        );
    }
    if here.candidates.is_empty() {
        return (
            "no-address",
            format!("{node} advertises no address for UDP, so there is nothing to try. {over}"),
            vec![format!("Run `meshvpn doctor` on {node}.")],
        );
    }
    let watch = |who: &str, other: &str| {
        format!(
            "On {who}, watch for it while repeating this: sudo tcpdump -ni any udp and host <public address of {other}>"
        )
    };
    if here.answers > 0 || there.answers > 0 {
        return (
            "unstable",
            format!(
                "probes were answered during the test, but no path stayed up. The way between them is unreliable. {over}"
            ),
            vec![
                "Run this again in a minute; a path that keeps dropping points to a NAT forgetting its mappings."
                    .into(),
            ],
        );
    }
    let (heard_by, sender) = match (here.heard > 0, there.heard > 0) {
        (true, false) => (Some(me.as_str()), node),
        (false, true) => (Some(node), me.as_str()),
        _ => (None, ""),
    };
    if let Some(receiver) = heard_by {
        return (
            "one-way",
            format!(
                "UDP gets through in one direction only: {sender}'s probes reach {receiver}, but nothing comes back. \
                 A firewall on the way to {sender} is dropping it, or {receiver} may not send to that address. {over}"
            ),
            vec![
                format!("Allow incoming UDP on {sender}'s side, or forward its UDP port on its router."),
                watch(sender, receiver),
            ],
        );
    }
    if here.heard > 0 && there.heard > 0 {
        return (
            "answers-lost",
            format!("both sides receive each other's probes, but the answers get lost. {over}"),
            vec![watch(me, node), watch(node, me)],
        );
    }
    // Nothing arrived anywhere.
    let hard = |s: &WhySide| s.nat == "changes-port" && s.ipv6.is_empty();
    let forward = |on: &str| {
        format!("Forward its UDP port (7870 by default) on the router in front of {on}, or give both machines IPv6.")
    };
    if hard(here) && hard(there) {
        return (
            "hard-nat",
            format!(
                "both {me} and {node} are behind NATs that use a new port per destination, so neither can find the other. {over}"
            ),
            vec![forward(me), forward(node)],
        );
    }
    if hard(here) || hard(there) {
        let (bad, other) = if hard(here) {
            (me.as_str(), node)
        } else {
            (node, me.as_str())
        };
        return (
            "hard-nat",
            format!("{bad} is behind a NAT that uses a new port per destination, so {other} can't find it. {over}"),
            vec![forward(other)],
        );
    }
    if same_lan {
        return (
            "lan-blocked",
            format!(
                "{me} and {node} share a network, but no probe arrived either way. A firewall on one of them, or client isolation on the network, is dropping them. {over}"
            ),
            vec![
                "Check the firewall on both for meshvpn's UDP port (7870 by default).".to_string(),
                watch(me, node),
            ],
        );
    }
    for (s, name) in [(here, me.as_str()), (there, node)] {
        if s.nat == "public" {
            return (
                "public-blocked",
                format!(
                    "{name} has a public address, but no probe arrived either way, so UDP is dropped on the way, most likely by its firewall. {over}"
                ),
                vec![format!(
                    "Allow meshvpn's UDP port (7870 by default) in {name}'s firewall or cloud security group, as for TCP."
                )],
            );
        }
    }
    for (s, name) in [(here, me.as_str()), (there, node)] {
        if s.nat == "unknown" {
            return (
                "udp-blocked",
                format!(
                    "{name} has never had a direct UDP path to a node outside its own network, so its network probably blocks outgoing UDP (common on company networks). {over}"
                ),
                vec![
                    format!("Ask whoever runs {name}'s network to allow outgoing UDP, or accept the slower path."),
                    watch(name, "the other node"),
                ],
            );
        }
    }
    (
        "firewall",
        format!(
            "both sides sent probes and neither arrived, although their NATs should allow it. A firewall between them is the likeliest cause. {over}"
        ),
        vec![watch(me, node), watch(node, me)],
    )
}

impl Node {
    fn why_side(&self, st: &State, nonce: u64, peer: &NodeId) -> WhySide {
        let (nat, ipv6) = self.nat_report(st);
        let count = st.why_counts.get(peer).copied().unwrap_or_default();
        WhySide {
            nonce,
            name: st.my_name.clone(),
            udp_on: self.udp.is_some(),
            nat: nat.as_ref().map_or("off", |n| n.code()).to_string(),
            nat_text: nat.as_ref().map(|n| n.describe()).unwrap_or_default(),
            ipv6,
            candidates: st
                .records
                .get(peer)
                .map(|r| Self::peer_candidates(&r.info).iter().map(|a| a.to_string()).collect())
                .unwrap_or_default(),
            sent: count.sent,
            heard: count.heard,
            answers: count.answers,
        }
    }

    /// Counts from zero and probes right away, not at the slow pace of a path that keeps failing.
    fn why_start(st: &mut State, peer: NodeId) {
        st.why_counts.insert(peer, WhyCount::default());
        st.udp_probing.remove(&peer);
    }

    fn why_same_lan(st: &State, peer: &NodeId) -> bool {
        let Some(rec) = st.records.get(peer) else { return false };
        let lans = crate::net::local_lans();
        rec.info.lan.iter().any(|l| {
            let ip = l.split('/').next().and_then(|ip| ip.parse::<Ipv4Addr>().ok());
            ip.is_some_and(|ip| lans.iter().any(|(_, mine, p)| crate::net::same_subnet(*mine, *p, ip)))
        })
    }

    fn peer_path(&self, st: &State, id: &NodeId) -> String {
        if let Some(p) = st.udp_paths.get(id).filter(|p| p.usable()) {
            format!("direct UDP {}", p.addr)
        } else if let Some(l) = st.links.get(id) {
            format!("direct {}", l.addr)
        } else if let Some(hop) = st.routes.get(id) {
            let via = st.records.get(hop).map(|r| r.info.name.clone()).unwrap_or(hop.short());
            format!("relay via {via}")
        } else {
            "-".into()
        }
    }

    /// The test, from the side that asks.
    pub async fn why(self: &Arc<Self>, who: &str) -> Result<WhyReport> {
        let nonce = rand::rngs::OsRng.next_u64();
        let (peer, name) = {
            let mut st = self.state.lock().unwrap();
            let (peer, name) = self.resolve_node(&st, who)?;
            if peer == self.ident.id {
                bail!("{name} is this machine");
            }
            if !self.is_online(&st, &peer) {
                bail!("{name} is offline, so there is nothing to test (see meshvpn status)");
            }
            // Already direct over UDP: nothing to find out, and a test would only disturb it.
            if !st.udp_paths.get(&peer).is_some_and(|p| p.usable()) {
                Self::why_start(&mut st, peer);
                st.why_seen.insert(nonce);
                let req = WhyReq {
                    nonce,
                    from: self.ident.id,
                    to: peer,
                };
                self.broadcast(&st, &frame(T_WHY, &serde_json::to_vec(&req).unwrap()), None);
            }
            (peer, name)
        };
        let direct_udp = |n: &Self| {
            let st = n.state.lock().unwrap();
            st.udp_paths.get(&peer).is_some_and(|p| p.usable())
        };
        let started = Instant::now();
        while started.elapsed() < WINDOW && !direct_udp(self) {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        while started.elapsed() < WINDOW + LATE_ANSWER
            && !direct_udp(self)
            && !self.state.lock().unwrap().why_replies.contains_key(&nonce)
        {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let mut st = self.state.lock().unwrap();
        let there = st.why_replies.remove(&nonce);
        let here = self.why_side(&st, nonce, &peer);
        st.why_counts.remove(&peer);
        let path = self.peer_path(&st, &peer);
        let same_lan = Self::why_same_lan(&st, &peer);
        let (verdict, why, to_try) = diagnose(&path, &here, there.as_ref(), &name, same_lan);
        Ok(WhyReport {
            node: name,
            direct: path.starts_with("direct"),
            path,
            verdict: verdict.to_string(),
            why,
            to_try,
            here,
            there,
        })
    }

    /// Passes the request on; if it is for this node, tests from this end and answers.
    pub(super) fn handle_why(self: &Arc<Self>, link: NodeId, payload: &[u8]) {
        let Ok(req) = serde_json::from_slice::<WhyReq>(payload) else {
            return;
        };
        let mut st = self.state.lock().unwrap();
        if !st.why_seen.insert(req.nonce) {
            return;
        }
        if st.why_seen.len() > 1000 {
            st.why_seen.clear();
        }
        self.broadcast(&st, &frame(T_WHY, payload), Some(link));
        if req.to != self.ident.id || st.why_running >= MAX_RUNNING || !st.records.contains_key(&req.from) {
            return;
        }
        st.why_running += 1;
        Self::why_start(&mut st, req.from);
        drop(st);
        let node = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(PEER_WINDOW).await;
            let mut st = node.state.lock().unwrap();
            st.why_running -= 1;
            let side = node.why_side(&st, req.nonce, &req.from);
            st.why_counts.remove(&req.from);
            st.why_seen.insert(req.nonce ^ u64::MAX);
            let f = frame(T_WHY_REPLY, &serde_json::to_vec(&(req.from, side)).unwrap());
            node.broadcast(&st, &f, None);
        });
    }

    /// Passes an answer on towards whoever asked, once each.
    pub(super) fn handle_why_reply(self: &Arc<Self>, link: NodeId, payload: &[u8]) {
        let Ok((asker, side)) = serde_json::from_slice::<(NodeId, WhySide)>(payload) else {
            return;
        };
        let mut st = self.state.lock().unwrap();
        if asker == self.ident.id {
            // Only a test this node runs, and not one of its own requests' leftovers.
            if st.why_seen.contains(&side.nonce) && st.why_replies.len() < 16 {
                st.why_replies.insert(side.nonce, side);
            }
            return;
        }
        if !st.why_seen.insert(side.nonce ^ u64::MAX) {
            return;
        }
        self.broadcast(&st, &frame(T_WHY_REPLY, payload), Some(link));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn side(name: &str, nat: &str, sent: u32, heard: u32, answers: u32) -> WhySide {
        WhySide {
            name: name.into(),
            udp_on: true,
            nat: nat.into(),
            candidates: vec!["1.2.3.4:7870".into()],
            sent,
            heard,
            answers,
            ..Default::default()
        }
    }

    fn verdict(path: &str, a: WhySide, b: Option<WhySide>, lan: bool) -> &'static str {
        diagnose(path, &a, b.as_ref(), "b", lan).0
    }

    const RELAY: &str = "relay via hub";

    #[test]
    fn causes_are_told_apart() {
        let a = |nat, heard, answers| side("a", nat, 6, heard, answers);
        let b = |nat, heard, answers| Some(side("b", nat, 6, heard, answers));
        assert_eq!(
            verdict("direct UDP 1.2.3.4:7870", a("public", 3, 3), b("public", 3, 3), false),
            "direct-udp"
        );
        assert_eq!(verdict(RELAY, a("keeps-port", 0, 0), None, false), "no-answer");
        assert_eq!(
            verdict(RELAY, a("keeps-port", 3, 0), b("keeps-port", 0, 0), false),
            "one-way"
        );
        assert_eq!(
            verdict(RELAY, a("keeps-port", 0, 0), b("keeps-port", 3, 0), false),
            "one-way"
        );
        assert_eq!(
            verdict(RELAY, a("keeps-port", 3, 0), b("keeps-port", 3, 0), false),
            "answers-lost"
        );
        assert_eq!(
            verdict(RELAY, a("keeps-port", 3, 3), b("keeps-port", 3, 0), false),
            "unstable"
        );
        assert_eq!(
            verdict(RELAY, a("changes-port", 0, 0), b("changes-port", 0, 0), false),
            "hard-nat"
        );
        assert_eq!(
            verdict(RELAY, a("keeps-port", 0, 0), b("changes-port", 0, 0), false),
            "hard-nat"
        );
        assert_eq!(
            verdict(RELAY, a("keeps-port", 0, 0), b("keeps-port", 0, 0), true),
            "lan-blocked"
        );
        assert_eq!(
            verdict(RELAY, a("keeps-port", 0, 0), b("public", 0, 0), false),
            "public-blocked"
        );
        assert_eq!(
            verdict(RELAY, a("unknown", 0, 0), b("keeps-port", 0, 0), false),
            "udp-blocked"
        );
        assert_eq!(
            verdict(RELAY, a("keeps-port", 0, 0), b("keeps-port", 0, 0), false),
            "firewall"
        );
    }

    #[test]
    fn udp_off_and_nothing_to_try_come_first() {
        let mut off = side("a", "off", 0, 0, 0);
        off.udp_on = false;
        assert_eq!(
            verdict(RELAY, off.clone(), Some(side("b", "public", 3, 0, 0)), false),
            "udp-off"
        );
        let mut there = side("b", "off", 0, 0, 0);
        there.udp_on = false;
        assert_eq!(
            verdict(RELAY, side("a", "public", 3, 0, 0), Some(there), false),
            "udp-off"
        );
        let mut none = side("a", "public", 0, 0, 0);
        none.candidates.clear();
        assert_eq!(
            verdict(RELAY, none, Some(side("b", "public", 0, 0, 0)), false),
            "no-address"
        );
    }

    #[test]
    fn a_hard_nat_with_ipv6_is_not_the_cause() {
        let mut a = side("a", "changes-port", 6, 0, 0);
        a.ipv6 = vec!["[2001:db8::1]:7870".into()];
        assert_eq!(
            verdict(RELAY, a, Some(side("b", "keeps-port", 6, 0, 0)), false),
            "firewall"
        );
    }

    #[test]
    fn the_report_reads_well_with_or_without_an_answer() {
        let here = side("laptop", "keeps-port", 6, 0, 0);
        let there = side("server", "public", 6, 0, 0);
        let (verdict, why, to_try) = diagnose(RELAY, &here, Some(&there), "server", false);
        let mut r = WhyReport {
            node: "server".into(),
            path: RELAY.into(),
            direct: false,
            verdict: verdict.into(),
            why,
            to_try,
            here,
            there: Some(there),
        };
        let text = r.render();
        println!("{text}");
        assert!(text.contains("laptop -> server: relay via hub"), "{text}");
        assert!(text.contains("server's firewall"), "{text}");
        r.there = None;
        let text = r.render();
        println!("{text}");
        assert!(text.contains("probes sent        6              ?"), "{text}");
        assert!(
            text.lines()
                .nth(2)
                .is_some_and(|l| l.contains("laptop") && l.contains("server")),
            "{text}"
        );
    }

    #[test]
    fn direct_tcp_says_so() {
        let (v, why, _) = diagnose(
            "direct 1.2.3.4:7870",
            &side("a", "public", 6, 0, 0),
            Some(&side("b", "public", 6, 0, 0)),
            "b",
            false,
        );
        assert_eq!(v, "public-blocked");
        assert!(why.contains("direct TCP"), "{why}");
    }
}

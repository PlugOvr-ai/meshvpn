//! `meshvpn net check`: will distributed training work on these nodes? NCCL fails by hanging, late
//! and without a word, when nodes disagree about the network or a firewall drops its connections.
//! So: ask every node what it would use, then open real connections between every pair, on ports
//! like those NCCL opens, and send data. It says which pair fails, before the training starts.

use anyhow::{Context, Result, bail};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::agent::{self, NodeView, Remote, sh_quote};

/// With more nodes than this, not every pair: each with its neighbours and with the master.
const ALL_PAIRS_UP_TO: usize = 8;

/// Takes one connection, reads everything, says how much (ends after `secs` without one).
pub fn listen(port: u16, secs: u64) -> Result<()> {
    let l = TcpListener::bind(("0.0.0.0", port)).with_context(|| format!("port {port}"))?;
    l.set_nonblocking(true)?;
    let end = Instant::now() + Duration::from_secs(secs);
    let mut conn = loop {
        match l.accept() {
            Ok((c, _)) => break c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > end {
                    bail!("nobody connected to port {port}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e.into()),
        }
    };
    conn.set_nonblocking(false)?;
    conn.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        match conn.read(&mut buf)? {
            0 => break,
            n => total += n as u64,
        }
    }
    conn.write_all(format!("{total}\n").as_bytes())?;
    println!("{total}");
    Ok(())
}

/// Sends `mb` MB and prints Mbit/s, once the other side has them all.
pub fn send(addr: &str, port: u16, mb: u64) -> Result<()> {
    let to: SocketAddr = format!("{addr}:{port}").parse()?;
    let mut c =
        TcpStream::connect_timeout(&to, Duration::from_secs(5)).with_context(|| format!("no connection to {to}"))?;
    c.set_write_timeout(Some(Duration::from_secs(30)))?;
    c.set_read_timeout(Some(Duration::from_secs(30)))?;
    let buf = vec![0x5au8; 1 << 20];
    let started = Instant::now();
    for _ in 0..mb {
        c.write_all(&buf).context("sending stalled")?;
    }
    c.shutdown(std::net::Shutdown::Write)?;
    let mut answer = String::new();
    c.read_to_string(&mut answer).context("no answer")?;
    if answer.trim().parse::<u64>().ok() != Some(mb << 20) {
        bail!("the other side got {} of {} bytes", answer.trim(), mb << 20);
    }
    let secs = started.elapsed().as_secs_f64().max(0.000_1);
    println!("{:.0}", (mb * 8) as f64 * 1.048_576 / secs);
    Ok(())
}

/// Which ordered pairs to test.
fn pairs(group: &[NodeView], master: &NodeView) -> Vec<(usize, usize)> {
    let n = group.len();
    let mut out = vec![];
    if n <= ALL_PAIRS_UP_TO {
        for a in 0..n {
            for b in 0..n {
                if a != b {
                    out.push((a, b));
                }
            }
        }
        return out;
    }
    let m = group.iter().position(|g| g.id == master.id).unwrap_or(0);
    for a in 0..n {
        for b in [(a + 1) % n, (a + n - 1) % n, m] {
            if a != b && !out.contains(&(a, b)) {
                out.push((a, b));
            }
        }
    }
    for a in 0..n {
        if a != m && !out.contains(&(m, a)) {
            out.push((m, a));
        }
    }
    out
}

/// The test of one pair, from `a` to `b` on `addr:port`: Mbit/s, or why not.
fn probe(
    a: &NodeView,
    b: &NodeView,
    addr: &str,
    port: u16,
    mb: u64,
    remote: &Remote,
) -> std::result::Result<f64, String> {
    let listen_cmd = format!("meshvpn net probe-listen {port} 40");
    let send_cmd = format!("sleep 1; meshvpn net probe-send {addr} {port} {mb}");
    let (from_b, from_a) = std::thread::scope(|s| {
        let l = s.spawn(|| agent::exec(std::slice::from_ref(b), remote, &[listen_cmd]));
        let c = agent::exec(std::slice::from_ref(a), remote, &[send_cmd]);
        (l.join().unwrap(), c)
    });
    let (l, c) = (&from_b[0], &from_a[0]);
    if !c.ok {
        let why = c.stderr.trim();
        return Err(if why.is_empty() {
            "didn't finish in time".into()
        } else {
            why.lines().last().unwrap_or(why).to_string()
        });
    }
    if !l.ok && !l.stderr.is_empty() {
        return Err(l.stderr.trim().lines().last().unwrap_or("").to_string());
    }
    c.stdout
        .trim()
        .parse()
        .map_err(|_| format!("said {:?}", c.stdout.trim()))
}

/// The check. true: fine.
pub fn check(
    group: &[NodeView],
    master: &NodeView,
    port: u16,
    mb: u64,
    remote: &Remote,
    json_out: bool,
) -> Result<bool> {
    let mut problems: Vec<String> = vec![];
    if group.len() < 2 {
        bail!("give at least two nodes");
    }
    // What every node would use: each computes that itself, from what it knows.
    let names: Vec<String> = group.iter().map(|n| sh_quote(&n.name)).collect();
    let env_cmd = format!(
        "meshvpn net env --json --master {} --port {port} {}",
        sh_quote(&master.name),
        names.join(" ")
    );
    let mut env: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for r in agent::exec(group, remote, &[env_cmd]) {
        if r.ok {
            env.insert(r.node.clone(), serde_json::from_str(&r.stdout).unwrap_or_default());
        } else {
            let why = if r.stderr.trim().is_empty() {
                r.stdout.trim()
            } else {
                r.stderr.trim()
            };
            problems.push(format!("{}: {why}", r.node));
        }
    }
    let field = |k: &str| -> BTreeMap<String, Vec<String>> {
        let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (node, e) in &env {
            let v = e[k].as_str().unwrap_or("?").to_string();
            seen.entry(v).or_default().push(node.clone());
        }
        seen
    };
    for k in ["MASTER_ADDR", "MESHVPN_PATH"] {
        let seen = field(k);
        if seen.len() > 1 {
            problems.push(format!(
                "the nodes disagree about {k} ({}): NCCL would hang - wait a minute for their \
                 measurements to settle (meshvpn net matrix), or use --master",
                seen.iter()
                    .map(|(v, n)| format!("{v} on {}", n.join(", ")))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    let path = field("MESHVPN_PATH").into_keys().next().unwrap_or_else(|| "?".into());
    let lan = path == "lan";
    // Real connections, on a port like those NCCL opens; to the master also on its port.
    let mut results: Vec<serde_json::Value> = vec![];
    let mut slowest: Option<(f64, String)> = None;
    if problems.is_empty() {
        let mut high = 40000 + (std::process::id() % 15000) as u16;
        let mut tests: Vec<(usize, usize, u16, u64)> = vec![];
        for (a, b) in pairs(group, master) {
            high = if high >= 59990 { 40000 } else { high + 7 };
            tests.push((a, b, high, mb));
        }
        let m = group.iter().position(|g| g.id == master.id).unwrap_or(0);
        for a in (0..group.len()).filter(|a| *a != m) {
            tests.push((a, m, port, 1));
        }
        for (a, b, p, size) in tests {
            let (na, nb) = (&group[a], &group[b]);
            let addr = if lan {
                na.perf
                    .iter()
                    .find(|x| x.peer.hex() == nb.id)
                    .and_then(|x| x.lan_ip.clone())
                    .unwrap_or_else(|| nb.ip.to_string())
            } else {
                nb.ip.to_string()
            };
            let what = format!("{} -> {} ({addr}:{p})", na.name, nb.name);
            if !json_out {
                eprintln!("  {what}...");
            }
            match probe(na, nb, &addr, p, size, remote) {
                Ok(mbps) => {
                    results.push(json!({ "from": na.name, "to": nb.name, "addr": addr, "port": p, "mbps": mbps }));
                    if size == mb && slowest.as_ref().is_none_or(|s| mbps < s.0) {
                        slowest = Some((mbps, format!("{} -> {}", na.name, nb.name)));
                    }
                }
                Err(e) => {
                    results.push(json!({ "from": na.name, "to": nb.name, "addr": addr, "port": p, "error": e }));
                    if p == port && e.contains("in use") {
                        continue; // something runs on the master's port now: not this check's matter
                    }
                    problems.push(format!(
                        "{what}: {e} - a firewall on {}? NCCL opens ports above 32768 on every node",
                        nb.name
                    ));
                }
            }
        }
    }
    let ok = problems.is_empty();
    if json_out {
        println!(
            "{}",
            json!({ "ok": ok, "path": path, "env": env, "pairs": results, "problems": problems,
                    "slowest_mbps": slowest.as_ref().map(|s| s.0) })
        );
        return Ok(ok);
    }
    println!(
        "path:    {}",
        if lan {
            "LAN, every pair shares one (not encrypted)"
        } else {
            "mesh (encrypted in software)"
        }
    );
    for (iface, nodes) in field("NCCL_SOCKET_IFNAME") {
        println!("NCCL:    NCCL_SOCKET_IFNAME={iface} on {}", nodes.join(", "));
    }
    if let Some((mbps, who)) = &slowest {
        println!("slowest: {who}, {mbps:.0} Mbit/s");
    }
    if ok {
        println!("ok:      NCCL's TCP connections will work between these nodes");
        if !lan {
            println!(
                "note:    no LAN between all of them, so training is limited by the mesh's encryption (see `slowest`)"
            );
        }
    } else {
        for p in &problems {
            println!("problem: {p}");
        }
    }
    Ok(ok)
}

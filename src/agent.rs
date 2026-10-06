//! Commands for working with many nodes at once - built for people and AI agents alike:
//! selecting nodes (`all`, `tag:gpu`, names), listing them with their hardware, running
//! commands and copying files across them. Everything has `--json` output.

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::control::{self, Request, Response};
use crate::node::Status;
use crate::proto::{Inventory, Lease, ObjectAd, Perf};

/// One node as agents see it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeView {
    pub name: String,
    pub id: String,
    pub ip: Ipv4Addr,
    pub online: bool,
    /// This machine.
    #[serde(rename = "self")]
    pub is_self: bool,
    pub tags: Vec<String>,
    pub path: String,
    pub rtt_ms: Option<u64>,
    pub inventory: Option<Inventory>,
    pub objects: Vec<ObjectAd>,
    /// Physical networks of the node.
    pub lan: Vec<String>,
    /// The node's measurements towards others (its row of the network matrix).
    pub perf: Vec<Perf>,
    /// When it last finished a requested measurement (ms since epoch).
    #[serde(skip)]
    pub measured: u64,
    /// GPU reservations on this node.
    pub leases: Vec<Lease>,
}

impl NodeView {
    /// A placeholder for a node known only by name (tests).
    pub fn named(name: &str) -> Self {
        NodeView {
            name: name.into(),
            id: String::new(),
            ip: Ipv4Addr::UNSPECIFIED,
            online: true,
            is_self: false,
            tags: vec![],
            path: String::new(),
            rtt_ms: None,
            inventory: None,
            objects: vec![],
            lan: vec![],
            perf: vec![],
            measured: 0,
            leases: vec![],
        }
    }

    /// GPUs that are idle and not reserved.
    pub fn free_gpus(&self) -> usize {
        let reserved: Vec<u32> = self.leases.iter().flat_map(|l| l.gpus.iter().copied()).collect();
        self.inventory.as_ref().map_or(0, |i| {
            i.gpus
                .iter()
                .filter(|g| !reserved.contains(&g.index))
                .filter(|g| g.util_pct < 10 && g.mem_used_mb * 10 < g.mem_total_mb.max(1))
                .count()
        })
    }
}

pub fn status(dir: &Path) -> Result<Status> {
    let rt = tokio::runtime::Runtime::new()?;
    match rt.block_on(control::request(dir, &Request::Status))? {
        Response::Status(st) => Ok(*st),
        _ => bail!("unexpected answer from meshvpn"),
    }
}

/// All nodes, this one first.
pub fn nodes(st: &Status) -> Vec<NodeView> {
    let mut out = vec![NodeView {
        name: st.name.clone(),
        id: st.id.clone(),
        ip: st.ip,
        online: true,
        is_self: true,
        tags: st.tags.clone(),
        path: "self".into(),
        rtt_ms: Some(0),
        inventory: st.inventory.clone(),
        objects: vec![],
        lan: st.lan.clone(),
        perf: st.perf.clone(),
        measured: st.measured,
        leases: st.leases.clone(),
    }];
    out.extend(st.peers.iter().map(|p| NodeView {
        name: p.name.clone(),
        id: p.id.clone(),
        ip: p.ip,
        online: p.online,
        is_self: false,
        tags: p.tags.clone(),
        path: p.path.clone(),
        rtt_ms: p.rtt_ms,
        inventory: p.inventory.clone(),
        objects: p.objects.clone(),
        lan: p.lan.clone(),
        perf: p.perf.clone(),
        measured: p.measured,
        leases: p.leases.clone(),
    }));
    out
}

/// Selectors: `all`, `tag:<tag>`, a node name (`name` / `name.mesh`), an id prefix or a mesh IP.
/// Several selectors add up. A selector that matches nothing is an error (exit code 5).
pub fn select(all: &[NodeView], selectors: &[String]) -> Result<Vec<NodeView>> {
    let mut picked: Vec<NodeView> = vec![];
    for sel in selectors {
        let sel = sel.trim().to_lowercase();
        let matches: Vec<&NodeView> = all
            .iter()
            .filter(|n| match sel.as_str() {
                "all" | "*" => true,
                s if s.starts_with("tag:") => n.tags.iter().any(|t| *t == s[4..]),
                s => {
                    let s = s.strip_suffix(".mesh").unwrap_or(s);
                    n.name == s || n.ip.to_string() == s || (s.len() >= 4 && n.id.starts_with(s))
                }
            })
            .collect();
        if matches.is_empty() {
            bail!("no node matches {sel:?} (see meshvpn nodes)");
        }
        for m in matches {
            if !picked.iter().any(|p| p.id == m.id) {
                picked.push(m.clone());
            }
        }
    }
    Ok(picked)
}

fn gpu_summary(inv: &Inventory) -> String {
    if inv.gpus.is_empty() {
        return "-".into();
    }
    let mut names: Vec<String> = vec![];
    for g in &inv.gpus {
        let short = g.name.replace("NVIDIA ", "");
        if !names.contains(&short) {
            names.push(short);
        }
    }
    format!("{}x {}", inv.gpus.len(), names.join(", "))
}

pub fn print_nodes(nodes: &[NodeView]) {
    let w = nodes.iter().map(|n| n.name.len()).max().unwrap_or(4).max(4);
    println!(
        "{:<w$}  {:<15}  {:<7}  {:<18}  {:>5}  {:>13}  GPUS",
        "NAME", "IP", "STATUS", "TAGS", "CPUS", "MEM FREE/ALL"
    );
    for n in nodes {
        let status = if n.is_self {
            "self"
        } else if n.online {
            "online"
        } else {
            "offline"
        };
        let tags = if n.tags.is_empty() {
            "-".into()
        } else {
            n.tags.join(",")
        };
        let (cpus, mem, gpus) = match &n.inventory {
            Some(i) => (
                i.cpu_cores.to_string(),
                format!(
                    "{:.0}/{:.0} GB",
                    i.mem_avail_mb as f64 / 1024.0,
                    i.mem_total_mb as f64 / 1024.0
                ),
                gpu_summary(i),
            ),
            None => ("-".into(), "-".into(), "-".into()),
        };
        println!(
            "{:<w$}  {:<15}  {:<7}  {:<18}  {:>5}  {:>13}  {gpus}",
            n.name, n.ip, status, tags, cpus, mem
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Running commands and copying files over SSH (uses the password-less logins of `meshvpn ssh`)

/// Quotes `s` for a POSIX shell.
pub fn sh_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+".contains(c)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[derive(Clone)]
pub struct Remote {
    pub user: String,
    /// Userspace mode: ssh has to go through meshvpn.
    pub socks: bool,
    pub timeout: Duration,
}

impl Remote {
    /// The account running this (the one behind sudo, if any) - not $USER, which is often
    /// missing (containers, services).
    pub fn default_user() -> String {
        let uid = unsafe { libc::geteuid() };
        if uid == 0
            && let Ok(u) = std::env::var("SUDO_USER")
        {
            return u;
        }
        let pw = unsafe { libc::getpwuid(uid) };
        if !pw.is_null() {
            return unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
                .to_string_lossy()
                .into_owned();
        }
        std::env::var("USER").unwrap_or_else(|_| "root".into())
    }

    /// A shell command on `node`: locally for this machine, over ssh otherwise.
    pub(crate) fn command(&self, node: &NodeView, script: &str) -> Command {
        if node.is_self {
            let mut c = Command::new("sh");
            c.arg("-c").arg(script);
            return c;
        }
        let mut c = Command::new("ssh");
        c.args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"])
            .args(["-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"]);
        if self.socks {
            let exe = crate::update::current_exe().unwrap_or_else(|_| "meshvpn".into());
            c.args(["-o", &format!("ProxyCommand={} nc %h %p", exe.display())]);
        }
        c.arg(self.destination(node)).arg(script);
        c
    }

    /// An interactive login shell on `node` (for a terminal): ssh -t, prompts allowed.
    pub(crate) fn shell(&self, node: &NodeView) -> Command {
        if node.is_self {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            let mut c = Command::new(shell);
            c.arg("-l");
            return c;
        }
        let mut c = Command::new("ssh");
        c.args([
            "-t",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
        ]);
        if self.socks {
            let exe = crate::update::current_exe().unwrap_or_else(|_| "meshvpn".into());
            c.args(["-o", &format!("ProxyCommand={} nc %h %p", exe.display())]);
        }
        c.arg(self.destination(node));
        c
    }

    /// `user@node.mesh`, or just `node.mesh` without a user (ssh's own config decides).
    fn destination(&self, node: &NodeView) -> String {
        if self.user.is_empty() {
            format!("{}.mesh", node.name)
        } else {
            format!("{}@{}.mesh", self.user, node.name)
        }
    }

    /// The account ssh logs in with for `node` when no user is given (`ssh -G`: User lines
    /// of ~/.ssh/config, else the local account).
    pub fn ssh_config_user(node: &str) -> String {
        std::process::Command::new("ssh")
            .args(["-G", &format!("{node}.mesh")])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find_map(|l| l.strip_prefix("user ").map(|u| u.trim().to_string()))
            })
            .filter(|u| !u.is_empty())
            .unwrap_or_else(Self::default_user)
    }
}

#[derive(Serialize)]
pub struct RunResult {
    pub node: String,
    pub ok: bool,
    /// None: killed after the timeout, or could not be started.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

const MAX_OUTPUT: usize = 1 << 20;

/// Runs `cmd` (stdin from `input`), with a deadline. Output is capped at 1 MB per stream.
fn run_one(node: &str, mut cmd: Command, input: Option<Box<dyn Read + Send>>, timeout: Duration) -> RunResult {
    let started = Instant::now();
    let fail = |msg: String| RunResult {
        node: node.into(),
        ok: false,
        exit_code: None,
        stdout: String::new(),
        stderr: msg,
        duration_ms: started.elapsed().as_millis() as u64,
    };
    cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(format!("cannot start: {e}")),
    };
    if let (Some(mut input), Some(mut stdin)) = (input, child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut input, &mut stdin);
        });
    }
    let reader = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = vec![];
            if let Some(mut r) = r {
                let _ = r.by_ref().take(MAX_OUTPUT as u64).read_to_end(&mut buf);
                let _ = std::io::copy(&mut r, &mut std::io::sink());
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let out = reader(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err = reader(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if started.elapsed() < timeout => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdout = out.join().unwrap_or_default();
    let mut stderr = err.join().unwrap_or_default();
    if status.is_none() {
        stderr.push_str(&format!("\nmeshvpn: killed after {}s timeout", timeout.as_secs()));
    }
    let code = status.and_then(|s| s.code());
    RunResult {
        node: node.into(),
        ok: code == Some(0),
        exit_code: code,
        stdout,
        stderr,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

/// Runs the same thing on several nodes at once.
fn parallel<F>(targets: &[NodeView], f: F) -> Vec<RunResult>
where
    F: Fn(&NodeView) -> RunResult + Sync,
{
    std::thread::scope(|s| {
        let handles: Vec<_> = targets.iter().map(|n| s.spawn(|| f(n))).collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

/// `meshvpn exec <selectors> -- command...`
pub fn exec(targets: &[NodeView], remote: &Remote, command: &[String]) -> Vec<RunResult> {
    // One argument is a shell command line (pipes etc. work); several are quoted as argv.
    let script = if command.len() == 1 {
        command[0].clone()
    } else {
        command.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" ")
    };
    parallel(targets, |n| {
        run_one(&n.name, remote.command(n, &script), None, remote.timeout)
    })
}

/// `meshvpn cp`: where a path lives.
pub enum Place {
    Local(String),
    /// Selectors and the path on those nodes.
    Remote(Vec<String>, String),
}

/// `node:/path`, `tag:gpu:/path`, `all:/path` or a local path.
pub fn parse_place(s: &str) -> Place {
    if s.starts_with('/') || s.starts_with('.') || s.starts_with('~') {
        return Place::Local(s.into());
    }
    let (sel, path) = match s.strip_prefix("tag:") {
        Some(rest) => match rest.split_once(':') {
            Some((tag, path)) => (format!("tag:{tag}"), path),
            None => return Place::Local(s.into()),
        },
        None => match s.split_once(':') {
            Some((node, path)) if !node.is_empty() && !node.contains('/') => (node.to_string(), path),
            _ => return Place::Local(s.into()),
        },
    };
    let path = if path.is_empty() { "." } else { path };
    Place::Remote(sel.split(',').map(String::from).collect(), path.into())
}

fn split_path(p: &str) -> (String, String) {
    let p = p.trim_end_matches('/');
    let path = Path::new(if p.is_empty() { "/" } else { p });
    let parent = path
        .parent()
        .map(|x| x.to_string_lossy().into_owned())
        .filter(|x| !x.is_empty())
        .unwrap_or_else(|| ".".into());
    let name = path
        .file_name()
        .map(|x| x.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".into());
    (parent, name)
}

/// Copies local `sources` into directory `dest` on every target (tar over ssh, so
/// directories, permissions and many small files work well).
pub fn upload(targets: &[NodeView], remote: &Remote, sources: &[String], dest: &str) -> Result<Vec<RunResult>> {
    for s in sources {
        if !Path::new(s).exists() {
            bail!("{s}: no such file or directory");
        }
    }
    let script = format!("mkdir -p {d} && tar -C {d} -xf -", d = sh_quote(dest));
    Ok(parallel(targets, |n| {
        let mut tar = Command::new("tar");
        tar.arg("-cf").arg("-");
        for s in sources {
            let (parent, name) = split_path(s);
            tar.arg("-C").arg(parent).arg(name);
        }
        let child = tar.stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
        match child {
            Ok(mut tar) => {
                let input = Box::new(tar.stdout.take().unwrap());
                let r = run_one(&n.name, remote.command(n, &script), Some(input), remote.timeout);
                let _ = tar.wait();
                r
            }
            Err(e) => RunResult {
                node: n.name.clone(),
                ok: false,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("tar: {e}"),
                duration_ms: 0,
            },
        }
    }))
}

/// Copies `source` from every target into local directory `dest` (into `dest/<node>/` when
/// there are several targets).
pub fn download(targets: &[NodeView], remote: &Remote, source: &str, dest: &str) -> Result<Vec<RunResult>> {
    let (parent, name) = split_path(source);
    let script = format!("tar -C {} -cf - {}", sh_quote(&parent), sh_quote(&name));
    let several = targets.len() > 1;
    Ok(parallel(targets, |n| {
        let dir = if several {
            format!("{dest}/{}", n.name)
        } else {
            dest.to_string()
        };
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return RunResult {
                node: n.name.clone(),
                ok: false,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("{dir}: {e}"),
                duration_ms: 0,
            };
        }
        let mut fetch = remote.command(n, &script);
        fetch.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let started = Instant::now();
        let result = (|| -> Result<RunResult> {
            let mut child = fetch.spawn()?;
            let out = child.stdout.take().ok_or_else(|| anyhow!("no output"))?;
            let tar = Command::new("tar")
                .arg("-C")
                .arg(&dir)
                .arg("-xf")
                .arg("-")
                .stdin(out)
                .stderr(Stdio::piped())
                .spawn()?;
            let mut remote_err = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut remote_err);
            }
            let fetched = child.wait()?;
            let unpacked = tar.wait_with_output()?;
            let ok = fetched.success() && unpacked.status.success();
            Ok(RunResult {
                node: n.name.clone(),
                ok,
                exit_code: fetched.code(),
                stdout: String::new(),
                stderr: format!("{remote_err}{}", String::from_utf8_lossy(&unpacked.stderr)),
                duration_ms: started.elapsed().as_millis() as u64,
            })
        })();
        result.unwrap_or_else(|e| RunResult {
            node: n.name.clone(),
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: e.to_string(),
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }))
}

pub fn print_results(results: &[RunResult], show_output: bool) {
    let several = results.len() > 1;
    for r in results {
        if several || !r.ok {
            let state = match r.exit_code {
                Some(0) => "ok".to_string(),
                Some(c) => format!("exit {c}"),
                None => "failed".to_string(),
            };
            println!("── {} ({state}, {:.1}s)", r.node, r.duration_ms as f64 / 1000.0);
        }
        if show_output {
            print!("{}", r.stdout);
            if !r.stdout.is_empty() && !r.stdout.ends_with('\n') {
                println!();
            }
        }
        if !r.stderr.trim().is_empty() {
            eprintln!("{}", r.stderr.trim_end());
        }
    }
    let _ = std::io::stdout().flush();
}

pub fn results_json(results: &[RunResult]) -> serde_json::Value {
    json!({
        "ok": results.iter().all(|r| r.ok),
        "results": results,
    })
}

// ---------------------------------------------------------------------------------------------
// Network matrix, LAN paths and training environment

#[derive(Serialize, Clone)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub rtt_ms: Option<f64>,
    pub mesh_mbps: Option<f32>,
    /// `to`'s address on a LAN both share, verified from `from`.
    pub lan_ip: Option<String>,
    pub age_s: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// What every selected node measured towards the others.
pub fn matrix(nodes: &[NodeView]) -> Vec<Edge> {
    let mut edges = vec![];
    for from in nodes {
        for to in nodes.iter().filter(|t| t.id != from.id) {
            if let Some(p) = from.perf.iter().find(|p| p.peer.hex() == to.id) {
                edges.push(Edge {
                    from: from.name.clone(),
                    to: to.name.clone(),
                    rtt_ms: p.rtt_us.map(|u| u as f64 / 1000.0),
                    mesh_mbps: p.mesh_mbps,
                    lan_ip: p.lan_ip.clone(),
                    age_s: now_ms().saturating_sub(p.at) / 1000,
                });
            }
        }
    }
    edges
}

/// Asks the nodes to measure towards each other and waits until all rows are fresh.
pub fn measure(dir: &Path, nodes: &[NodeView], mb: u64) -> Result<Vec<NodeView>> {
    let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let started = now_ms();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(control::request(
        dir,
        &Request::Measure {
            nodes: ids.clone(),
            bytes: mb * 1_000_000,
        },
    ))?;
    let deadline = Instant::now() + Duration::from_secs(30 + nodes.len() as u64 * (mb / 4).max(5));
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let fresh: Vec<NodeView> = select(&self::nodes(&status(dir)?), &ids)?;
        let pending: Vec<&str> = fresh
            .iter()
            .filter(|n| n.online && n.measured < started)
            .map(|n| n.name.as_str())
            .collect();
        if pending.is_empty() {
            return Ok(fresh);
        }
        if Instant::now() > deadline {
            eprintln!(
                "note: no fresh results from {} yet - showing what is there",
                pending.join(", ")
            );
            return Ok(fresh);
        }
    }
}

pub fn print_matrix(edges: &[Edge]) {
    if edges.is_empty() {
        println!("No measurements yet - run with --measure.");
        return;
    }
    let w = edges
        .iter()
        .map(|e| e.from.len().max(e.to.len()))
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "{:<w$}  {:<w$}  {:>9}  {:>12}  {:<17}  AGE",
        "FROM", "TO", "RTT", "MESH", "LAN PATH"
    );
    for e in edges {
        let rtt = e.rtt_ms.map(|r| format!("{r:.1} ms")).unwrap_or("-".into());
        let mbps = e.mesh_mbps.map(|m| format!("{m:.0} Mbit/s")).unwrap_or("-".into());
        let lan = e.lan_ip.clone().unwrap_or("-".into());
        println!(
            "{:<w$}  {:<w$}  {rtt:>9}  {mbps:>12}  {lan:<17}  {}s",
            e.from, e.to, e.age_s
        );
    }
}

#[derive(Serialize)]
pub struct Route {
    pub node: String,
    pub mesh_ip: Ipv4Addr,
    /// Verified address on a LAN both share - use it for heavy traffic.
    pub lan_ip: Option<String>,
    /// Local interface for `best`.
    pub interface: Option<String>,
    pub best: String,
}

pub fn route(me: &NodeView, to: &NodeView, userspace: bool) -> Route {
    let lan_ip = if to.is_self {
        None
    } else {
        me.perf
            .iter()
            .find(|p| p.peer.hex() == to.id)
            .and_then(|p| p.lan_ip.clone())
    };
    let interface = match &lan_ip {
        Some(ip) => ip.parse().ok().and_then(crate::net::lan_interface_for),
        None if userspace => None,
        None => Some("mesh0".into()),
    };
    Route {
        node: to.name.clone(),
        mesh_ip: to.ip,
        best: lan_ip.clone().unwrap_or_else(|| to.ip.to_string()),
        lan_ip,
        interface,
    }
}

/// Environment for distributed training (torchrun/NCCL) on THIS node, for the group `group`
/// with `master` as rank 0. Uses the LAN only if every pair in the group verified a LAN path
/// (mixing LAN and mesh addresses makes NCCL hang); otherwise the mesh for everyone.
pub fn training_env(me: &NodeView, group: &[NodeView], master: &NodeView, port: u16) -> Result<Vec<(String, String)>> {
    if !group.iter().any(|n| n.id == me.id) {
        bail!("this node ({}) is not in the selected group", me.name);
    }
    if !group.iter().any(|n| n.id == master.id) {
        bail!("the master ({}) is not in the selected group", master.name);
    }
    let lan_between = |a: &NodeView, b: &NodeView| -> Option<String> {
        a.perf
            .iter()
            .find(|p| p.peer.hex() == b.id)
            .and_then(|p| p.lan_ip.clone())
    };
    let all_lan = group.iter().all(|a| {
        group
            .iter()
            .filter(|b| b.id != a.id)
            .all(|b| lan_between(a, b).is_some())
    });
    let (master_addr, iface) = if group.len() == 1 {
        ("127.0.0.1".to_string(), "lo".to_string())
    } else if all_lan {
        // The master's LAN address as the others see it; our interface on that LAN.
        let peer = group.iter().find(|n| n.id != master.id).unwrap();
        let addr = lan_between(peer, master).unwrap();
        let towards = if me.id == master.id {
            lan_between(master, peer)
        } else {
            Some(addr.clone())
        };
        let iface = towards
            .and_then(|a| a.parse().ok())
            .and_then(crate::net::lan_interface_for)
            .ok_or_else(|| anyhow!("no local interface on the LAN towards {}", master.name))?;
        (addr, iface)
    } else {
        if let Some(n) = group.iter().find(|n| n.inventory.as_ref().is_some_and(|i| i.userspace)) {
            bail!(
                "no LAN path between all nodes, and {} runs in userspace mode (no mesh0 interface for NCCL)",
                n.name
            );
        }
        (master.ip.to_string(), "mesh0".to_string())
    };
    let mut ranked: Vec<&NodeView> = group.iter().collect();
    ranked.sort_by_key(|n| (n.id != master.id, n.name.clone()));
    let rank = ranked.iter().position(|n| n.id == me.id).unwrap();
    Ok(vec![
        ("MASTER_ADDR".into(), master_addr),
        ("MASTER_PORT".into(), port.to_string()),
        ("NNODES".into(), group.len().to_string()),
        ("NODE_RANK".into(), rank.to_string()),
        ("NCCL_SOCKET_IFNAME".into(), iface.clone()),
        ("GLOO_SOCKET_IFNAME".into(), iface),
        (
            "MESHVPN_PATH".into(),
            if all_lan || group.len() == 1 {
                "lan".into()
            } else {
                "mesh".into()
            },
        ),
    ])
}

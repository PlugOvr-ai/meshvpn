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
use crate::proto::{Inventory, ObjectAd};

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
}

impl NodeView {
    pub fn free_gpus(&self) -> usize {
        self.inventory.as_ref().map_or(0, |i| {
            i.gpus
                .iter()
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
    fn command(&self, node: &NodeView, script: &str) -> Command {
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
        c.arg(format!("{}@{}.mesh", self.user, node.name)).arg(script);
        c
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

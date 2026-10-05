//! `meshvpn launch`: start a distributed job (torchrun & co.) on a group of nodes.
//!
//! Every node gets its environment (MASTER_ADDR, NODE_RANK, NCCL_SOCKET_IFNAME... from
//! `meshvpn net env`, computed on that node), torchrun gets its rendezvous arguments added,
//! all nodes start together, output is streamed and logged per node, and when one node fails
//! the others are stopped (a distributed job would hang otherwise).
//!
//! Stopping is reliable: each job runs under a watcher that holds the SSH connection's stdin.
//! When the connection ends - Ctrl+C, `meshvpn jobs stop`, a lost network, a crashed
//! launcher - the watcher kills the job's whole process group on that node.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::agent::{self, NodeView, Remote, sh_quote};

static STOP: AtomicBool = AtomicBool::new(false);

/// GPU reservations of a job last this long and are renewed every 5 minutes.
const LEASE_TTL_MS: u64 = 15 * 60 * 1000;

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub struct Opts {
    pub selectors: Vec<String>,
    pub master: Option<String>,
    pub port: u16,
    pub user: Option<String>,
    pub workdir: Option<String>,
    pub keep_going: bool,
    pub command: Vec<String>,
    /// Reserve this many GPUs per node for the job (and set CUDA_VISIBLE_DEVICES).
    pub gpus: Option<u32>,
}

/// What a job looks like on disk (`~/.local/state/meshvpn/jobs/<id>/job.json`).
#[derive(Serialize, Deserialize, Clone)]
pub struct Job {
    pub id: String,
    pub command: Vec<String>,
    pub nodes: Vec<String>,
    pub master: String,
    /// running, succeeded, failed, stopped
    pub state: String,
    pub started: u64,
    /// The same in milliseconds, to order jobs started within one second.
    #[serde(default)]
    pub started_ms: u64,
    #[serde(default)]
    pub finished: Option<u64>,
    pub pid: u32,
    pub dir: String,
    /// The environment every node got.
    pub env: HashMap<String, HashMap<String, String>>,
    #[serde(default)]
    pub results: Vec<NodeResult>,
    /// GPU reservations of the job, per node.
    #[serde(default)]
    pub gpus: Vec<crate::gpu::Grant>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeResult {
    pub node: String,
    pub exit_code: Option<i32>,
    pub duration_s: f64,
    pub log: String,
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn jobs_dir() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("meshvpn/jobs")
}

impl Job {
    fn save(&self) -> Result<()> {
        let path = Path::new(&self.dir).join("job.json");
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn load(id: &str) -> Result<Job> {
        let path = jobs_dir().join(id).join("job.json");
        let mut job: Job =
            serde_json::from_slice(&std::fs::read(&path).with_context(|| format!("job {id} not found"))?)?;
        // A launcher that died without saying so.
        if job.state == "running" && unsafe { libc::kill(job.pid as i32, 0) } != 0 {
            job.state = "lost".into();
        }
        Ok(job)
    }

    pub fn list() -> Vec<Job> {
        let mut jobs: Vec<Job> = std::fs::read_dir(jobs_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| Job::load(&e.file_name().to_string_lossy()).ok())
            .collect();
        jobs.sort_by_key(|j| std::cmp::Reverse((j.started, j.started_ms)));
        jobs
    }
}

/// torchrun gets its rendezvous arguments from us unless the user gave them already.
pub fn add_torchrun_args(cmd: &[String], env: &HashMap<String, String>) -> Vec<String> {
    // Skip a leading `env NAME=value ...`.
    let mut start = 0;
    if cmd.first().is_some_and(|c| c == "env" || c.ends_with("/env")) {
        start = 1;
    }
    while cmd.get(start).is_some_and(|a| !a.starts_with('-') && a.contains('=')) {
        start += 1;
    }
    let prog = cmd.get(start).map(|p| p.rsplit('/').next().unwrap_or(p)).unwrap_or("");
    let at = if prog == "torchrun" {
        Some(start + 1)
    } else {
        cmd.windows(3)
            .position(|w| w[0].starts_with("python") && w[1] == "-m" && w[2] == "torch.distributed.run")
            .map(|i| i + 3)
    };
    let Some(at) = at else { return cmd.to_vec() };
    let has = |names: &[&str]| {
        cmd.iter()
            .any(|a| names.iter().any(|n| a == n || a.starts_with(&format!("{n}="))))
    };
    if has(&["--rdzv_endpoint", "--rdzv-endpoint", "--standalone"]) {
        return cmd.to_vec();
    }
    let mut extra = vec![];
    let get = |k: &str| env.get(k).cloned().unwrap_or_default();
    for (names, value) in [
        (&["--nnodes"][..], get("NNODES")),
        (&["--node_rank", "--node-rank"][..], get("NODE_RANK")),
        (&["--master_addr", "--master-addr"][..], get("MASTER_ADDR")),
        (&["--master_port", "--master-port"][..], get("MASTER_PORT")),
    ] {
        if !has(names) {
            extra.push(format!("{}={value}", names[0]));
        }
    }
    // One process per reserved GPU, unless the user says otherwise.
    if let Some(n) = env.get("MESHVPN_GPUS")
        && !has(&["--nproc_per_node", "--nproc-per-node"])
    {
        extra.push(format!("--nproc_per_node={n}"));
    }
    let mut out = cmd[..at].to_vec();
    out.extend(extra);
    out.extend(cmd[at..].iter().cloned());
    out
}

/// The command for one node, wrapped so it dies with the connection.
fn node_script(env: &HashMap<String, String>, workdir: Option<&str>, command: &[String]) -> String {
    let cmd = add_torchrun_args(command, env);
    let line = if cmd.len() == 1 {
        cmd[0].clone()
    } else {
        cmd.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" ")
    };
    let mut vars: Vec<String> = env.iter().map(|(k, v)| format!("{k}={}", sh_quote(v))).collect();
    vars.sort();
    let cd = workdir.map(|w| format!("cd {} && ", sh_quote(w))).unwrap_or_default();
    let job = format!("{cd}export {}; {line}", vars.join(" "));
    // Job control gives the job its own process group; the watcher kills that group when
    // stdin (the SSH connection) closes.
    format!(
        "set -m; ( {job} ) </dev/null & pid=$!; \
         ( cat >/dev/null; kill -TERM -$pid 2>/dev/null; sleep 10; kill -KILL -$pid 2>/dev/null ) >/dev/null 2>&1 & \
         watcher=$!; wait $pid; code=$?; kill $watcher 2>/dev/null; exit $code"
    )
}

struct Running {
    node: String,
    child: Child,
    stdin: Option<ChildStdin>,
    started: Instant,
    exit: Option<i32>,
    log: PathBuf,
}

/// Runs the job in the foreground (or as the detached launcher). Returns the finished job.
pub fn run(dir: &Path, opts: &Opts, job_dir: Option<PathBuf>, quiet: bool) -> Result<Job> {
    let st = agent::status(dir)?;
    let all = agent::nodes(&st);
    let group = agent::select(&all, &opts.selectors)?;
    if let Some(off) = group.iter().find(|n| !n.online) {
        bail!("{} is offline - a distributed job needs all its nodes", off.name);
    }
    let master: NodeView = match &opts.master {
        Some(m) => agent::select(&all, std::slice::from_ref(m))?.remove(0),
        None => group
            .iter()
            .min_by_key(|n| n.name.clone())
            .cloned()
            .ok_or_else(|| anyhow!("no nodes"))?,
    };
    let remote = Remote {
        user: opts.user.clone().unwrap_or_else(Remote::default_user),
        socks: st.socks.is_some(),
        timeout: Duration::from_secs(60),
    };

    // Each node computes its own environment (only it knows its interface names).
    let names: Vec<String> = group.iter().map(|n| sh_quote(&n.name)).collect();
    let env_cmd = format!(
        "meshvpn net env --json --master {} --port {} {}",
        sh_quote(&master.name),
        opts.port,
        names.join(" ")
    );
    let mut env: HashMap<String, HashMap<String, String>> = HashMap::new();
    for r in agent::exec(&group, &remote, &[env_cmd]) {
        if !r.ok {
            bail!("preparing {}: {}{}", r.node, r.stdout.trim(), r.stderr.trim());
        }
        let e: HashMap<String, String> =
            serde_json::from_str(r.stdout.trim()).with_context(|| format!("environment of {}", r.node))?;
        env.insert(r.node, e);
    }

    let id = job_dir
        .as_ref()
        .and_then(|d| d.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(new_id);

    // GPUs: reserved on every node before anything starts (all or nothing), renewed while the
    // job runs, released at the end - and expiring on their own if the launcher dies.
    let grants: Vec<crate::gpu::Grant> = match opts.gpus {
        Some(n) => {
            let holder = crate::gpu::default_holder(Some(&format!("job {id}")));
            crate::gpu::reserve_all(dir, &group, &remote, n, LEASE_TTL_MS, &holder)?
        }
        None => vec![],
    };
    for g in &grants {
        if let Some(e) = env.get_mut(&g.node) {
            e.insert("CUDA_VISIBLE_DEVICES".into(), g.cuda_visible_devices.clone());
            e.insert("MESHVPN_GPUS".into(), g.lease.gpus.len().to_string());
            e.insert("MESHVPN_GPU_LEASE".into(), g.lease.id.clone());
        }
    }
    let renewing = Arc::new(AtomicBool::new(true));
    if !grants.is_empty() {
        let (renewing, grants, group, remote, dir) = (
            renewing.clone(),
            grants.clone(),
            group.clone(),
            remote.clone(),
            dir.to_path_buf(),
        );
        std::thread::spawn(move || {
            while renewing.load(Ordering::SeqCst) {
                for _ in 0..300 {
                    std::thread::sleep(Duration::from_secs(1));
                    if !renewing.load(Ordering::SeqCst) {
                        return;
                    }
                }
                for g in &grants {
                    if let Some(n) = group.iter().find(|n| n.name == g.node) {
                        let _ = crate::gpu::renew_on(&dir, n, &remote, &g.lease.id, LEASE_TTL_MS);
                    }
                }
            }
        });
    }
    let dir_path = job_dir.unwrap_or_else(|| jobs_dir().join(&id));
    std::fs::create_dir_all(&dir_path)?;
    let mut job = Job {
        id: id.clone(),
        command: opts.command.clone(),
        nodes: group.iter().map(|n| n.name.clone()).collect(),
        master: master.name.clone(),
        state: "running".into(),
        started: now_s(),
        started_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        finished: None,
        pid: std::process::id(),
        dir: dir_path.display().to_string(),
        env: env.clone(),
        results: vec![],
        gpus: grants.clone(),
    };
    job.save()?;

    unsafe {
        libc::signal(
            libc::SIGINT,
            on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGHUP,
            on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }

    // Start everything at once.
    let print_lock = Arc::new(Mutex::new(()));
    let width = group.iter().map(|n| n.name.len()).max().unwrap_or(4);
    let mut running: Vec<Running> = vec![];
    for n in &group {
        let script = node_script(&env[&n.name], opts.workdir.as_deref(), &opts.command);
        let mut cmd = remote.command(n, &script);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // If the launcher dies (even kill -9), its ssh connections close and the watchers on
        // the nodes stop the job.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let mut child = cmd.spawn().with_context(|| format!("starting on {}", n.name))?;
        let log = dir_path.join(format!("{}.log", n.name));
        let file = Arc::new(Mutex::new(std::fs::File::create(&log)?));
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let (file, lock, name) = (file.clone(), print_lock.clone(), n.name.clone());
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let _ = writeln!(file.lock().unwrap(), "{line}");
                    if !quiet {
                        let _g = lock.lock().unwrap();
                        println!("[{name:>width$}] {line}");
                    }
                }
            });
        }
        let stdin = child.stdin.take();
        running.push(Running {
            node: n.name.clone(),
            child,
            stdin,
            started: Instant::now(),
            exit: None,
            log,
        });
    }
    if !quiet {
        eprintln!(
            "job {id}: {} on {} node(s), master {} via {} - logs in {}",
            opts.command.join(" "),
            group.len(),
            master.name,
            env.get(&master.name)
                .and_then(|e| e.get("MESHVPN_PATH"))
                .map(String::as_str)
                .unwrap_or("?"),
            dir_path.display()
        );
    }

    // Wait; stop everyone when one fails (unless --keep-going) or on Ctrl+C / jobs stop.
    let mut stopping: Option<Instant> = None;
    let mut stop_reason = None;
    loop {
        for r in running.iter_mut().filter(|r| r.exit.is_none()) {
            if let Ok(Some(s)) = r.child.try_wait() {
                r.exit = Some(s.code().unwrap_or(-1));
                if r.exit != Some(0) && !opts.keep_going && stopping.is_none() {
                    stop_reason = Some(format!("{} failed (exit {})", r.node, r.exit.unwrap()));
                }
            }
        }
        if STOP.load(Ordering::SeqCst) && stop_reason.is_none() {
            stop_reason = Some("stopped".into());
        }
        if stop_reason.is_some() && stopping.is_none() {
            stopping = Some(Instant::now());
            if !quiet {
                eprintln!(
                    "job {id}: {} - stopping the other nodes",
                    stop_reason.as_deref().unwrap()
                );
            }
            for r in running.iter_mut() {
                r.stdin.take(); // closes the connection's stdin: the watcher kills the job
            }
        }
        if let Some(t) = stopping
            && t.elapsed() > Duration::from_secs(20)
        {
            for r in running.iter_mut().filter(|r| r.exit.is_none()) {
                let _ = r.child.kill();
            }
        }
        if running.iter().all(|r| r.exit.is_some()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    renewing.store(false, Ordering::SeqCst);
    for g in &grants {
        if let Some(n) = group.iter().find(|n| n.name == g.node) {
            let _ = crate::gpu::release_on(dir, n, &remote, &g.lease.id);
        }
    }
    job.results = running
        .iter()
        .map(|r| NodeResult {
            node: r.node.clone(),
            exit_code: r.exit,
            duration_s: r.started.elapsed().as_secs_f64(),
            log: r.log.display().to_string(),
        })
        .collect();
    job.finished = Some(now_s());
    job.state = if STOP.load(Ordering::SeqCst) {
        "stopped".into()
    } else if running.iter().all(|r| r.exit == Some(0)) {
        "succeeded".into()
    } else {
        "failed".into()
    };
    job.save()?;
    Ok(job)
}

fn new_id() -> String {
    let mut b = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Starts the job in a background launcher and returns right away.
pub fn detach(dir: &Path, args: &[String]) -> Result<Job> {
    let id = new_id();
    let job_dir = jobs_dir().join(&id);
    std::fs::create_dir_all(&job_dir)?;
    let launcher_log = std::fs::File::create(job_dir.join("launcher.log"))?;
    let exe = crate::update::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--dir")
        .arg(dir)
        .arg("launch")
        .arg("--job-dir")
        .arg(&job_dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(launcher_log.try_clone()?)
        .stderr(launcher_log);
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid(); // survive the terminal / agent session that started it
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    // Wait until the launcher has written the job (or failed while preparing).
    let deadline = Instant::now() + Duration::from_secs(120);
    let path = job_dir.join("job.json");
    while !path.exists() {
        if Instant::now() > deadline {
            bail!(
                "the launcher did not start (see {})",
                job_dir.join("launcher.log").display()
            );
        }
        if unsafe { libc::kill(child.id() as i32, 0) } != 0 {
            let log = std::fs::read_to_string(job_dir.join("launcher.log")).unwrap_or_default();
            let _ = std::fs::remove_dir_all(&job_dir);
            bail!("{}", log.trim().trim_start_matches("error: "));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Job::load(&id)
}

pub fn stop(id: &str) -> Result<Job> {
    let job = Job::load(id)?;
    if job.state != "running" {
        bail!("job {id} is not running ({})", job.state);
    }
    unsafe { libc::kill(job.pid as i32, libc::SIGTERM) };
    for _ in 0..300 {
        std::thread::sleep(Duration::from_millis(100));
        let j = Job::load(id)?;
        if j.state != "running" {
            return Ok(j);
        }
    }
    bail!("job {id} did not stop within 30 s")
}

/// The last `lines` lines of a node's log.
pub fn tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn torchrun_gets_rendezvous_args() {
        let env: HashMap<String, String> = [
            ("NNODES", "2"),
            ("NODE_RANK", "1"),
            ("MASTER_ADDR", "10.0.0.1"),
            ("MASTER_PORT", "29500"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        assert_eq!(
            add_torchrun_args(&s(&["torchrun", "--nproc_per_node=8", "train.py"]), &env),
            s(&[
                "torchrun",
                "--nnodes=2",
                "--node_rank=1",
                "--master_addr=10.0.0.1",
                "--master_port=29500",
                "--nproc_per_node=8",
                "train.py"
            ])
        );
        // given by the user: kept
        let cmd = s(&["/opt/venv/bin/torchrun", "--nnodes=4", "train.py"]);
        assert_eq!(add_torchrun_args(&cmd, &env)[1], "--node_rank=1");
        assert!(add_torchrun_args(&cmd, &env).contains(&"--nnodes=4".to_string()));
        // python -m torch.distributed.run
        let cmd = s(&["python3", "-m", "torch.distributed.run", "t.py"]);
        assert_eq!(add_torchrun_args(&cmd, &env)[3], "--nnodes=2");
        // behind env VAR=value
        let cmd = s(&["env", "STEPS=3", "torchrun", "t.py"]);
        assert_eq!(add_torchrun_args(&cmd, &env)[3], "--nnodes=2");
        // other programs, and elastic rendezvous: untouched
        assert_eq!(
            add_torchrun_args(&s(&["python", "train.py"]), &env),
            s(&["python", "train.py"])
        );
        let cmd = s(&["torchrun", "--rdzv-endpoint=host:1", "t.py"]);
        assert_eq!(add_torchrun_args(&cmd, &env), cmd);
    }
}

mod config;
mod control;
mod hosts;
mod keys;
mod link;
mod node;
mod proto;
mod ssh;
mod sshd;
mod tui;
mod update;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use config::{Config, DEFAULT_PORT, DEFAULT_SOCKS_PORT, Invite, SavedState, SshTunnel};
use keys::{Identity, overlay_ip};

/// A decentralized mesh VPN. No coordination server: nodes find each other by gossip,
/// relay for each other, and can live behind a reverse SSH tunnel.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Directory holding config and state.
    #[arg(long, global = true, env = "MESHVPN_DIR", default_value = "/etc/meshvpn")]
    dir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a brand new network with this machine as its first node.
    Init {
        /// Name of the network.
        #[arg(long, default_value = "mesh")]
        network: String,
        #[command(flatten)]
        node: NodeOpts,
    },
    /// Join an existing network using an invite code from any member.
    Join {
        /// The invite code (`mesh1-...`), printed by `meshvpn invite` on any member.
        invite: String,
        #[command(flatten)]
        node: NodeOpts,
    },
    /// Print an invite code that lets another machine join.
    Invite,
    /// Run the VPN in the foreground (needs root).
    Up,
    /// Show this node and its peers.
    Status {
        /// Machine readable output.
        #[arg(long)]
        json: bool,
    },
    /// Connect to a node at HOST:PORT (e.g. a firewalled node's reverse tunnel port).
    AddPeer { addr: String },
    /// Remove offline nodes (e.g. old identities of re-installed machines) from the whole network.
    Forget {
        /// Name or id (prefix) of the node.
        #[arg(required_unless_present = "offline")]
        who: Option<String>,
        /// Forget all nodes that are currently offline.
        #[arg(long, conflicts_with = "who")]
        offline: bool,
    },
    /// Ban a node from the network for good: every node drops it, and all other members get a
    /// new network key (so it cannot come back under a new identity). Old invites stop working.
    Ban {
        /// Name or id (prefix) of the node.
        who: String,
    },
    /// Password-less SSH logins between nodes: each machine decides who may log in to it.
    /// Without a subcommand, opens an editor for this machine's permissions.
    Ssh {
        #[command(subcommand)]
        cmd: Option<SshCmd>,
    },
    /// Used by sshd (AuthorizedKeysCommand): prints the keys that may log in as USER.
    #[command(hide = true)]
    SshAuthorizedKeys { user: String },
    /// Update to the latest release from GitHub (restarts the running VPN).
    Update {
        /// Only check whether a new version is available.
        #[arg(long)]
        check: bool,
        /// Update even a development build.
        #[arg(long)]
        force: bool,
    },
    /// Install and start a systemd service so the VPN runs at boot.
    Install,
    /// Stop and remove the systemd service.
    Uninstall,
}

#[derive(Subcommand)]
enum SshCmd {
    /// Let a node - or one user on it (`user@node`) - log in here without a password.
    ///
    /// Example: `sudo meshvpn ssh allow cornelius@desktop --as cornelius`
    Allow {
        /// `node` (any of its users) or `user@node`.
        who: String,
        /// Local account(s) they may log in as.
        #[arg(long = "as", required = true, num_args = 1..)]
        users: Vec<String>,
    },
    /// Take a permission back (without --as: all accounts).
    Deny {
        who: String,
        #[arg(long = "as", num_args = 1..)]
        users: Vec<String>,
    },
    /// Show who may log in here, and which keys this machine offers to others.
    List,
}

#[derive(Args)]
struct NodeOpts {
    /// Name of this machine in the network (default: hostname).
    #[arg(long)]
    name: Option<String>,
    /// Where to accept connections from other nodes.
    #[arg(long, default_value_t = format!("0.0.0.0:{DEFAULT_PORT}"))]
    listen: String,
    /// Never accept connections (this node only connects out).
    #[arg(long)]
    no_listen: bool,
    /// Public address other nodes can reach this one at (HOST:PORT). Repeatable.
    #[arg(long = "endpoint", value_name = "HOST:PORT")]
    endpoints: Vec<String>,
    /// Firewalled machine: reach the internet through a reverse SSH tunnel to USER@HOST.
    #[arg(long, value_name = "USER@HOST")]
    ssh: Option<String>,
    /// SSH port of the tunnel server.
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,
    /// Port opened on the SSH server that forwards to this node (0 = none; the node then
    /// only connects out through the tunnel and is reached through other nodes).
    #[arg(long, default_value_t = DEFAULT_PORT)]
    ssh_remote_port: u16,
    /// Host name others use to reach the SSH server (default: host of --ssh).
    #[arg(long)]
    ssh_public_host: Option<String>,
    /// SSH private key to use for the tunnel.
    #[arg(long)]
    ssh_identity: Option<String>,
    /// Do not send outgoing connections through the SSH tunnel.
    #[arg(long)]
    ssh_no_socks: bool,
    /// Send all outgoing connections through this SOCKS5 proxy (HOST:PORT).
    #[arg(long)]
    socks_proxy: Option<String>,
    /// Never connect out; wait for other nodes to connect in.
    #[arg(long)]
    no_outbound: bool,
    /// Let every node of the network log in here over SSH as USER without a password (e.g. on
    /// cluster machines everybody works on). Repeatable, or comma separated.
    #[arg(long, value_name = "USER", value_delimiter = ',')]
    ssh_allow_all: Vec<String>,
    /// Name of the network interface.
    #[arg(long, default_value = "mesh0")]
    interface: String,
    /// Overwrite an existing configuration.
    #[arg(long)]
    force: bool,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = real_main(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main(cli: Cli) -> Result<()> {
    let dir = cli.dir;
    match cli.cmd {
        Cmd::Init { network, node } => {
            let key = keys::random32();
            let cfg = create(&dir, node, config::sanitize_name(&network), key, vec![])?;
            println!("Created network \"{}\".\n", cfg.network);
            print_node_summary(&cfg)?;
            print_invite(&dir, &cfg);
            enable_ssh_logins(&cfg);
            print_next_steps(&dir, &cfg);
        }
        Cmd::Join { invite, node } => {
            let inv = Invite::decode(&invite)?;
            let key = keys::unb64_32(&inv.key)?;
            let mut cfg = create(&dir, node, inv.network, key, inv.bootstrap)?;
            cfg.network_id = inv.id;
            cfg.key_version = inv.v;
            cfg.save(&dir)?;
            println!("Joined network \"{}\".\n", cfg.network);
            print_node_summary(&cfg)?;
            println!("It will connect to: {}", cfg.bootstrap.join(", "));
            enable_ssh_logins(&cfg);
            print_next_steps(&dir, &cfg);
        }
        Cmd::Invite => {
            let cfg = Config::load(&dir)?;
            print_invite(&dir, &cfg);
        }
        Cmd::Up => {
            let cfg = Config::load(&dir)?;
            init_logging();
            tokio::runtime::Runtime::new()?.block_on(node::run(dir, cfg))?;
        }
        Cmd::Status { json } => {
            let resp = tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &control::Request::Status))?;
            let control::Response::Status(st) = resp else {
                bail!("unexpected response")
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&st)?);
            } else {
                print_status(&st);
            }
        }
        Cmd::AddPeer { addr } => {
            if !addr.contains(':') {
                bail!("expected HOST:PORT, e.g. jump.example.com:{DEFAULT_PORT}");
            }
            tokio::runtime::Runtime::new()?.block_on(control::request(
                &dir,
                &control::Request::AddPeer { addr: addr.clone() },
            ))?;
            println!("Connecting to {addr}. It is remembered, and the whole network will learn about it.");
            println!("Check with: meshvpn status");
        }
        Cmd::Ssh { cmd: None } if unsafe { libc::isatty(1) } == 1 => {
            require_root()?;
            tui::run(&dir)?;
        }
        Cmd::Ssh { cmd } => {
            let req = match cmd.unwrap_or(SshCmd::List) {
                SshCmd::Allow { who, users } => {
                    require_root()?;
                    if sshd::enable()? {
                        println!(
                            "Enabled password-less logins from mesh nodes in sshd ({}).",
                            sshd::DROPIN
                        );
                    }
                    control::Request::SshAllow { who, users }
                }
                SshCmd::Deny { who, users } => {
                    require_root()?;
                    control::Request::SshDeny { who, users }
                }
                SshCmd::List => control::Request::SshList,
            };
            if let control::Response::Message { text } =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))?
            {
                println!("{}", text.trim_end());
            }
        }
        Cmd::SshAuthorizedKeys { user } => {
            // Called by sshd for every login attempt: never fail loudly, just offer nothing.
            let req = control::Request::AuthorizedKeys { user };
            if let Ok(rt) = tokio::runtime::Runtime::new()
                && let Ok(control::Response::Message { text }) = rt.block_on(control::request(&dir, &req))
            {
                print!("{text}");
            }
        }
        Cmd::Ban { who } => {
            let resp =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &control::Request::Ban { who }))?;
            if let control::Response::Message { text } = resp {
                println!("{text}");
            }
        }
        Cmd::Forget { who, offline: _ } => {
            let resp =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &control::Request::Forget { who }))?;
            if let control::Response::Message { text } = resp {
                println!("{text}");
            }
        }
        Cmd::Update { check, force } => update_cmd(&dir, check, force)?,
        Cmd::Install => install(&dir)?,
        Cmd::Uninstall => uninstall()?,
    }
    Ok(())
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("meshvpn=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn create(dir: &Path, o: NodeOpts, network: String, key: [u8; 32], bootstrap: Vec<String>) -> Result<Config> {
    if Config::path(dir).exists() && !o.force {
        bail!(
            "{} already exists - this machine is already set up (use --force to replace it)",
            Config::path(dir).display()
        );
    }
    // Starting over: forget the nodes of the previous setup.
    let _ = std::fs::remove_file(SavedState::path(dir));
    let name = o
        .name
        .as_deref()
        .map(config::sanitize_name)
        .unwrap_or_else(config::default_node_name);
    let mut cfg = Config::new(name, network, key);
    cfg.listen = (!o.no_listen).then_some(o.listen);
    cfg.endpoints = o.endpoints;
    cfg.bootstrap = bootstrap;
    cfg.interface = o.interface;
    cfg.socks_proxy = o.socks_proxy;
    cfg.no_outbound = o.no_outbound;
    if let Some(u) = o.ssh_allow_all.iter().find(|u| !proto::valid_user(u)) {
        bail!("--ssh-allow-all: invalid user name {u:?}");
    }
    cfg.ssh_allow_all = o.ssh_allow_all;
    if let Some(server) = o.ssh {
        if cfg.listen.is_none() {
            bail!("--ssh needs this node to listen (drop --no-listen)");
        }
        cfg.ssh_tunnel = Some(SshTunnel {
            server,
            port: o.ssh_port,
            remote_port: o.ssh_remote_port,
            public_host: o.ssh_public_host,
            identity_file: o.ssh_identity,
            socks_port: if o.ssh_no_socks { 0 } else { DEFAULT_SOCKS_PORT },
            extra_args: vec![],
        });
        // Behind the tunnel there is nothing useful to auto-detect.
        cfg.auto_endpoints = false;
        cfg.listen = Some(format!("127.0.0.1:{}", cfg.listen_port().unwrap_or(DEFAULT_PORT)));
    }
    cfg.save(dir)?;
    Ok(cfg)
}

/// Sets up sshd right away if the config asks for password-less logins. If that isn't possible
/// yet (e.g. meshvpn not installed to /usr/local/bin), the daemon retries at startup.
fn enable_ssh_logins(cfg: &Config) {
    if cfg.ssh_allow_all.is_empty() && cfg.ssh_allow.is_empty() {
        return;
    }
    match sshd::enable() {
        Ok(_) => println!(
            "Password-less SSH logins from mesh nodes are enabled ({}).\n",
            sshd::DROPIN
        ),
        Err(e) => println!("note: password-less SSH logins are not active yet: {e:#}\n"),
    }
}

fn print_node_summary(cfg: &Config) -> Result<()> {
    let id = Identity::from_config(cfg)?;
    println!("  this node:   {}", cfg.name);
    println!("  mesh IP:     {}", overlay_ip(&id.id));
    println!("  host name:   {}.mesh", cfg.name);
    if let Some(t) = &cfg.ssh_tunnel {
        if t.remote_port == 0 {
            println!("  ssh tunnel:  {} (outgoing only)", t.server);
        } else {
            println!("  ssh tunnel:  {} (reachable at {})", t.server, t.public_endpoint());
        }
    }
    if !cfg.ssh_allow_all.is_empty() {
        println!(
            "  ssh logins:  every node may log in as {} without a password",
            cfg.ssh_allow_all.join(", ")
        );
    }
    println!();
    Ok(())
}

fn print_next_steps(dir: &Path, cfg: &Config) {
    println!();
    if std::os::unix::net::UnixStream::connect(control::socket_path(dir)).is_ok() {
        println!("meshvpn is still running with the previous configuration. Restart it:");
        println!("  sudo systemctl restart meshvpn   # if installed as a service");
        println!("  (or stop `meshvpn up` with Ctrl+C and start it again)");
        println!();
    }
    println!("Next steps:");
    println!("  sudo meshvpn up          # run now, in the foreground");
    println!("  sudo meshvpn install     # or: run in the background, also after reboot");
    println!("  meshvpn status           # see who is connected");
    if let Some(t) = &cfg.ssh_tunnel {
        println!();
        println!("SSH tunnel notes:");
        println!(
            "  - `sudo ssh -p {} {}` must work without a password (as root, or pass --ssh-identity).",
            t.port, t.server
        );
        if t.remote_port != 0 {
            println!("  - For other nodes to connect in, the SSH server needs `GatewayPorts clientspecified`");
            println!(
                "    in /etc/ssh/sshd_config and port {} open. Without it this node still works by",
                t.remote_port
            );
            println!("    connecting out through the tunnel.");
        }
    } else if cfg.no_outbound {
        println!();
        println!("This node does not connect out. On any existing node run:");
        match cfg.static_endpoints().first() {
            Some(e) => println!("  sudo meshvpn add-peer {e}"),
            None => println!("  sudo meshvpn add-peer <public HOST:PORT that reaches this node>"),
        }
    }
}

fn make_invite(dir: &Path, cfg: &Config) -> Invite {
    let mut boot: Vec<String> = cfg.static_endpoints();
    let saved = SavedState::load(dir);
    let net = cfg.network_id();
    match saved.me.as_ref().and_then(|m| m.verify(&net).ok()) {
        Some(me) => boot.extend(me.endpoints),
        None => {
            if cfg.auto_endpoints
                && let Some(port) = cfg.listen_port()
                && cfg.listen.as_deref().is_some_and(|l| !l.starts_with("127."))
                && let Some(ip) = local_ip()
            {
                boot.push(format!("{ip}:{port}"));
            }
        }
    }
    let mut peers: Vec<_> = saved.peers.iter().filter_map(|p| p.verify(&net).ok()).collect();
    peers.sort_by_key(|p| std::cmp::Reverse(p.seq));
    for p in peers {
        boot.extend(p.endpoints);
    }
    boot.extend(cfg.bootstrap.clone());
    let mut seen = HashSet::new();
    boot.retain(|e| seen.insert(e.clone()));
    boot.truncate(12);

    Invite {
        network: cfg.network.clone(),
        key: cfg.network_key.clone(),
        bootstrap: boot,
        id: cfg.network_id(),
        v: cfg.key_version,
    }
}

fn print_invite(dir: &Path, cfg: &Config) {
    let inv = make_invite(dir, cfg);
    let boot = &inv.bootstrap;
    println!("Invite code (treat it like a password - it grants access to the network):\n");
    println!("  {}\n", inv.encode());
    println!("On the new machine run:\n");
    println!("  sudo meshvpn join {}\n", inv.encode());
    if boot.is_empty() {
        println!("warning: no reachable address of this network is known, so the new node will not");
        println!("find it. Give this node a public address with `--endpoint HOST:PORT` in init/join,");
        println!("or add one to `endpoints` in {}.", Config::path(dir).display());
    } else {
        println!("The new node will first contact: {}", boot.join(", "));
    }
}

fn local_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:80").ok()?;
    Some(s.local_addr().ok()?.ip())
}

fn print_status(st: &node::Status) {
    println!(
        "● {}  {}  ({} on {}, network \"{}\")",
        st.name,
        st.ip,
        &st.id[..8],
        st.interface,
        st.network
    );
    if let Some(v) = &st.update_available {
        println!("  \x1b[1;36mupdate:\x1b[0m meshvpn {v} is available - run: sudo meshvpn update");
    }
    if !st.banned.is_empty() {
        println!("  banned:       {}", st.banned.join(", "));
    }
    for w in &st.warnings {
        println!("  \x1b[1;33mwarning:\x1b[0m {w}");
    }
    if !st.endpoints.is_empty() {
        println!("  reachable at: {}", st.endpoints.join(", "));
    }
    if let Some(t) = &st.ssh_tunnel {
        println!("  ssh tunnel:   {t}");
    }
    if let Some(o) = &st.outbound_via {
        println!("  outgoing via: {o}");
    }
    println!();
    if st.peers.is_empty() {
        println!("No other nodes known yet.");
        return;
    }
    let w = st.peers.iter().map(|p| p.name.len()).max().unwrap_or(4).max(4);
    println!("{:<w$}  {:<15}  {:<7}  {:>6}  PATH", "NAME", "IP", "STATUS", "RTT");
    for p in &st.peers {
        let status = if p.online { "online" } else { "offline" };
        let rtt = p.rtt_ms.map(|r| format!("{r}ms")).unwrap_or_else(|| "-".into());
        let path = if p.online {
            p.path.clone()
        } else {
            match p.last_seen_secs {
                Some(s) => format!("last seen {}", human_secs(s)),
                None => "not seen since restart".into(),
            }
        };
        println!("{:<w$}  {:<15}  {:<7}  {:>6}  {}", p.name, p.ip, status, rtt, path);
    }
}

fn human_secs(s: u64) -> String {
    match s {
        0..=119 => format!("{s}s ago"),
        120..=7199 => format!("{}m ago", s / 60),
        _ => format!("{}h ago", s / 3600),
    }
}

fn update_cmd(dir: &Path, check: bool, force: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    // A running daemon does it itself: it knows the way out (e.g. the SSH tunnel) and restarts.
    if control::is_running(dir) {
        let req = control::Request::Update {
            check_only: check,
            force,
        };
        if let control::Response::Message { text } = rt.block_on(control::request(dir, &req))? {
            println!("{text}");
        }
        return Ok(());
    }
    let socks = Config::load(dir).ok().and_then(|c| c.effective_socks());
    rt.block_on(async {
        let client = update::client(socks.as_deref())?;
        let tag = update::latest_tag(&client).await?;
        if !update::is_newer(&tag, update::CURRENT) {
            println!("meshvpn {} is up to date", update::CURRENT);
        } else if check {
            println!("meshvpn {tag} is available (running {})", update::CURRENT);
        } else if update::is_dev_build() && !force {
            bail!("this is a development build - update it with git pull && cargo build (or use --force)");
        } else {
            let exe = update::install(&client, &tag).await?;
            println!("updated {} -> {tag} ({})", update::CURRENT, exe.display());
        }
        Ok(())
    })
}

const UNIT_PATH: &str = "/etc/systemd/system/meshvpn.service";
const BIN_PATH: &str = "/usr/local/bin/meshvpn";

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("this needs root - try again with sudo");
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> Result<()> {
    let st = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .context("running systemctl")?;
    if !st.success() {
        bail!("systemctl {} failed", args.join(" "));
    }
    Ok(())
}

fn install(dir: &Path) -> Result<()> {
    require_root()?;
    Config::load(dir)?; // fail early with a helpful message
    // Installed by a package manager or install.sh: use it where it is. Otherwise (e.g. run
    // from a download folder) copy it somewhere permanent first.
    let exe = std::env::current_exe()?.canonicalize()?;
    let bin = if exe.starts_with("/usr/") || exe.starts_with("/opt/") {
        exe
    } else {
        std::fs::copy(&exe, BIN_PATH).with_context(|| format!("copying binary to {BIN_PATH}"))?;
        PathBuf::from(BIN_PATH)
    };
    let dir = std::path::absolute(dir)?;
    let unit = format!(
        "[Unit]\nDescription=meshvpn decentralized mesh VPN\nWants=network-online.target\nAfter=network-online.target\n\n\
         [Service]\nExecStart={} --dir {} up\nRestart=always\nRestartSec=3\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        bin.display(),
        dir.display()
    );
    std::fs::write(UNIT_PATH, unit)?;
    systemctl(&["daemon-reload"])?;
    // The service takes over: a meshvpn started by hand (or an old version) would hold the
    // network interface and make the service fail with "Resource busy".
    let _ = systemctl(&["stop", "meshvpn"]);
    for (pid, cmd) in stop_other_daemons() {
        println!("Stopped a meshvpn that was already running (pid {pid}: {cmd}).");
    }
    systemctl(&["enable", "meshvpn"])?;
    systemctl(&["restart", "meshvpn"])?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    let active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "meshvpn"])
        .status()
        .is_ok_and(|s| s.success());
    if !active {
        bail!("the meshvpn service did not start - see: journalctl -u meshvpn -n 20");
    }
    println!("meshvpn is running and will start at boot.");
    println!("  status: meshvpn status   logs: journalctl -u meshvpn -f");
    Ok(())
}

/// `meshvpn [options] up`, started from any path.
fn is_daemon_cmdline(args: &[String]) -> bool {
    let is_meshvpn = args
        .first()
        .is_some_and(|a| Path::new(a).file_name().is_some_and(|n| n == "meshvpn"));
    is_meshvpn && args.iter().skip(1).any(|a| a == "up")
}

/// Stops meshvpn daemons (`meshvpn ... up`) other than this process. Returns what it stopped.
fn stop_other_daemons() -> Vec<(i32, String)> {
    let me = std::process::id() as i32;
    let mut stopped = vec![];
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return stopped;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|p| p.parse::<i32>().ok()) else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let args: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        if !is_daemon_cmdline(&args) {
            continue;
        }
        unsafe { libc::kill(pid, libc::SIGTERM) };
        for _ in 0..50 {
            if !Path::new(&format!("/proc/{pid}")).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if Path::new(&format!("/proc/{pid}")).exists() {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        stopped.push((pid, args.join(" ")));
    }
    stopped
}

fn uninstall() -> Result<()> {
    require_root()?;
    let _ = systemctl(&["disable", "--now", "meshvpn"]);
    sshd::disable();
    std::fs::remove_file(UNIT_PATH).ok();
    let _ = systemctl(&["daemon-reload"]);
    println!("meshvpn service removed (configuration kept).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    #[test]
    fn finds_meshvpn_daemons_only() {
        assert!(is_daemon_cmdline(&args("./target/release/meshvpn up")));
        assert!(is_daemon_cmdline(&args("/usr/local/bin/meshvpn --dir /etc/meshvpn up")));
        assert!(!is_daemon_cmdline(&args("meshvpn status")));
        assert!(!is_daemon_cmdline(&args("/usr/bin/vim meshvpn up")));
        assert!(!is_daemon_cmdline(&args("sudo meshvpn up")));
    }
}

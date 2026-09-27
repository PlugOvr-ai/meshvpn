mod config;
mod control;
mod hosts;
mod keys;
mod link;
mod node;
mod proto;
mod ssh;

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
    /// Install and start a systemd service so the VPN runs at boot.
    Install,
    /// Stop and remove the systemd service.
    Uninstall,
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
    /// Port opened on the SSH server that forwards to this node.
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
            print_next_steps(&cfg);
        }
        Cmd::Join { invite, node } => {
            let inv = Invite::decode(&invite)?;
            let key = keys::unb64_32(&inv.key)?;
            let cfg = create(&dir, node, inv.network, key, inv.bootstrap)?;
            println!("Joined network \"{}\".\n", cfg.network);
            print_node_summary(&cfg)?;
            println!("It will connect to: {}", cfg.bootstrap.join(", "));
            print_next_steps(&cfg);
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

fn print_node_summary(cfg: &Config) -> Result<()> {
    let id = Identity::from_config(cfg)?;
    println!("  this node:   {}", cfg.name);
    println!("  mesh IP:     {}", overlay_ip(&id.id));
    println!("  host name:   {}.mesh", cfg.name);
    if let Some(t) = &cfg.ssh_tunnel {
        println!("  ssh tunnel:  {} (reachable at {})", t.server, t.public_endpoint());
    }
    println!();
    Ok(())
}

fn print_next_steps(cfg: &Config) {
    println!();
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
        println!("  - For other nodes to connect in, the SSH server needs `GatewayPorts clientspecified`");
        println!(
            "    in /etc/ssh/sshd_config and port {} open. Without it this node still works by",
            t.remote_port
        );
        println!("    connecting out through the tunnel.");
    } else if cfg.no_outbound {
        println!();
        println!("This node does not connect out. On any existing node run:");
        match cfg.static_endpoints().first() {
            Some(e) => println!("  sudo meshvpn add-peer {e}"),
            None => println!("  sudo meshvpn add-peer <public HOST:PORT that reaches this node>"),
        }
    }
}

fn print_invite(dir: &Path, cfg: &Config) {
    let mut boot: Vec<String> = cfg.static_endpoints();
    let saved = SavedState::load(dir);
    match saved.me.as_ref().and_then(|m| m.verify().ok()) {
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
    let mut peers: Vec<_> = saved.peers.iter().filter_map(|p| p.verify().ok()).collect();
    peers.sort_by_key(|p| std::cmp::Reverse(p.seq));
    for p in peers {
        boot.extend(p.endpoints);
    }
    boot.extend(cfg.bootstrap.clone());
    let mut seen = HashSet::new();
    boot.retain(|e| seen.insert(e.clone()));
    boot.truncate(12);

    let inv = Invite {
        network: cfg.network.clone(),
        key: cfg.network_key.clone(),
        bootstrap: boot.clone(),
    };
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
    systemctl(&["enable", "--now", "meshvpn"])?;
    println!("meshvpn is running and will start at boot.");
    println!("  status: meshvpn status   logs: journalctl -u meshvpn -f");
    Ok(())
}

fn uninstall() -> Result<()> {
    require_root()?;
    let _ = systemctl(&["disable", "--now", "meshvpn"]);
    std::fs::remove_file(UNIT_PATH).ok();
    let _ = systemctl(&["daemon-reload"]);
    println!("meshvpn service removed (configuration kept).");
    Ok(())
}

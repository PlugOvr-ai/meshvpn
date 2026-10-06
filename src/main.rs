mod agent;
mod config;
mod console;
mod control;
mod desktop;
mod doctor;
mod gpu;
mod hosts;
mod inventory;
mod keys;
mod launch;
mod link;
mod mcp;
mod net;
mod node;
mod proto;
mod share;
mod ssh;
mod sshd;
mod sshserver;
mod tui;
mod update;
mod userspace;

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
    /// Directory holding config and state [default: /etc/meshvpn as root, else
    /// ~/.config/meshvpn for a rootless install, or /etc/meshvpn if only that exists].
    #[arg(long, global = true, env = "MESHVPN_DIR")]
    dir: Option<PathBuf>,
    /// Machine readable output (JSON on stdout, also for errors). Exit codes: 0 ok, 1 error,
    /// 2 usage, 3 meshvpn not running, 4 needs root, 5 node/rule not found.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a brand new network with this machine as its first node.
    Init {
        /// Name of the network.
        #[arg(long, default_value = "mesh")]
        network: String,
        /// Open network: everybody with an invite may invite others and ban (no admins).
        #[arg(long)]
        open: bool,
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
    Invite {
        /// How many nodes may join with it (managed networks).
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// How long it is valid, e.g. 30m, 24h, 7d (managed networks).
        #[arg(long, default_value = "24h")]
        expires: String,
    },
    /// GPUs across the network: list them, reserve them for a job, release them.
    Gpu {
        #[command(subcommand)]
        cmd: GpuCmd,
    },
    /// Admins of a managed network: only they invite, ban and change the admins.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Run the VPN in the foreground (needs root).
    Up,
    /// Check this machine's setup and say how to fix problems.
    Doctor,
    /// Show this node and its peers.
    Status,
    /// List nodes with tags, hardware and GPUs. Selectors: all, tag:<tag>, names, mesh IPs.
    Nodes {
        /// Which nodes (default: all).
        selectors: Vec<String>,
        /// Only nodes that are online.
        #[arg(long)]
        online: bool,
        /// Only nodes with at least this many idle GPUs.
        #[arg(long, value_name = "N")]
        free_gpus: Option<usize>,
    },
    /// Network between nodes: latency/throughput matrix, LAN paths, training environment.
    Net {
        #[command(subcommand)]
        cmd: NetCmd,
    },
    /// Share a file or directory (dataset, checkpoint) with the network; prints its id.
    Share {
        path: PathBuf,
        /// Name shown to others (default: the file/directory name).
        #[arg(long)]
        name: Option<String>,
    },
    /// Download a shared object into DIR - in parallel from every node that has it, over LAN
    /// paths where possible. Resumes where it stopped; afterwards this node serves it too.
    Fetch {
        id: String,
        /// Directory to download into.
        #[arg(value_name = "DIR")]
        dest: PathBuf,
    },
    /// Stop sharing an object (the files stay).
    Unshare { id: String },
    /// Shared objects in the network and which nodes have them.
    Objects,
    /// Start a distributed job on a group of nodes, e.g.
    /// `meshvpn launch tag:gpu -- torchrun --nproc_per_node=8 train.py`. Every node gets
    /// MASTER_ADDR, NODE_RANK, NCCL_SOCKET_IFNAME...; torchrun gets --nnodes/--node_rank/
    /// --master_addr/--master_port added. If one node fails, the others are stopped.
    Launch {
        /// The nodes of the job: all, tag:<tag>, names.
        #[arg(required = true)]
        selectors: Vec<String>,
        /// The command (one argument = a shell command line).
        #[arg(last = true, required = true)]
        command: Vec<String>,
        /// Rank 0 (default: the first node by name).
        #[arg(long)]
        master: Option<String>,
        #[arg(long, default_value_t = 29500)]
        port: u16,
        /// Account on the nodes (default: you).
        #[arg(long, short)]
        user: Option<String>,
        /// Directory to run in on the nodes (default: home).
        #[arg(long)]
        workdir: Option<String>,
        /// Don't stop the other nodes when one fails.
        #[arg(long)]
        keep_going: bool,
        /// Reserve this many GPUs per node for the job (sets CUDA_VISIBLE_DEVICES and torchrun's
        /// --nproc_per_node); fails before starting if they are not free.
        #[arg(long)]
        gpus: Option<u32>,
        /// Run in the background and print the job id (see `meshvpn jobs`).
        #[arg(long)]
        detach: bool,
        #[arg(long, hide = true)]
        job_dir: Option<PathBuf>,
    },
    /// Jobs started with `meshvpn launch` (yours): list, logs, stop.
    Jobs {
        #[command(subcommand)]
        cmd: Option<JobsCmd>,
    },
    /// Model Context Protocol server on stdio for AI agents (`claude mcp add meshvpn -- meshvpn mcp`).
    Mcp,
    /// Label this node (e.g. gpu, trainer) so it can be selected as tag:<name>.
    Tag {
        #[command(subcommand)]
        cmd: TagCmd,
    },
    /// Run a command on several nodes at once, e.g. `meshvpn exec tag:gpu -- nvidia-smi`.
    /// Uses the password-less SSH logins (`meshvpn ssh`) of the target nodes.
    Exec {
        /// Nodes: all, tag:<tag>, names (several add up).
        #[arg(required = true)]
        selectors: Vec<String>,
        /// The command (one argument = a shell command line, e.g. 'nvidia-smi | head').
        #[arg(last = true, required = true)]
        command: Vec<String>,
        /// Account on the target nodes (default: you).
        #[arg(long, short)]
        user: Option<String>,
        /// Give up on a node after this many seconds.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
        /// Only online nodes (skip offline ones instead of failing on them).
        #[arg(long)]
        online: bool,
    },
    /// Copy files to or from nodes, e.g. `meshvpn cp ./data tag:gpu:/srv/` or
    /// `meshvpn cp node1:/var/log/train.log ./logs`. The destination is a directory.
    Cp {
        /// Sources, then the destination. Remote: node:/path, tag:<tag>:/path, all:/path.
        #[arg(required = true, num_args = 2..)]
        paths: Vec<String>,
        #[arg(long, short)]
        user: Option<String>,
        #[arg(long, default_value_t = 3600)]
        timeout: u64,
        #[arg(long)]
        online: bool,
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
    /// The mesh in your terminal: all nodes, and shells on them as tabs (also plain `meshvpn`).
    Console {
        /// Account for the shells on other nodes (default: you).
        #[arg(short, long)]
        user: Option<String>,
    },
    /// A node's graphical desktop in your browser, e.g. `meshvpn desktop gpu-box` (also in
    /// containers without X: meshvpn brings its own). Logins as with `meshvpn ssh`.
    #[command(args_conflicts_with_subcommands = true)]
    Desktop {
        #[command(subcommand)]
        cmd: Option<DesktopCmd>,
        /// The node whose desktop to open.
        node: Option<String>,
        /// Account on the node (default: you).
        #[arg(short, long)]
        user: Option<String>,
        /// Local port for the viewer (default: any free one).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Only print the link, don't open a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Connect stdin/stdout to HOST:PORT in the mesh (for ssh's ProxyCommand in userspace mode).
    Nc { host: String, port: u16 },
    /// SFTP on stdin/stdout (started by the built-in SSH server as the logged-in user).
    #[command(hide = true)]
    SftpServer,
    /// Used by sshd (AuthorizedKeysCommand): prints the keys that may log in as USER.
    #[command(hide = true)]
    SshAuthorizedKeys { user: String },
    /// Give this node a new name (it becomes NAME.mesh everywhere; its IP and permissions stay).
    Rename {
        /// The new name (a-z, 0-9 and -).
        name: String,
    },
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
enum NetCmd {
    /// Latency, mesh throughput and direct LAN paths between nodes.
    Matrix {
        /// Which nodes (default: all).
        selectors: Vec<String>,
        /// Measure now (sends test data between the nodes) instead of showing the last results.
        #[arg(long)]
        measure: bool,
        /// Test data per pair in MB, with --measure.
        #[arg(long, default_value_t = 16)]
        mb: u64,
    },
    /// The best address to reach a node from here: its LAN address if both share one, else
    /// its mesh address.
    Route { node: String },
    /// Environment for distributed training on THIS node (run it on every node of the group):
    /// MASTER_ADDR, NODE_RANK, NCCL_SOCKET_IFNAME ... `eval $(meshvpn net env --master gpu1 tag:gpu)`
    Env {
        /// The nodes of the training job.
        #[arg(required = true)]
        selectors: Vec<String>,
        /// Rank 0 (default: the first node by name).
        #[arg(long)]
        master: Option<String>,
        #[arg(long, default_value_t = 29500)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum GpuCmd {
    /// GPUs of the nodes: free, busy or reserved (by whom, how long).
    List {
        /// Which nodes (default: all).
        selectors: Vec<String>,
    },
    /// Reserve GPUs: N on every selected node, or with --one on the single best node.
    /// The node with the GPUs grants it (over SSH for other nodes), so reservations never
    /// collide. Prints CUDA_VISIBLE_DEVICES per node.
    Reserve {
        #[arg(required = true)]
        selectors: Vec<String>,
        /// GPUs per node.
        #[arg(long, short = 'n', default_value_t = 1)]
        count: u32,
        /// Exactly these GPUs (e.g. 0,1) - one node only.
        #[arg(long, value_delimiter = ',')]
        gpus: Option<Vec<u32>>,
        /// How long (renew with `meshvpn gpu renew`), e.g. 30m, 2h, 1d.
        #[arg(long = "for", default_value = "2h")]
        duration: String,
        /// Pick the one node with the most free GPUs among the selected.
        #[arg(long)]
        one: bool,
        /// Who it is for (shown to others).
        #[arg(long)]
        note: Option<String>,
        #[arg(long, short)]
        user: Option<String>,
    },
    /// Release reservations.
    Release {
        #[arg(required = true)]
        ids: Vec<String>,
        #[arg(long, short)]
        user: Option<String>,
    },
    /// Extend reservations.
    Renew {
        #[arg(required = true)]
        ids: Vec<String>,
        #[arg(long = "for", default_value = "2h")]
        duration: String,
        #[arg(long, short)]
        user: Option<String>,
    },
    #[command(hide = true)]
    ReserveLocal {
        #[arg(long)]
        count: Option<u32>,
        #[arg(long, value_delimiter = ',')]
        gpus: Option<Vec<u32>>,
        #[arg(long)]
        ttl_ms: u64,
        #[arg(long)]
        holder: String,
    },
    #[command(hide = true)]
    ReleaseLocal { id: String },
    #[command(hide = true)]
    RenewLocal {
        id: String,
        #[arg(long)]
        ttl_ms: u64,
    },
}

#[derive(Subcommand)]
enum DesktopCmd {
    /// Install the desktop components on this machine (a static X server, keyboard layouts,
    /// fonts; about 5 MB). Happens by itself on first use if the machine has internet.
    Setup {
        /// Install from a downloaded meshvpn-desktop-<arch>.tar.gz (machines without internet).
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// End your desktop session on this machine (closes its applications).
    Stop,
    /// Connect stdin/stdout to your desktop session (used through SSH by `meshvpn desktop <node>`).
    #[command(hide = true)]
    Attach,
    /// Run the desktop session (started by attach).
    #[command(hide = true)]
    Session,
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Managed or open, who the admins are, who joined with which invite.
    Status,
    /// Make an existing open network managed, with this node as its admin. Every node known
    /// now stays a member; new nodes then need an invite from an admin.
    Enable,
    /// Make a node an admin.
    Add { node: String },
    /// Take admin rights away.
    Rm { node: String },
}

#[derive(Subcommand)]
enum JobsCmd {
    /// All jobs, newest first.
    List,
    /// A job's state, environment and the end of each node's log.
    Show {
        id: String,
        /// Lines per node.
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// The log of a job (all nodes, or one).
    Logs {
        id: String,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, default_value_t = 100)]
        tail: usize,
    },
    /// Stop a running job on all its nodes.
    Stop { id: String },
}

#[derive(Subcommand)]
enum TagCmd {
    /// Add tags to this node.
    Add { tags: Vec<String> },
    /// Remove tags from this node.
    Rm { tags: Vec<String> },
    /// Show this node's tags.
    List,
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
    /// Tags for this node (e.g. gpu,trainer), to select it as tag:<name>. Comma separated.
    #[arg(long = "tag", value_name = "TAG", value_delimiter = ',')]
    tags: Vec<String>,
    /// Run without a TUN device (for containers without NET_ADMIN). By default meshvpn
    /// switches to this mode by itself when no TUN device is available.
    #[arg(long)]
    userspace: bool,
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
    let json = cli.json;
    match real_main(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            let msg = format!("{e:#}");
            let code = exit_code(&msg);
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": msg, "code": code }));
            } else {
                eprintln!("error: {msg}");
            }
            std::process::exit(code);
        }
    }
}

/// Stable exit codes, so scripts and agents can tell failures apart.
fn exit_code(msg: &str) -> i32 {
    if msg.contains("is not running") {
        3
    } else if msg.contains("try again with sudo") || msg.contains("needs root") || msg.contains("permission denied") {
        4
    } else if msg.contains("no node")
        || msg.contains("no rule")
        || msg.contains("not found")
        || msg.contains("No such file")
    {
        5
    } else {
        1
    }
}

/// Prints a plain message, or `{"ok": true, "message": ...}` with --json.
fn say(json: bool, text: &str) {
    if json {
        println!("{}", serde_json::json!({ "ok": true, "message": text }));
    } else {
        println!("{text}");
    }
}

fn real_main(cli: Cli) -> Result<i32> {
    let dir = cli.dir.unwrap_or_else(config::default_dir);
    config::set_rootless(&dir);
    let json = cli.json;
    load_proxy_env(&dir);
    // Plain `meshvpn` in a terminal of a set-up machine: the console.
    let Some(cmd) = cli.cmd else {
        if unsafe { libc::isatty(1) } == 1 && Config::path(&dir).exists() {
            console::run(&dir, None)?;
        } else {
            use clap::CommandFactory;
            Cli::command().print_help()?;
        }
        return Ok(0);
    };
    match cmd {
        Cmd::Init { network, open, node } => {
            let key = keys::random32();
            let cfg = create(&dir, node, config::sanitize_name(&network), key, vec![])?;
            if !open {
                // Managed from the start: this node is the first admin.
                let ident = Identity::from_config(&cfg)?;
                let roster = proto::Roster {
                    net: cfg.network_id(),
                    version: 1,
                    admins: vec![ident.id],
                    members: vec![ident.id],
                    issuer: ident.id,
                    at: now_ms(),
                };
                let mut saved = SavedState::load(&dir);
                saved.roster = Some(proto::SignedDoc::sign(&roster, &ident));
                saved.save(&dir)?;
            }
            println!("Created network \"{}\".\n", cfg.network);
            print_node_summary(&cfg)?;
            print_invite(&dir, &cfg, 1, 24 * 3600 * 1000, false)?;
            enable_ssh_logins(&cfg);
            print_next_steps(&dir, &cfg);
        }
        Cmd::Join { invite, node } => {
            let inv = Invite::decode(&invite)?;
            check_invite_expiry(&inv)?;
            let key = keys::unb64_32(&inv.key)?;
            let mut cfg = create(&dir, node, inv.network, key, inv.bootstrap)?;
            cfg.network_id = inv.id;
            cfg.key_version = inv.v;
            cfg.trusted_admins = inv.admins;
            cfg.ticket = inv.ticket;
            cfg.save(&dir)?;
            println!("Joined network \"{}\".\n", cfg.network);
            print_node_summary(&cfg)?;
            println!("It will connect to: {}", cfg.bootstrap.join(", "));
            enable_ssh_logins(&cfg);
            print_next_steps(&dir, &cfg);
        }
        Cmd::Invite { uses, expires } => {
            let cfg = Config::load(&dir)?;
            print_invite(&dir, &cfg, uses, parse_duration_ms(&expires)?, json)?;
        }
        Cmd::Gpu { cmd } => return gpu_cmd(&dir, cmd, json),
        Cmd::Admin { cmd } => {
            let req = match cmd {
                AdminCmd::Status => control::Request::AdminStatus,
                AdminCmd::Enable => {
                    require_owner()?;
                    control::Request::AdminEnable
                }
                AdminCmd::Add { node } => {
                    require_owner()?;
                    control::Request::AdminChange { who: node, add: true }
                }
                AdminCmd::Rm { node } => {
                    require_owner()?;
                    control::Request::AdminChange { who: node, add: false }
                }
            };
            let status = matches!(req, control::Request::AdminStatus);
            if let control::Response::Message { text } =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))?
            {
                if !status {
                    say(json, &text);
                } else if json {
                    println!("{text}");
                } else {
                    let v: serde_json::Value = serde_json::from_str(&text)?;
                    if v["managed"] == true {
                        println!("managed network (roster v{})", v["version"]);
                        let admins: Vec<&str> = v["admins"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|a| a.as_str())
                            .collect();
                        println!("  admins:      {}", admins.join(", "));
                        println!(
                            "  this node:   {}",
                            if v["this_node_is_admin"] == true {
                                "admin"
                            } else {
                                "member"
                            }
                        );
                        println!("  members from before it became managed: {}", v["members_from_before"]);
                        for a in v["admitted_by_invite"].as_array().into_iter().flatten() {
                            println!(
                                "  joined by invite: {} (invited by {})",
                                a["node"].as_str().unwrap_or("?"),
                                a["invited_by"].as_str().unwrap_or("?")
                            );
                        }
                    } else {
                        println!("open network: everybody with the network key may invite and ban.");
                        println!(
                            "{}",
                            config::hint("make it managed (this node becomes admin): sudo meshvpn admin enable")
                        );
                    }
                }
            }
        }
        Cmd::Up => {
            let cfg = Config::load(&dir)?;
            init_logging();
            tokio::runtime::Runtime::new()?.block_on(node::run(dir, cfg))?;
        }
        Cmd::Nodes {
            selectors,
            online,
            free_gpus,
        } => {
            let all = agent::nodes(&agent::status(&dir)?);
            let sel = if selectors.is_empty() {
                vec!["all".to_string()]
            } else {
                selectors
            };
            let mut list = agent::select(&all, &sel)?;
            list.retain(|n| (!online || n.online) && free_gpus.is_none_or(|g| n.free_gpus() >= g));
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                agent::print_nodes(&list);
            }
        }
        Cmd::Net { cmd } => {
            let st = agent::status(&dir)?;
            let all = agent::nodes(&st);
            match cmd {
                NetCmd::Matrix { selectors, measure, mb } => {
                    let sel = if selectors.is_empty() {
                        vec!["all".to_string()]
                    } else {
                        selectors
                    };
                    let mut group = agent::select(&all, &sel)?;
                    if measure {
                        if !json {
                            eprintln!("measuring between {} nodes ({mb} MB per pair)...", group.len());
                        }
                        group = agent::measure(&dir, &group, mb)?;
                    }
                    let edges = agent::matrix(&group);
                    if json {
                        println!("{}", serde_json::to_string_pretty(&edges)?);
                    } else {
                        agent::print_matrix(&edges);
                    }
                }
                NetCmd::Route { node } => {
                    let to = agent::select(&all, &[node])?.remove(0);
                    let r = agent::route(&all[0], &to, st.socks.is_some());
                    if json {
                        println!("{}", serde_json::to_string_pretty(&r)?);
                    } else {
                        println!(
                            "{}: use {} ({})",
                            r.node,
                            r.best,
                            match (&r.lan_ip, &r.interface) {
                                (Some(_), Some(i)) => format!("direct LAN path via {i}"),
                                (Some(_), None) => "direct LAN path".into(),
                                (None, _) => format!("over the mesh, no shared LAN; mesh IP {}", r.mesh_ip),
                            }
                        );
                    }
                }
                NetCmd::Env {
                    selectors,
                    master,
                    port,
                } => {
                    let group = agent::select(&all, &selectors)?;
                    let master = match master {
                        Some(m) => agent::select(&all, &[m])?.remove(0),
                        None => group.iter().min_by_key(|n| n.name.clone()).unwrap().clone(),
                    };
                    let vars = agent::training_env(&all[0], &group, &master, port)?;
                    if json {
                        let map: serde_json::Map<String, serde_json::Value> = vars
                            .into_iter()
                            .map(|(k, v)| (k, serde_json::Value::String(v)))
                            .collect();
                        println!("{}", serde_json::Value::Object(map));
                    } else {
                        for (k, v) in vars {
                            println!("export {k}={}", agent::sh_quote(&v));
                        }
                    }
                }
            }
        }
        Cmd::Share { path, name } => {
            require_owner()?;
            let path = std::path::absolute(&path)?.to_string_lossy().into_owned();
            let req = control::Request::Share { path, name };
            if let control::Response::Message { text } =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))?
            {
                let v: serde_json::Value = serde_json::from_str(&text)?;
                if json {
                    println!("{v}");
                } else {
                    println!(
                        "shared {} ({} files, {}) as\n  {}\nfetch it on other nodes with: sudo meshvpn fetch {} <dir>",
                        v["name"].as_str().unwrap_or(""),
                        v["files"],
                        human_bytes(v["size"].as_u64().unwrap_or(0)),
                        v["id"].as_str().unwrap_or(""),
                        v["id"].as_str().unwrap_or("")
                    );
                }
            }
        }
        Cmd::Fetch { id, dest } => {
            require_owner()?;
            let dest = std::path::absolute(&dest)?.to_string_lossy().into_owned();
            let owner = std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok());
            if !json {
                eprintln!("fetching {id}...");
            }
            let req = control::Request::Fetch { id, dest, owner };
            if let control::Response::Message { text } =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))?
            {
                let v: serde_json::Value = serde_json::from_str(&text)?;
                if json {
                    println!("{v}");
                } else {
                    let from: Vec<String> = v["from"]
                        .as_object()
                        .map(|m| {
                            m.iter()
                                .map(|(k, b)| format!("{k} {}", human_bytes(b.as_u64().unwrap_or(0))))
                                .collect()
                        })
                        .unwrap_or_default();
                    println!(
                        "fetched {} into {}: {} in {:.1}s ({:.0} Mbit/s){}{}",
                        v["name"].as_str().unwrap_or(""),
                        v["dest"].as_str().unwrap_or(""),
                        human_bytes(v["bytes"].as_u64().unwrap_or(0)),
                        v["seconds"].as_f64().unwrap_or(0.0),
                        v["mbit_per_s"].as_f64().unwrap_or(0.0),
                        if from.is_empty() {
                            String::new()
                        } else {
                            format!(" from {}", from.join(", "))
                        },
                        match v["reused_bytes"].as_u64().unwrap_or(0) {
                            0 => String::new(),
                            r => format!(" ({} were already there)", human_bytes(r)),
                        }
                    );
                }
            }
        }
        Cmd::Unshare { id } => {
            require_owner()?;
            tokio::runtime::Runtime::new()?
                .block_on(control::request(&dir, &control::Request::Unshare { id: id.clone() }))?;
            say(json, &format!("no longer sharing {id}"));
        }
        Cmd::Objects => {
            let st = agent::status(&dir)?;
            let mut objects: Vec<(proto::ObjectAd, Vec<String>)> = vec![];
            for n in agent::nodes(&st) {
                let list = if n.is_self {
                    st.objects.clone()
                } else {
                    n.objects.clone()
                };
                for o in list {
                    match objects.iter_mut().find(|(x, _)| x.id == o.id) {
                        Some((_, holders)) => holders.push(n.name.clone()),
                        None => objects.push((o, vec![n.name.clone()])),
                    }
                }
            }
            if json {
                let v: Vec<serde_json::Value> = objects
                    .iter()
                    .map(|(o, h)| serde_json::json!({"id": o.id, "name": o.name, "size": o.size, "holders": h}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else if objects.is_empty() {
                println!(
                    "{}",
                    config::hint("Nothing shared yet - share a file or directory with: sudo meshvpn share <path>")
                );
            } else {
                println!("{:<32}  {:<24}  {:>9}  HOLDERS", "ID", "NAME", "SIZE");
                for (o, h) in objects {
                    println!(
                        "{:<32}  {:<24}  {:>9}  {}",
                        o.id,
                        o.name,
                        human_bytes(o.size),
                        h.join(", ")
                    );
                }
            }
        }
        Cmd::Mcp => mcp::serve(dir.clone())?,
        Cmd::Doctor => {
            let checks = doctor::diagnose(&dir);
            if json {
                println!("{}", serde_json::to_string_pretty(&checks)?);
            } else {
                doctor::print(&checks);
            }
            return Ok(if checks.iter().any(|c| c.level == doctor::Level::Fail) {
                1
            } else {
                0
            });
        }
        Cmd::Launch {
            selectors,
            command,
            master,
            port,
            user,
            workdir,
            keep_going,
            detach,
            job_dir,
            gpus,
        } => {
            let opts = launch::Opts {
                selectors: selectors.clone(),
                master: master.clone(),
                port,
                user: user.clone(),
                workdir: workdir.clone(),
                keep_going,
                command: command.clone(),
                gpus,
            };
            if detach {
                let mut args: Vec<String> = selectors;
                for (flag, v) in [("--master", master), ("--user", user), ("--workdir", workdir)] {
                    if let Some(v) = v {
                        args.extend([flag.to_string(), v]);
                    }
                }
                args.extend(["--port".to_string(), port.to_string()]);
                if keep_going {
                    args.push("--keep-going".into());
                }
                if let Some(g) = gpus {
                    args.extend(["--gpus".to_string(), g.to_string()]);
                }
                args.push("--".into());
                args.extend(command);
                let job = launch::detach(&dir, &args)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&job)?);
                } else {
                    println!(
                        "job {} started on {} (master {})",
                        job.id,
                        job.nodes.join(", "),
                        job.master
                    );
                    println!(
                        "  meshvpn jobs show {id}   meshvpn jobs logs {id}   meshvpn jobs stop {id}",
                        id = job.id
                    );
                }
                return Ok(0);
            }
            let quiet = job_dir.is_some();
            let job = launch::run(&dir, &opts, job_dir, quiet)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&job)?);
            } else if !quiet {
                for r in &job.results {
                    eprintln!(
                        "  {:<12} {} after {:.1}s",
                        r.node,
                        match r.exit_code {
                            Some(0) => "ok".to_string(),
                            Some(c) => format!("exit {c}"),
                            None => "killed".to_string(),
                        },
                        r.duration_s
                    );
                }
                eprintln!("job {}: {} - logs in {}", job.id, job.state, job.dir);
            }
            return Ok(match job.state.as_str() {
                "succeeded" => 0,
                "stopped" => 130,
                _ => 1,
            });
        }
        Cmd::Jobs { cmd } => match cmd.unwrap_or(JobsCmd::List) {
            JobsCmd::List => {
                let jobs = launch::Job::list();
                if json {
                    println!("{}", serde_json::to_string_pretty(&jobs)?);
                } else if jobs.is_empty() {
                    println!("No jobs yet - start one with: meshvpn launch <nodes> -- <command>");
                } else {
                    println!("{:<8}  {:<9}  {:<24}  COMMAND", "JOB", "STATE", "NODES");
                    for j in jobs {
                        println!(
                            "{:<8}  {:<9}  {:<24}  {}",
                            j.id,
                            j.state,
                            j.nodes.join(","),
                            j.command.join(" ")
                        );
                    }
                }
            }
            JobsCmd::Show { id, tail } => {
                let job = launch::Job::load(&id)?;
                let tails: serde_json::Map<String, serde_json::Value> = job
                    .nodes
                    .iter()
                    .map(|n| {
                        let log = Path::new(&job.dir).join(format!("{n}.log"));
                        (n.clone(), serde_json::Value::String(launch::tail(&log, tail)))
                    })
                    .collect();
                if json {
                    let mut v = serde_json::to_value(&job)?;
                    v["log_tail"] = serde_json::Value::Object(tails);
                    println!("{}", serde_json::to_string_pretty(&v)?);
                } else {
                    println!(
                        "job {}: {} on {} (master {})",
                        job.id,
                        job.state,
                        job.nodes.join(", "),
                        job.master
                    );
                    println!("command: {}", job.command.join(" "));
                    for r in &job.results {
                        println!("  {:<12} exit {:?} after {:.1}s", r.node, r.exit_code, r.duration_s);
                    }
                    for (n, t) in tails {
                        println!("── {n}\n{}", t.as_str().unwrap_or(""));
                    }
                }
            }
            JobsCmd::Logs { id, node, tail } => {
                let job = launch::Job::load(&id)?;
                for n in job.nodes.iter().filter(|n| node.as_ref().is_none_or(|x| x == *n)) {
                    let text = launch::tail(&Path::new(&job.dir).join(format!("{n}.log")), tail);
                    for line in text.lines() {
                        println!("[{n}] {line}");
                    }
                }
            }
            JobsCmd::Stop { id } => {
                let job = launch::stop(&id)?;
                say(json, &format!("job {} {}", job.id, job.state));
            }
        },
        Cmd::Tag { cmd } => {
            let (add, remove) = match cmd {
                TagCmd::Add { tags } => (tags, vec![]),
                TagCmd::Rm { tags } => (vec![], tags),
                TagCmd::List => {
                    let tags = agent::status(&dir)?.tags;
                    if json {
                        println!("{}", serde_json::json!({ "tags": tags }));
                    } else {
                        println!(
                            "{}",
                            if tags.is_empty() {
                                "(no tags)".into()
                            } else {
                                tags.join(" ")
                            }
                        );
                    }
                    return Ok(0);
                }
            };
            require_owner()?;
            let tags: Vec<String> = if control::is_running(&dir) {
                let req = control::Request::Tags { add, remove };
                match tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))? {
                    control::Response::Message { text } => {
                        text.split(',').filter(|t| !t.is_empty()).map(String::from).collect()
                    }
                    _ => bail!("unexpected answer from meshvpn"),
                }
            } else {
                let mut cfg = Config::load(&dir)?;
                if let Some(t) = add.iter().find(|t| !proto::valid_tag(t)) {
                    bail!("invalid tag {t:?} (use a-z, 0-9, - _ . =)");
                }
                cfg.tags.retain(|t| !remove.contains(t));
                for t in add {
                    if !cfg.tags.contains(&t) {
                        cfg.tags.push(t);
                    }
                }
                cfg.save(&dir)?;
                cfg.tags
            };
            if json {
                println!("{}", serde_json::json!({ "ok": true, "tags": tags }));
            } else {
                println!(
                    "tags: {}",
                    if tags.is_empty() {
                        "(none)".into()
                    } else {
                        tags.join(" ")
                    }
                );
            }
        }
        Cmd::Exec {
            selectors,
            command,
            user,
            timeout,
            online,
        } => {
            let st = agent::status(&dir)?;
            let mut targets = agent::select(&agent::nodes(&st), &selectors)?;
            if online {
                targets.retain(|n| n.online);
            }
            let remote = agent::Remote {
                user: user.unwrap_or_else(agent::Remote::default_user),
                socks: st.socks.is_some(),
                timeout: std::time::Duration::from_secs(timeout),
            };
            let results = agent::exec(&targets, &remote, &command);
            if json {
                println!("{}", serde_json::to_string_pretty(&agent::results_json(&results))?);
            } else {
                agent::print_results(&results, true);
            }
            return Ok(if results.iter().all(|r| r.ok) { 0 } else { 1 });
        }
        Cmd::Cp {
            mut paths,
            user,
            timeout,
            online,
        } => {
            let dest = paths.pop().unwrap();
            let st = agent::status(&dir)?;
            let all = agent::nodes(&st);
            let remote = agent::Remote {
                user: user.unwrap_or_else(agent::Remote::default_user),
                socks: st.socks.is_some(),
                timeout: std::time::Duration::from_secs(timeout),
            };
            let pick = |sel: &[String]| -> Result<Vec<agent::NodeView>> {
                let mut t = agent::select(&all, sel)?;
                if online {
                    t.retain(|n| n.online);
                }
                Ok(t)
            };
            let results = match agent::parse_place(&dest) {
                agent::Place::Remote(sel, dir_there) => {
                    let mut sources = vec![];
                    for p in &paths {
                        match agent::parse_place(p) {
                            agent::Place::Local(l) => sources.push(l),
                            agent::Place::Remote(..) => bail!("copy either to nodes or from nodes, not between them"),
                        }
                    }
                    agent::upload(&pick(&sel)?, &remote, &sources, &dir_there)?
                }
                agent::Place::Local(local) => {
                    if paths.len() != 1 {
                        bail!("download one remote path at a time");
                    }
                    match agent::parse_place(&paths[0]) {
                        agent::Place::Remote(sel, src) => agent::download(&pick(&sel)?, &remote, &src, &local)?,
                        agent::Place::Local(_) => bail!("both paths are local - use cp"),
                    }
                }
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&agent::results_json(&results))?);
            } else {
                agent::print_results(&results, false);
                let ok = results.iter().filter(|r| r.ok).count();
                println!("copied on {ok}/{} node(s)", results.len());
            }
            return Ok(if results.iter().all(|r| r.ok) { 0 } else { 1 });
        }
        Cmd::Status => {
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
            require_owner()?;
            tui::run(&dir)?;
        }
        Cmd::Ssh { cmd } => {
            let req = match cmd.unwrap_or(SshCmd::List) {
                SshCmd::Allow { who, users } if !control::is_running(&dir) => {
                    require_owner()?;
                    let msg = ssh_rules_offline(&dir, &who, users, true)?;
                    if let Err(e) = sshd::enable_if_installed() {
                        println!("note: sshd is not set up yet ({e:#}); meshvpn retries when it starts");
                    }
                    say(json, &msg);
                    return Ok(0);
                }
                SshCmd::Deny { who, users } if !control::is_running(&dir) => {
                    require_owner()?;
                    say(json, &ssh_rules_offline(&dir, &who, users, false)?);
                    return Ok(0);
                }
                SshCmd::Allow { who, users } => {
                    require_owner()?;
                    if sshd::enable_if_installed()? {
                        println!(
                            "Enabled password-less logins from mesh nodes in sshd ({}).",
                            sshd::DROPIN
                        );
                    }
                    control::Request::SshAllow { who, users }
                }
                SshCmd::Deny { who, users } => {
                    require_owner()?;
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
        Cmd::SftpServer => sshserver::sftp_server()?,
        Cmd::Console { user } => console::run(&dir, user)?,
        Cmd::Desktop {
            cmd,
            node,
            user,
            port,
            no_browser,
        } => match cmd {
            Some(DesktopCmd::Setup { from }) => {
                let b = desktop::bundle::setup(from.as_deref())?;
                say(json, &format!("desktop components installed in {}", b.dir.display()));
            }
            Some(DesktopCmd::Stop) => {
                if desktop::session::stop()? {
                    say(json, "desktop session ended");
                } else {
                    say(json, "no desktop session is running");
                }
            }
            Some(DesktopCmd::Attach) => desktop::session::attach()?,
            Some(DesktopCmd::Session) => {
                init_logging();
                desktop::session::run()?;
            }
            None => {
                let Some(node) = node else {
                    bail!("which node? e.g. meshvpn desktop <node> (see meshvpn nodes)");
                };
                if std::env::var_os("MESHVPN_DESKTOP_BRIDGE").is_some() {
                    let target = desktop::client::Target::test(&node, user.as_deref());
                    desktop::client::run(target, port, !no_browser)?;
                    return Ok(0);
                }
                let st = agent::status(&dir)?;
                let targets = agent::select(&agent::nodes(&st), &[node])?;
                let [node] = <[agent::NodeView; 1]>::try_from(targets)
                    .map_err(|_| anyhow::anyhow!("select exactly one node"))?;
                let remote = agent::Remote {
                    user: user.unwrap_or_else(agent::Remote::default_user),
                    socks: st.socks.is_some(),
                    timeout: std::time::Duration::from_secs(30),
                };
                desktop::client::run(desktop::client::Target { node, remote }, port, !no_browser)?;
            }
        },
        Cmd::Nc { host, port } => {
            let rt = tokio::runtime::Runtime::new()?;
            // Through the userspace stack if meshvpn runs in that mode, directly otherwise.
            let socks = match rt.block_on(control::request(&dir, &control::Request::Status)) {
                Ok(control::Response::Status(st)) => st.socks,
                _ => None,
            };
            rt.block_on(async {
                match socks {
                    Some(proxy) => userspace::netcat(&proxy, &host, port).await,
                    None => {
                        let s = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                        let (mut r, mut w) = s.into_split();
                        let up = async {
                            let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut w).await;
                            let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
                        };
                        let down = async {
                            let _ = tokio::io::copy(&mut r, &mut tokio::io::stdout()).await;
                        };
                        tokio::join!(up, down);
                        Ok(())
                    }
                }
            })?;
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
        Cmd::Rename { name } => {
            require_owner()?;
            if control::is_running(&dir) {
                let req = control::Request::Rename { name };
                if let control::Response::Message { text } =
                    tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))?
                {
                    say(json, &text);
                }
            } else {
                // Not running: just change the config; the name goes out at the next start.
                let mut cfg = Config::load(&dir)?;
                let new = config::sanitize_name(&name);
                if new == cfg.name {
                    bail!("this node is already called {new}");
                }
                let net = cfg.network_id();
                let peers: Vec<String> = SavedState::load(&dir)
                    .peers
                    .iter()
                    .filter_map(|p| p.verify(&net).ok())
                    .map(|i| i.name)
                    .collect();
                node::check_name_free(&new, peers.iter())?;
                let old = std::mem::replace(&mut cfg.name, new.clone());
                cfg.save(&dir)?;
                println!("renamed {old} -> {new} (meshvpn is not running; the new name is announced when it starts)");
            }
        }
        Cmd::Ban { who } => {
            let resp =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &control::Request::Ban { who }))?;
            if let control::Response::Message { text } = resp {
                say(json, &text);
            }
        }
        Cmd::Forget { who, offline: _ } => {
            let resp =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &control::Request::Forget { who }))?;
            if let control::Response::Message { text } = resp {
                say(json, &text);
            }
        }
        Cmd::Update { check, force } => update_cmd(&dir, check, force, json)?,
        Cmd::Install => install(&dir)?,
        Cmd::Uninstall => uninstall(&dir)?,
    }
    Ok(0)
}

/// systemd and sudo start meshvpn without the user's proxy variables, so install.sh saves the
/// system's proxy in `<dir>/proxy.env`. Variables that are already set win.
fn load_proxy_env(dir: &Path) {
    const VARS: &[&str] = &["https_proxy", "http_proxy", "all_proxy", "no_proxy"];
    let Ok(text) = std::fs::read_to_string(dir.join("proxy.env")) else {
        return;
    };
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim().trim_matches('"'));
        if !VARS.contains(&key) || value.is_empty() {
            continue;
        }
        let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        if !set(key) && !set(&key.to_uppercase()) {
            // Still single-threaded here: no other thread reads the environment yet.
            unsafe { std::env::set_var(key, value) };
        }
    }
}

fn human_bytes(b: u64) -> String {
    match b {
        0..1_000_000 => format!("{:.0} kB", b as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} MB", b as f64 / 1e6),
        _ => format!("{:.2} GB", b as f64 / 1e9),
    }
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
    if o.userspace {
        cfg.userspace = config::Userspace::Always;
    }
    if let Some(t) = o.tags.iter().find(|t| !proto::valid_tag(t)) {
        bail!("--tag: invalid tag {t:?} (use a-z, 0-9, - _ . =)");
    }
    cfg.tags = o.tags;
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
    match sshd::enable_if_installed() {
        Ok(false) if config::rootless() || !sshserver::sshd_installed() => println!(
            "Password-less SSH logins from mesh nodes go to meshvpn's built-in SSH server{}.\n",
            if config::rootless() { " (as this user only)" } else { "" }
        ),
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
        println!(
            "{}",
            config::hint("  sudo meshvpn install   # restarts the service (or the background daemon)")
        );
        println!("  (or stop `meshvpn up` with Ctrl+C and start it again)");
        println!();
    }
    println!("Next steps:");
    println!("  {:<22} # run now, in the foreground", config::hint("sudo meshvpn up"));
    println!(
        "  {:<22} # or: run in the background, also after reboot",
        config::hint("sudo meshvpn install")
    );
    println!("  {:<22} # see who is connected", "meshvpn status");
    if config::rootless() {
        println!();
        println!("Rootless install (config in {}):", dir.display());
        println!("  - mesh nodes reach the services listening on this machine");
        println!("  - ssh user@<node>.mesh works directly (via ~/.ssh/config)");
        println!(
            "  - other programs reach the mesh through socks5h://{}",
            cfg.socks_listen
        );
        println!(
            "    e.g. ALL_PROXY=socks5h://{} curl http://<node>.mesh:8080",
            cfg.socks_listen
        );
    }
    if let Some(t) = &cfg.ssh_tunnel {
        println!();
        println!("SSH tunnel notes:");
        println!(
            "  - `{}ssh -p {} {}` must work without a password (as {}, or pass --ssh-identity).",
            if config::rootless() { "" } else { "sudo " },
            t.port,
            t.server,
            if config::rootless() { "this user" } else { "root" }
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

fn make_invite(dir: &Path, cfg: &Config, uses: u32, valid_ms: u64) -> Result<Invite> {
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

    let (ticket, admins) = invite_ticket(dir, cfg, uses, valid_ms)?;
    Ok(Invite {
        network: cfg.network.clone(),
        key: cfg.network_key.clone(),
        bootstrap: boot,
        id: cfg.network_id(),
        v: cfg.key_version,
        ticket,
        admins,
    })
}

fn gpu_cmd(dir: &Path, cmd: GpuCmd, json: bool) -> Result<i32> {
    // Run on the GPU node itself (over SSH from other nodes): always JSON.
    let local = |req: control::Request| -> Result<i32> {
        let rt = tokio::runtime::Runtime::new()?;
        if let control::Response::Message { text } = rt.block_on(control::request(dir, &req))? {
            println!("{text}");
        }
        Ok(0)
    };
    match cmd {
        GpuCmd::ReserveLocal {
            count,
            gpus,
            ttl_ms,
            holder,
        } => {
            return local(control::Request::GpuReserve {
                count,
                indices: gpus,
                ttl_ms,
                holder,
            });
        }
        GpuCmd::ReleaseLocal { id } => return local(control::Request::GpuRelease { id }),
        GpuCmd::RenewLocal { id, ttl_ms } => return local(control::Request::GpuRenew { id, ttl_ms }),
        _ => {}
    }
    let st = agent::status(dir)?;
    let all = agent::nodes(&st);
    let remote = |user: Option<String>| agent::Remote {
        user: user.unwrap_or_else(agent::Remote::default_user),
        socks: st.socks.is_some(),
        timeout: std::time::Duration::from_secs(60),
    };
    let grants: Vec<gpu::Grant> = match cmd {
        GpuCmd::List { selectors } => {
            let sel = if selectors.is_empty() {
                vec!["all".to_string()]
            } else {
                selectors
            };
            let rows = gpu::rows(&agent::select(&all, &sel)?);
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                gpu::print_rows(&rows);
            }
            return Ok(0);
        }
        GpuCmd::Reserve {
            selectors,
            count,
            gpus,
            duration,
            one,
            note,
            user,
        } => {
            let ttl = parse_duration_ms(&duration)?;
            let holder = gpu::default_holder(note.as_deref());
            let mut nodes = agent::select(&all, &selectors)?;
            nodes.retain(|n| n.online);
            if one || gpus.is_some() {
                nodes.sort_by_key(|n| std::cmp::Reverse(n.free_gpus()));
                let n = nodes
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("no node of the selection is online"))?;
                if gpus.is_none() && n.free_gpus() < count as usize {
                    bail!(
                        "no node of the selection has {count} free GPU(s) (most: {} on {})",
                        n.free_gpus(),
                        n.name
                    );
                }
                vec![gpu::reserve_on(
                    dir,
                    n,
                    &remote(user),
                    count,
                    gpus.as_deref(),
                    ttl,
                    &holder,
                )?]
            } else {
                gpu::reserve_all(dir, &nodes, &remote(user), count, ttl, &holder)?
            }
        }
        GpuCmd::Release { ids, user } => {
            let mut out = vec![];
            for id in ids {
                let n = gpu::find_lease(&all, &id)?;
                out.push(gpu::release_on(dir, n, &remote(user.clone()), &id)?);
            }
            out
        }
        GpuCmd::Renew { ids, duration, user } => {
            let ttl = parse_duration_ms(&duration)?;
            let mut out = vec![];
            for id in ids {
                let n = gpu::find_lease(&all, &id)?;
                out.push(gpu::renew_on(dir, n, &remote(user.clone()), &id, ttl)?);
            }
            out
        }
        _ => unreachable!(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&grants)?);
    } else {
        for g in &grants {
            println!(
                "{}: GPUs {} - reservation {} until {} min from now  (CUDA_VISIBLE_DEVICES={})",
                g.node,
                g.cuda_visible_devices,
                g.lease.id,
                g.lease.expires.saturating_sub(gpu::now_ms()) / 60_000,
                g.cuda_visible_devices
            );
        }
    }
    Ok(0)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// `30m`, `24h`, `7d` or seconds.
pub(crate) fn parse_duration_ms(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid duration {s:?} (e.g. 30m, 24h, 7d)"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => bail!("invalid duration {s:?} (e.g. 30m, 24h, 7d)"),
    };
    Ok(secs * 1000)
}

/// In a managed network: a ticket signed by this node, which must be an admin.
fn invite_ticket(
    dir: &Path,
    cfg: &Config,
    uses: u32,
    valid_ms: u64,
) -> Result<(Option<proto::SignedDoc>, Vec<keys::NodeId>)> {
    if control::is_running(dir) {
        let req = control::Request::IssueTicket { uses, valid_ms };
        let control::Response::Message { text } =
            tokio::runtime::Runtime::new()?.block_on(control::request(dir, &req))?
        else {
            bail!("unexpected answer from meshvpn");
        };
        let v: serde_json::Value = serde_json::from_str(&text)?;
        return Ok((
            serde_json::from_value(v["ticket"].clone())?,
            serde_json::from_value(v["admins"].clone())?,
        ));
    }
    // Not running: sign it ourselves, if the saved roster says we are an admin.
    let Some(signed) = SavedState::load(dir).roster else {
        return Ok((None, vec![]));
    };
    let roster: proto::Roster = signed.open(|r: &proto::Roster| r.issuer)?;
    let ident = Identity::from_config(cfg)?;
    if !roster.admins.contains(&ident.id) {
        bail!("only admins can invite in this managed network (see meshvpn admin status)");
    }
    let mut id = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    let ticket = proto::Ticket {
        net: cfg.network_id(),
        id: id.iter().map(|b| format!("{b:02x}")).collect(),
        expires: now_ms() + valid_ms,
        uses: uses.max(1),
        issuer: ident.id,
    };
    Ok((Some(proto::SignedDoc::sign(&ticket, &ident)), roster.admins))
}

/// `meshvpn ssh allow/deny` while meshvpn is not running (e.g. in a Dockerfile before the first
/// start): edits the rules in the config; nodes are looked up among the ones known from the
/// last run.
fn ssh_rules_offline(dir: &Path, who: &str, users: Vec<String>, allow: bool) -> Result<String> {
    if let Some(u) = users.iter().find(|u| !proto::valid_user(u)) {
        bail!("invalid user name {u:?}");
    }
    let mut cfg = Config::load(dir)?;
    if node::is_everyone(who) {
        if allow {
            if users.is_empty() {
                bail!("say which account: --as <user>");
            }
            for u in &users {
                if !cfg.ssh_allow_all.contains(u) {
                    cfg.ssh_allow_all.push(u.clone());
                }
            }
        } else if users.is_empty() {
            cfg.ssh_allow_all.clear();
        } else {
            cfg.ssh_allow_all.retain(|u| !users.contains(u));
        }
        cfg.save(dir)?;
        return Ok(if allow {
            format!(
                "every node of the network may log in here as {} without a password (takes effect when meshvpn starts)",
                users.join(", ")
            )
        } else {
            "updated password-less logins for everyone (takes effect when meshvpn starts)".into()
        });
    }
    let (from_user, node) = match who.split_once('@') {
        Some((u, n)) => (Some(u.to_string()), n.trim().to_lowercase()),
        None => (None, who.trim().to_lowercase()),
    };
    if let Some(u) = &from_user
        && !proto::valid_user(u)
    {
        bail!("invalid user name {u:?}");
    }
    if !allow {
        let before = cfg.ssh_allow.clone();
        for r in cfg
            .ssh_allow
            .iter_mut()
            .filter(|r| (r.name == node || r.node.hex().starts_with(&node)) && r.from_user == from_user)
        {
            if users.is_empty() {
                r.users.clear();
            } else {
                r.users.retain(|u| !users.contains(u));
            }
        }
        cfg.ssh_allow.retain(|r| !r.users.is_empty());
        if cfg.ssh_allow == before {
            bail!("no rule for {who} (see meshvpn ssh list)");
        }
        cfg.save(dir)?;
        return Ok(format!(
            "updated the rules for {who} (takes effect when meshvpn starts)"
        ));
    }
    if users.is_empty() {
        bail!("say which account: --as <user>");
    }
    // Nodes known from the last run, newest record first for duplicate names.
    let net = cfg.network_id();
    let mut known: Vec<proto::NodeInfo> = SavedState::load(dir)
        .peers
        .iter()
        .filter_map(|p| p.verify(&net).ok())
        .filter(|i| i.name == node || (node.len() >= 4 && i.id.hex().starts_with(&node)))
        .collect();
    known.sort_by_key(|i| std::cmp::Reverse(i.seq));
    let Some(info) = known.first() else {
        bail!(
            "meshvpn doesn't know a node named {node:?} yet - it learns the other nodes once it runs. Start it \
             first (meshvpn up / install), or allow every node: meshvpn ssh allow everyone --as {}",
            users.join(",")
        );
    };
    match cfg
        .ssh_allow
        .iter_mut()
        .find(|r| r.node == info.id && r.from_user == from_user)
    {
        Some(rule) => {
            for u in &users {
                if !rule.users.contains(u) {
                    rule.users.push(u.clone());
                }
            }
            rule.name = info.name.clone();
        }
        None => cfg.ssh_allow.push(config::SshAllow {
            node: info.id,
            name: info.name.clone(),
            from_user: from_user.clone(),
            users: users.clone(),
        }),
    }
    cfg.save(dir)?;
    let src = from_user
        .map(|u| format!("{u}@{}", info.name))
        .unwrap_or_else(|| format!("any user on {}", info.name));
    Ok(format!(
        "{src} may log in here as {} without a password (takes effect when meshvpn starts)",
        users.join(", ")
    ))
}

/// An expired invite is refused right away instead of producing a node that can't connect.
fn check_invite_expiry(inv: &Invite) -> Result<()> {
    let Some(ticket) = &inv.ticket else {
        return Ok(()); // open network: invites don't expire
    };
    let ticket = ticket
        .open::<proto::Ticket>(|t| t.issuer)
        .context("the invite is damaged (its admission ticket doesn't verify)")?;
    let now = now_ms();
    if now > ticket.expires {
        bail!(
            "this invite expired {} ago - ask an admin for a new one (meshvpn invite on an admin node; \
             --expires 7d for a longer one). If that seems wrong, check this machine's clock.",
            ago(now - ticket.expires)
        );
    }
    Ok(())
}

fn ago(ms: u64) -> String {
    let m = ms / 60_000;
    match m {
        0 => "less than a minute".into(),
        1..120 => format!("{m} min"),
        120..2880 => format!("{} h", m / 60),
        _ => format!("{} days", m / 1440),
    }
}

fn print_invite(dir: &Path, cfg: &Config, uses: u32, valid_ms: u64, json: bool) -> Result<()> {
    let inv = make_invite(dir, cfg, uses, valid_ms)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "invite": inv.encode(),
                "managed": inv.ticket.is_some(),
                "uses": inv.ticket.as_ref().map(|_| uses),
                "expires_ms": inv.ticket.as_ref().map(|_| now_ms() + valid_ms),
            })
        );
        return Ok(());
    }
    let boot = &inv.bootstrap;
    match &inv.ticket {
        Some(_) => println!(
            "Invite code - good for {} new node(s), valid for {} (treat it like a password):\n",
            uses.max(1),
            human_duration(valid_ms)
        ),
        None => println!("Invite code (treat it like a password - it grants access to the network):\n"),
    }
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
    Ok(())
}

fn human_duration(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..120 => format!("{s} seconds"),
        120..7200 => format!("{} minutes", s / 60),
        7200..172800 => format!("{} hours", s / 3600),
        _ => format!("{} days", s / 86400),
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
        println!(
            "  \x1b[1;36mupdate:\x1b[0m meshvpn {v} is available - run: {}",
            config::hint("sudo meshvpn update")
        );
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
    if let Some(s) = &st.socks {
        println!("  mode:         userspace (no TUN device) - programs reach the mesh via socks5h://{s}");
    }
    if st.ssh_server.as_deref() == Some("built-in") {
        println!(
            "  ssh server:   built-in (ssh <user>@{}.mesh, logins: meshvpn ssh list)",
            st.name
        );
    }
    if let Some(t) = &st.turned_away {
        println!("  \x1b[1;31mnot admitted:\x1b[0m {t}");
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

fn update_cmd(dir: &Path, check: bool, force: bool, json: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    // A running daemon does it itself: it knows the way out (e.g. the SSH tunnel) and restarts.
    if control::is_running(dir) {
        let req = control::Request::Update {
            check_only: check,
            force,
        };
        if let control::Response::Message { text } = rt.block_on(control::request(dir, &req))? {
            say(json, &text);
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
        if config::rootless() {
            bail!("this needs root (it changes the system, which a rootless install can't) - try again with sudo");
        }
        bail!("this needs root - try again with sudo");
    }
    Ok(())
}

/// Root, or the user owning a rootless install.
fn require_owner() -> Result<()> {
    if config::rootless() {
        return Ok(());
    }
    require_root()
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
    if config::rootless() {
        return install_user(dir);
    }
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
    if !systemd_running() {
        for (pid, cmd) in stop_other_daemons() {
            println!("Stopped a meshvpn that was already running (pid {pid}: {cmd}).");
        }
        return install_background(&dir, &bin, Path::new("/var/log/meshvpn.log"));
    }
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
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            continue; // another user's (rootless) meshvpn
        }
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

fn uninstall(dir: &Path) -> Result<()> {
    if config::rootless() {
        return uninstall_user(dir);
    }
    require_root()?;
    if systemd_running() {
        let _ = systemctl(&["disable", "--now", "meshvpn"]);
    } else {
        remove_cron_entry();
        for (pid, cmd) in stop_other_daemons() {
            println!("Stopped meshvpn (pid {pid}: {cmd}).");
        }
    }
    sshd::disable();
    node::remove_ssh_client_config();
    std::fs::remove_file(UNIT_PATH).ok();
    let _ = systemctl(&["daemon-reload"]);
    println!("meshvpn service removed (configuration kept).");
    Ok(())
}

const CRON_MARK: &str = "# meshvpn rootless";

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is not set"))
}

fn user_unit_path() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(x) => PathBuf::from(x),
        None => home()?.join(".config"),
    };
    Ok(base.join("systemd/user/meshvpn.service"))
}

/// A systemd user manager this process can talk to (not in most containers).
fn user_systemd() -> bool {
    systemd_running()
        && std::process::Command::new("systemctl")
            .args(["--user", "show-environment"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

fn remove_cron_entry() {
    if let Some(lines) = crontab_lines() {
        let before = std::process::Command::new("crontab")
            .arg("-l")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(CRON_MARK))
            .unwrap_or(false);
        if before {
            let _ = set_crontab(&lines);
        }
    }
}

fn crontab_lines() -> Option<Vec<String>> {
    let out = std::process::Command::new("crontab").arg("-l").output().ok()?;
    // "no crontab for user" is an empty one; a missing crontab binary is None.
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.contains(CRON_MARK))
            .map(String::from)
            .collect(),
    )
}

fn set_crontab(lines: &[String]) -> Result<()> {
    use std::io::Write as _;
    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("running crontab")?;
    let mut text = lines.join("\n");
    text.push('\n');
    child.stdin.take().unwrap().write_all(text.as_bytes())?;
    if !child.wait()?.success() {
        bail!("crontab failed");
    }
    Ok(())
}

/// `meshvpn install` without root: a systemd user service, or where there is none (containers)
/// a background daemon plus an @reboot crontab entry.
fn install_user(dir: &Path) -> Result<()> {
    Config::load(dir)?;
    let home = home()?;
    let exe = std::env::current_exe()?.canonicalize()?;
    let permanent = [
        Path::new("/usr"),
        Path::new("/opt"),
        &home.join(".local/bin"),
        &home.join("bin"),
    ];
    let bin = if permanent.iter().any(|p| exe.starts_with(p)) {
        exe
    } else {
        let bin = home.join(".local/bin/meshvpn");
        std::fs::create_dir_all(bin.parent().unwrap())?;
        std::fs::copy(&exe, &bin).with_context(|| format!("copying binary to {}", bin.display()))?;
        bin
    };
    let dir = std::path::absolute(dir)?;
    for (pid, cmd) in stop_other_daemons() {
        println!("Stopped a meshvpn that was already running (pid {pid}: {cmd}).");
    }
    if user_systemd() {
        let unit_path = user_unit_path()?;
        std::fs::create_dir_all(unit_path.parent().unwrap())?;
        let unit = format!(
            "[Unit]\nDescription=meshvpn decentralized mesh VPN (rootless)\n\n\
             [Service]\nExecStart={} --dir {} up\nRestart=always\nRestartSec=3\n\n\
             [Install]\nWantedBy=default.target\n",
            bin.display(),
            dir.display()
        );
        std::fs::write(&unit_path, unit)?;
        systemctl(&["--user", "daemon-reload"])?;
        systemctl(&["--user", "enable", "meshvpn"])?;
        systemctl(&["--user", "restart", "meshvpn"])?;
        std::thread::sleep(std::time::Duration::from_secs(2));
        let active = std::process::Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", "meshvpn"])
            .status()
            .is_ok_and(|s| s.success());
        if !active {
            bail!("the meshvpn user service did not start - see: journalctl --user -u meshvpn -n 20");
        }
        // Without lingering, user services only run while the user is logged in.
        let user = agent::Remote::default_user();
        let linger = std::process::Command::new("loginctl")
            .args(["show-user", &user, "-p", "Linger", "--value"])
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "yes")
            || std::process::Command::new("loginctl")
                .args(["--no-ask-password", "enable-linger", &user])
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
        println!("meshvpn is running as a user service (no root needed).");
        if linger {
            println!("  It starts at boot, also when you are not logged in.");
        } else {
            println!("  It runs while you are logged in. To start it at boot, an admin can run:");
            println!("    sudo loginctl enable-linger {user}");
        }
        println!("  status: meshvpn status   logs: journalctl --user -u meshvpn -f");
        return Ok(());
    }
    // No systemd for this user: start it in the background and again after reboot via cron.
    install_background(&dir, &bin, &dir.join("meshvpn.log"))
}

/// systemd is running here (not just installed: in containers `systemctl` exists but only
/// prints "Running in chroot, ignoring command").
pub fn systemd_running() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// Without systemd: start the daemon in the background now and, where cron exists, at boot.
fn install_background(dir: &Path, bin: &Path, log: &Path) -> Result<()> {
    let cmd = format!("{} --dir {} up", bin.display(), dir.display());
    let out = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
    let mut c = std::process::Command::new(bin);
    c.arg("--dir")
        .arg(dir)
        .arg("up")
        .stdin(std::process::Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out);
    unsafe {
        use std::os::unix::process::CommandExt;
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    c.spawn().context("starting meshvpn")?;
    let mut running = false;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if control::is_running(dir) {
            running = true;
            break;
        }
    }
    if !running {
        bail!("meshvpn did not start - see {}", log.display());
    }
    println!(
        "meshvpn is running in the background (no systemd here). Log: {}",
        log.display()
    );
    let in_container = userspace::in_container();
    let cron = crontab_lines().filter(|_| !in_container).map(|mut lines| {
        lines.push(format!("@reboot {cmd} >> {} 2>&1 {CRON_MARK}", log.display()));
        set_crontab(&lines)
    });
    match cron {
        Some(Ok(())) => println!("  It starts again at boot (crontab @reboot)."),
        _ if in_container => {
            println!("  In a container, start it together with the container: add this to its entrypoint");
            println!("    {cmd} &");
        }
        _ => println!(
            "  It does not start by itself after a reboot (no systemd or cron here): run `meshvpn install` again."
        ),
    }
    println!("  status: meshvpn status   stop: meshvpn uninstall");
    Ok(())
}

fn uninstall_user(dir: &Path) -> Result<()> {
    if let Ok(unit) = user_unit_path()
        && unit.exists()
    {
        let _ = systemctl(&["--user", "disable", "--now", "meshvpn"]);
        std::fs::remove_file(&unit).ok();
        let _ = systemctl(&["--user", "daemon-reload"]);
    }
    remove_cron_entry();
    for (pid, cmd) in stop_other_daemons() {
        println!("Stopped meshvpn (pid {pid}: {cmd}).");
    }
    node::user_ssh_config(dir, false);
    println!(
        "meshvpn stopped and removed from autostart (configuration kept in {}).",
        dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    #[test]
    fn say_prints_both_ways() {
        // say() once called itself for plain output (v0.5.0): every message hung.
        say(false, "plain");
        say(true, "json");
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

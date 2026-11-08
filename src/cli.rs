//! The `meshvpn` command line.

use crate::*;
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use config::{Config, DEFAULT_PORT, DEFAULT_SOCKS_PORT, Invite, SavedState, SshTunnel};
use keys::{Identity, overlay_ip};

/// A decentralized mesh VPN. No coordination server: nodes find each other by gossip,
/// relay for each other, and can live behind a reverse SSH tunnel.
#[derive(Parser)]
#[command(
    version,
    about,
    long_about = None,
    after_help = "AI agents: run `meshvpn guide` first - how to work with the network, and what is in it right now."
)]
struct Cli {
    /// Directory holding config and state [default: /etc/meshvpn as root, else
    /// ~/.config/meshvpn for a rootless install, or /etc/meshvpn if only that exists].
    #[arg(long, global = true, env = "MESHVPN_DIR")]
    dir: Option<PathBuf>,
    /// Which of this machine's networks a command is for, when it's in several (`meshvpn
    /// networks`). Commands find a node's network by themselves; this is for the rest.
    #[arg(long, global = true, env = "MESHVPN_NET", value_name = "NAME")]
    net: Option<String>,
    /// Machine readable output (JSON on stdout, also for errors). Exit codes: 0 ok, 1 error,
    /// 2 usage, 3 meshvpn not running, 4 needs root, 5 node/rule not found.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum NetworksCmd {
    /// Leave a network (also the first one): the others forget this node, meshvpn stops for it
    /// here and its configuration is removed.
    Leave {
        /// The network (as `meshvpn networks` lists it).
        name: String,
        /// Don't ask.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// The networks this machine is in. To be in another one too, join it: `meshvpn join <invite>`.
    Networks {
        #[command(subcommand)]
        cmd: Option<NetworksCmd>,
    },
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
        /// For a user's computer: a client (not a node), a member for --client-for only.
        #[arg(long, value_name = "USER")]
        client: Option<String>,
        /// How long the client stays a member (with --client).
        #[arg(long, default_value = "12h")]
        client_for: String,
    },
    /// Exit nodes: send this machine's internet traffic through another node, or offer this
    /// node's internet connection to the network.
    Exit {
        #[command(subcommand)]
        cmd: ExitCmd,
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
    Up {
        /// Write the log to FILE instead of the terminal (services without one, e.g. on Windows).
        #[arg(long, value_name = "FILE")]
        log_file: Option<PathBuf>,
    },
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
    /// Connect the network to a node at HOST[:PORT] that can't reach it by itself, e.g. a node on
    /// the internet when the others are behind a firewall (run this on one of them), or a
    /// firewalled node's reverse tunnel port. Remembered across restarts.
    #[command(alias = "add-peer")]
    Connect {
        /// HOST or HOST:PORT (default port 7870).
        addr: String,
    },
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
    /// How to work with meshvpn, for AI agents: the rules, the commands, and the network right now.
    /// `--skill` prints it as a Claude Code skill (save as ~/.claude/skills/meshvpn/SKILL.md).
    Guide {
        #[arg(long)]
        skill: bool,
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
        /// Which desktop: xfce, mate or cinnamon (installed on the node with `meshvpn desktop setup
        /// --desktop`), or plain (meshvpn's built-in minimal one). Default: the node's choice.
        #[arg(long, value_parser = ["xfce", "mate", "cinnamon", "plain"], conflicts_with_all = ["xfce", "plain", "screen"])]
        session: Option<String>,
        /// Same as --session xfce.
        #[arg(long, conflicts_with = "plain")]
        xfce: bool,
        /// Same as --session plain.
        #[arg(long, conflicts_with = "screen")]
        plain: bool,
        /// Share the node's own screen instead: the desktop you are logged in to at that machine,
        /// with its windows as they are (X11 only; visible there while shared).
        #[arg(long, conflicts_with = "xfce")]
        screen: bool,
    },
    /// Connect stdin/stdout to HOST:PORT in the mesh (for ssh's ProxyCommand in userspace mode).
    Nc { host: String, port: u16 },
    /// SFTP on stdin/stdout (started by the built-in SSH server as the logged-in user).
    #[command(hide = true)]
    SftpServer,
    /// A port forward of the built-in SSH server: stdin/stdout to HOST:PORT, connected as the
    /// logged-in user (not as the daemon).
    #[command(hide = true)]
    ForwardTcp { host: String, port: u16 },
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
    /// Find nodes again whose address changed through BitTorrent's Mainline DHT (encrypted, only
    /// members can read it): `on`, `off`, or without an argument what it is now. Restarts meshvpn.
    Dht {
        #[arg(value_parser = ["on", "off"])]
        state: Option<String>,
    },
    /// Install and start a systemd service so the VPN runs at boot (one per network: all of
    /// this machine's networks, or the one of --net).
    Install,
    /// Stop and remove the systemd service (of all networks, or the one of --net).
    Uninstall,
    /// Restart meshvpn's service, the same on Linux, macOS and Windows (all of this machine's
    /// networks, or the one of --net), e.g. after changing its configuration.
    Restart,
    /// Leave this network (or the one of --net): the other nodes forget this one, meshvpn stops
    /// for it here and its configuration and keys are removed. An admin makes another node
    /// admin first (meshvpn admin add <node>), unless there is one already.
    Leave {
        /// Don't ask.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Tab completion for bash (`meshvpn install` sets it up; zsh: `autoload bashcompinit;
    /// bashcompinit; source <(meshvpn completion bash)`).
    Completion {
        #[arg(value_parser = ["bash"])]
        shell: String,
    },
    /// What the completion script asks: candidates for the word at POINT of LINE.
    #[command(name = "__complete", hide = true)]
    Complete { line: String, point: usize },
    /// Commands of an installed extension.
    #[command(external_subcommand)]
    External(Vec<String>),
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
    /// Why is there no direct connection to a node? Tests it from both ends for about 10 seconds,
    /// and says what got through and what to do. Exit code 1 without a direct connection.
    Why { node: String },
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
    /// Before distributed training: do all nodes agree on the path, and do real connections
    /// work between every pair, on ports like those NCCL opens? Needs SSH to the nodes, like
    /// `launch`. Exit code 1 if something would hang.
    Check {
        /// The nodes of the training job.
        #[arg(required = true)]
        selectors: Vec<String>,
        /// Rank 0 (default: the first node by name).
        #[arg(long)]
        master: Option<String>,
        #[arg(long, default_value_t = 29500)]
        port: u16,
        /// Test data per pair in MB.
        #[arg(long, default_value_t = 32)]
        mb: u64,
    },
    /// (Part of `net check`, on the node that is connected to.)
    #[command(hide = true)]
    ProbeListen { port: u16, secs: u64 },
    /// (Part of `net check`, on the node that connects.)
    #[command(hide = true)]
    ProbeSend { addr: String, port: u16, mb: u64 },
}

#[derive(Subcommand)]
enum ExitCmd {
    /// Nodes that offer their internet connection, and which one this node uses.
    List,
    /// Offer this node's internet connection to the network (kernel mode). Others reach only
    /// public internet addresses through it, not this node's LAN.
    Offer {
        /// Stop offering it.
        #[arg(long)]
        stop: bool,
    },
    /// Send this machine's internet traffic through NODE (userspace mode: the SOCKS proxy's).
    /// LANs and the mesh stay direct; SSH sessions from outside keep working.
    Use { node: String },
    /// Send internet traffic out directly again.
    Off,
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
        /// Also install a desktop with the system's package manager (needs root): xfce, mate or
        /// cinnamon. It becomes this machine's choice for `meshvpn desktop`.
        #[arg(long, value_parser = ["xfce", "mate", "cinnamon"])]
        desktop: Option<String>,
        /// Same as --desktop xfce.
        #[arg(long, conflicts_with = "desktop")]
        xfce: bool,
        /// Also install the GPU support (needs root): 3D programs render on the GPU (VirtualGL),
        /// and the GPU encodes the picture for the browser (H.264 with NVENC or VA-API).
        #[arg(long)]
        gpu: bool,
        /// Add "meshvpn desktop" to the login screen (needs root): your desktop on the monitor,
        /// still running after you leave, and in the browser from elsewhere.
        #[arg(long)]
        login: bool,
    },
    /// Show your desktop session fullscreen on this machine's screen (started by the login
    /// entry; Ctrl+Alt+End leaves it running).
    #[command(hide = true)]
    Local,
    /// End your desktop session on this machine (closes its applications).
    Stop,
    /// Connect stdin/stdout to your desktop session (used through SSH by `meshvpn desktop <node>`).
    #[command(hide = true)]
    Attach {
        #[arg(long, default_value = "auto")]
        session: String,
    },
    /// Run the desktop session (started by attach).
    #[command(hide = true)]
    Session {
        #[arg(long, default_value = "auto")]
        session: String,
    },
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
    /// Let a node, one user on it (`user@node`) or an SSH key log in here without a password.
    ///
    /// Example: `sudo meshvpn ssh allow cornelius@desktop --as cornelius`
    /// or, not depending on any device's name: `sudo meshvpn ssh allow ssh-ed25519 AAAA... --as cornelius`
    Allow {
        /// `node` (any of its users), `user@node`, a node's id, or an SSH public key (a line of a .pub file).
        #[arg(required = true, num_args = 1..)]
        who: Vec<String>,
        /// Local account(s) they may log in as.
        #[arg(long = "as", required = true, num_args = 1..)]
        users: Vec<String>,
    },
    /// Take a permission back (without --as: all accounts).
    Deny {
        #[arg(required = true, num_args = 1..)]
        who: Vec<String>,
        #[arg(long = "as", num_args = 1..)]
        users: Vec<String>,
    },
    /// Show who may log in here, and which keys this machine offers to others.
    List,
    /// The account others log in as by default (console, desktop). Without USER: show it.
    ///
    /// Example: `sudo meshvpn ssh default-user ubuntu`
    DefaultUser {
        user: Option<String>,
        /// Remove it (then: the --ssh-allow-all account if there is exactly one).
        #[arg(long, conflicts_with = "user")]
        clear: bool,
    },
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

/// The meshvpn program with an extension (more commands, policies, access decisions).
pub fn main_with(ext: std::sync::Arc<dyn crate::ext::Extension>) {
    crate::ext::install(ext);
    main();
}

/// The meshvpn program.
pub fn main() {
    let cli = {
        use clap::{CommandFactory, FromArgMatches};
        let mut cmd = Cli::command();
        // `--version` of this build (an extension's own release number).
        cmd = cmd.version(&*Box::leak(crate::update::current().into_boxed_str()));
        if let Some(e) = crate::ext::get() {
            let help = e.help();
            if !help.is_empty() {
                cmd = cmd.after_help(help);
            }
        }
        Cli::from_arg_matches(&cmd.get_matches()).unwrap_or_else(|e| e.exit())
    };
    let json = cli.json;
    let base = cli.dir.clone().unwrap_or_else(config::default_dir);
    let chosen = cli.net.is_some();
    let result = match (chosen, node_elsewhere(&base, &cli)) {
        // Named as a node of a further network (`gpu1.lab.mesh`): there right away.
        (false, Some((net, true))) => rerun_in(&net),
        _ => real_main(cli),
    };
    let result = match result {
        // A node the first network doesn't know: the further network that does.
        Err(e) if !chosen && exit_code(&format!("{e:#}")) == 5 => match node_elsewhere_args(&base) {
            Some(net) => {
                if !json {
                    eprintln!("(in network {net})");
                }
                rerun_in(&net)
            }
            None => Err(e),
        },
        r => r,
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            let msg = format!("{e:#}");
            let code = exit_code(&msg);
            let msg = config::hint(&msg);
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": msg, "code": code }));
            } else {
                eprintln!("error: {msg}");
            }
            std::process::exit(code);
        }
    }
}

/// The words of the command line that may name a node.
fn arg_words() -> Vec<String> {
    std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect()
}

/// A further network named in the command line itself (`<node>.<network>.mesh`): (network, true).
fn node_elsewhere(base: &Path, cli: &Cli) -> Option<(String, bool)> {
    if cli.cmd.is_none() || networks::all(base).len() < 2 {
        return None;
    }
    arg_words().iter().find_map(|w| {
        let n = networks::all(base)
            .into_iter()
            .map(|(n, _)| n)
            .find(|n| !n.is_empty() && (w.contains(&format!(".{n}.mesh")) || w.ends_with(&format!(".{n}"))))?;
        Some((n, true))
    })
}

/// After "not found": the one further network that knows a node named in the command line.
fn node_elsewhere_args(base: &Path) -> Option<String> {
    if networks::all(base).len() < 2 {
        return None;
    }
    // `user@node`, `node:path`: the node part.
    arg_words().iter().find_map(|w| {
        let w = w.rsplit('@').next().unwrap_or(w);
        let w = w.split(':').next().unwrap_or(w);
        networks::network_of_node(base, w)
    })
}

/// The same command again, for network `net`.
fn rerun_in(net: &str) -> Result<i32> {
    use clap::{CommandFactory, FromArgMatches};
    let mut args: Vec<String> = std::env::args().collect();
    args.insert(1, format!("--net={net}"));
    let matches = Cli::command().try_get_matches_from(args)?;
    real_main(Cli::from_arg_matches(&matches)?)
}

/// Stable exit codes, so scripts and agents can tell failures apart.
fn exit_code(msg: &str) -> i32 {
    if msg.contains("is not running") {
        3
    } else if msg.contains("try again with sudo")
        || msg.contains("needs root")
        || msg.contains("needs administrator")
        || msg.contains("permission denied")
    {
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

/// The directory of network `name` of this machine (`--net`).
fn network_dir(base: &Path, name: &str, creating: bool) -> Result<PathBuf> {
    let name = name.trim().to_lowercase();
    let extra = networks::dir_of(base, &name);
    if Config::path(&extra).exists() {
        return Ok(extra);
    }
    // The first network, by its own name.
    if Config::load(base).is_ok_and(|c| c.network == name) || name.is_empty() {
        return Ok(base.to_path_buf());
    }
    networks::check_name(&name)?;
    if creating {
        return Ok(extra);
    }
    let known: Vec<String> = networks::all(base)
        .iter()
        .map(|(_, d)| networks::display_name(d))
        .collect();
    if known.is_empty() {
        bail!("no network called {name} here: this machine isn't in any network yet");
    }
    bail!(
        "no network called {name} here (not found) - this machine's networks: {}; to join another: meshvpn join <invite>",
        known.join(", ")
    )
}

/// Where `meshvpn join` puts a network: with the others if this machine is already in one.
fn join_dir(base: &Path, dir: &Path, net_given: bool, inv: &Invite, force: bool) -> Result<PathBuf> {
    if net_given || force {
        return Ok(dir.to_path_buf());
    }
    // Already in it (a renewal, or joining again).
    if let Some(d) = networks::find_id(base, &inv.id) {
        return Ok(d);
    }
    if !Config::path(dir).exists() {
        return Ok(dir.to_path_buf());
    }
    Ok(networks::dir_of(base, &networks::new_name(base, &inv.network)))
}

/// Prints a plain message, or `{"ok": true, "message": ...}` with --json.
fn exit_cmd(dir: &Path, cmd: ExitCmd, json: bool) -> Result<i32> {
    let rt = tokio::runtime::Runtime::new()?;
    let req = match cmd {
        ExitCmd::List => {
            let st = agent::status(dir)?;
            let exits: Vec<&node::PeerStatus> = st.peers.iter().filter(|p| p.exit).collect();
            if json {
                let list: Vec<serde_json::Value> = exits
                    .iter()
                    .map(|p| serde_json::json!({"name": p.name, "online": p.online, "path": p.path}))
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({"offering": st.exit_offer, "using": st.exit_via, "exits": list})
                );
                return Ok(0);
            }
            if st.exit_offer {
                println!("This node offers its internet connection (exit node).");
            }
            match &st.exit_via {
                Some(n) => println!("Internet traffic goes through {n}."),
                None => println!("Internet traffic goes out directly."),
            }
            if exits.is_empty() {
                println!("No other node offers its internet connection (meshvpn exit offer on that node).");
            } else {
                println!("\nExit nodes:");
                for p in exits {
                    println!(
                        "  {:<20} {}",
                        p.name,
                        if p.online { p.path.as_str() } else { "offline" }
                    );
                }
                println!("\nUse one: sudo meshvpn exit use <node>");
            }
            return Ok(0);
        }
        ExitCmd::Offer { stop } => control::Request::ExitOffer { on: !stop },
        ExitCmd::Use { node } => control::Request::ExitUse { node: Some(node) },
        ExitCmd::Off => control::Request::ExitUse { node: None },
    };
    require_owner()?;
    if let control::Response::Message { text } = rt.block_on(control::request(dir, &req))? {
        say(json, &text);
    }
    Ok(0)
}

fn say(json: bool, text: &str) {
    if json {
        println!("{}", serde_json::json!({ "ok": true, "message": text }));
    } else {
        println!("{text}");
    }
}

fn real_main(cli: Cli) -> Result<i32> {
    let base = cli.dir.clone().unwrap_or_else(config::default_dir);
    let creating = matches!(cli.cmd, Some(Cmd::Join { .. } | Cmd::Init { .. }));
    let dir = match &cli.net {
        Some(n) => network_dir(&base, n, creating)?,
        None => base.clone(),
    };
    let net_given = cli.net.is_some();
    config::set_rootless(&dir);
    networks::set_current(&dir);
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
            if !net_given
                && !node.force
                && let Ok(cfg) = Config::load(&dir)
            {
                bail!(
                    "this machine is already in network \"{}\" - to create another network next to it: {}",
                    cfg.network,
                    config::hint("sudo meshvpn --net <name> init")
                );
            }
            // A further network is called what --net says, unless --network says otherwise.
            let network = match networks::name(&dir) {
                Some(n) if network == "mesh" => n,
                _ => network,
            };
            let key = keys::random32();
            let (cfg, replaced) = create(&dir, node, config::sanitize_name(&network), key, vec![])?;
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
            print_invite(&dir, &cfg, 1, 24 * 3600 * 1000, None, false)?;
            enable_ssh_logins(&cfg);
            let restarted = restart_replaced(&dir, replaced);
            print_next_steps(&dir, &cfg, restarted);
        }
        Cmd::Join { invite, node } => {
            let inv = Invite::decode(&invite)?;
            check_invite_expiry(&inv)?;
            let first = Config::load(&base).ok();
            let dir = join_dir(&base, &dir, net_given, &inv, node.force)?;
            networks::set_current(&dir);
            // Already a member of this network (a client renewing): a new admission only.
            if let Ok(cfg) = Config::load(&dir)
                && !node.force
                && cfg.network_id() == inv.id
                && let Some(ticket) = inv.ticket.clone()
            {
                require_owner()?;
                if control::is_running(&dir) {
                    let req = control::Request::Readmit {
                        ticket,
                        ticket_key: inv.ticket_key.clone(),
                    };
                    let resp = tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))?;
                    match resp {
                        control::Response::Message { text } => say(json, &text),
                        control::Response::Error { message } => bail!("{message}"),
                        _ => bail!("unexpected answer from meshvpn"),
                    }
                } else {
                    let mut cfg = cfg;
                    cfg.ticket = Some(ticket);
                    cfg.ticket_key = inv.ticket_key.clone();
                    cfg.claim = None;
                    cfg.save(&dir)?;
                    say(json, "admission renewed - it applies when meshvpn starts");
                }
                return Ok(0);
            }
            let key = keys::unb64_32(&inv.key)?;
            let (mut cfg, replaced) = create(&dir, node, inv.network, key, inv.bootstrap)?;
            cfg.network_id = inv.id;
            cfg.key_version = inv.v;
            cfg.trusted_admins = inv.admins;
            cfg.ticket = inv.ticket;
            cfg.ticket_key = inv.ticket_key;
            cfg.join = inv.join;
            cfg.save(&dir)?;
            println!("Joined network \"{}\".\n", cfg.network);
            if let (Some(n), Some(first)) = (networks::name(&dir), first.filter(|_| !net_given)) {
                println!(
                    "This machine is also in network \"{}\", so this one is a further network here, called {n}:\n  \
                     its nodes are <node>.{n}.mesh, and meshvpn finds them by name in commands as usual\n  \
                     anything else for it takes --net {n}, e.g. meshvpn --net {n} status\n",
                    first.network
                );
            }
            print_node_summary(&cfg)?;
            println!("It will connect to: {}", cfg.bootstrap.join(", "));
            enable_ssh_logins(&cfg);
            let restarted = restart_replaced(&dir, replaced);
            print_next_steps(&dir, &cfg, restarted);
        }
        Cmd::Invite {
            uses,
            expires,
            client,
            client_for,
        } => {
            let cfg = Config::load(&dir)?;
            let client = match client {
                Some(user) => Some(proto::ClientGrant {
                    user,
                    until: now_ms() + parse_duration_ms(&client_for)?,
                }),
                None => None,
            };
            print_invite(&dir, &cfg, uses, parse_duration_ms(&expires)?, client, json)?;
        }
        Cmd::Gpu { cmd } => return gpu_cmd(&dir, cmd, json),
        Cmd::Exit { cmd } => return exit_cmd(&dir, cmd, json),
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
        Cmd::Up { log_file } => {
            let cfg = Config::load(&dir)?;
            init_logging(log_file.as_deref())?;
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
        Cmd::Net {
            cmd: NetCmd::ProbeListen { port, secs },
        } => {
            crate::netcheck::listen(port, secs)?;
        }
        Cmd::Net {
            cmd: NetCmd::ProbeSend { addr, port, mb },
        } => {
            crate::netcheck::send(&addr, port, mb)?;
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
                NetCmd::Why { node } => {
                    if !json {
                        eprintln!("testing the direct path to {node} from both ends (about 10 seconds)...");
                    }
                    let text = match tokio::runtime::Runtime::new()?
                        .block_on(control::request(&dir, &control::Request::NetWhy { node }))?
                    {
                        control::Response::Message { text } => text,
                        control::Response::Error { message } => bail!("{message}"),
                        _ => bail!("unexpected answer from meshvpn"),
                    };
                    let report: node::why::WhyReport = serde_json::from_str(&text)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        print!("{}", report.render());
                    }
                    if !report.direct {
                        std::process::exit(1);
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
                NetCmd::ProbeListen { .. } | NetCmd::ProbeSend { .. } => unreachable!(),
                NetCmd::Check {
                    selectors,
                    master,
                    port,
                    mb,
                } => {
                    let group = agent::select(&all, &selectors)?;
                    let master = match master {
                        Some(m) => agent::select(&all, &[m])?.remove(0),
                        None => group.iter().min_by_key(|n| n.name.clone()).unwrap().clone(),
                    };
                    let remote = agent::Remote {
                        user: agent::Remote::default_user(),
                        socks: st.socks.is_some(),
                        timeout: std::time::Duration::from_secs(120),
                    };
                    if !crate::netcheck::check(&group, &master, port, mb, &remote, json)? {
                        std::process::exit(1);
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
                let others: Vec<String> = networks::all(&base)
                    .iter()
                    .filter(|(_, d)| *d != dir)
                    .map(|(_, d)| networks::display_name(d))
                    .collect();
                if !others.is_empty() {
                    println!(
                        "\nThis machine is also in: {} (meshvpn networks; meshvpn --net {} status)",
                        others.join(", "),
                        others[0]
                    );
                }
            }
        }
        Cmd::Connect { addr } => {
            let addr = with_default_port(&addr);
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
        Cmd::Ssh {
            cmd: Some(SshCmd::DefaultUser { user, clear }),
        } => {
            if user.is_none() && !clear {
                let cfg = Config::load(&dir)?;
                let derived = (cfg.ssh_allow_all.len() == 1).then(|| cfg.ssh_allow_all[0].clone());
                match (cfg.ssh_default_user, derived) {
                    (Some(u), _) => say(json, &format!("others log in here as {u} by default")),
                    (None, Some(u)) => say(
                        json,
                        &format!("others log in here as {u} by default (from --ssh-allow-all)"),
                    ),
                    (None, None) => say(json, "no default login set (others log in as themselves)"),
                }
                return Ok(0);
            }
            require_owner()?;
            if let Some(u) = &user
                && !proto::valid_user(u)
            {
                bail!("invalid user name {u:?}");
            }
            if control::is_running(&dir) {
                let req = control::Request::LoginUser { user };
                if let control::Response::Message { text } =
                    tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))?
                {
                    say(json, &text);
                }
            } else {
                let mut cfg = Config::load(&dir)?;
                cfg.ssh_default_user = user.clone();
                cfg.save(&dir)?;
                say(
                    json,
                    &match user {
                        Some(u) => format!("others log in here as {u} by default (announced when meshvpn starts)"),
                        None => "default login removed".into(),
                    },
                );
            }
        }
        Cmd::Ssh { cmd } => {
            let req = match cmd.unwrap_or(SshCmd::List) {
                SshCmd::Allow { who, users } if !control::is_running(&dir) => {
                    require_owner()?;
                    let msg = ssh_rules_offline(&dir, &who.join(" "), users, true)?;
                    if let Err(e) = sshd::enable_if_installed() {
                        println!("note: sshd is not set up yet ({e:#}); meshvpn retries when it starts");
                    }
                    say(json, &msg);
                    return Ok(0);
                }
                SshCmd::Deny { who, users } if !control::is_running(&dir) => {
                    require_owner()?;
                    say(json, &ssh_rules_offline(&dir, &who.join(" "), users, false)?);
                    return Ok(0);
                }
                SshCmd::Allow { who, users } => {
                    require_owner()?;
                    // The rule is saved either way; sshd may only be ready later.
                    match sshd::enable_if_installed() {
                        Ok(true) => println!(
                            "Enabled password-less logins from mesh nodes in sshd ({}).",
                            sshd::DROPIN
                        ),
                        Ok(false) => {}
                        Err(e) => println!("note: logins through sshd are not active yet: {e:#}"),
                    }
                    control::Request::SshAllow {
                        who: who.join(" "),
                        users,
                    }
                }
                SshCmd::Deny { who, users } => {
                    require_owner()?;
                    control::Request::SshDeny {
                        who: who.join(" "),
                        users,
                    }
                }
                SshCmd::List => control::Request::SshList,
                SshCmd::DefaultUser { .. } => unreachable!("handled above"),
            };
            if let control::Response::Message { text } =
                tokio::runtime::Runtime::new()?.block_on(control::request(&dir, &req))?
            {
                println!("{}", text.trim_end());
            }
        }
        Cmd::SftpServer => sshserver::sftp_server()?,
        Cmd::ForwardTcp { host, port } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let s = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                let (mut r, mut w) = s.into_split();
                let up = async {
                    let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut w).await;
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
                };
                let down = async {
                    let mut out = tokio::io::stdout();
                    let _ = tokio::io::copy(&mut r, &mut out).await;
                    let _ = tokio::io::AsyncWriteExt::flush(&mut out).await;
                };
                tokio::join!(up, down);
                anyhow::Ok(())
            })?;
        }
        Cmd::Console { user } => console::run(&dir, user)?,
        Cmd::Guide { skill } => {
            if skill {
                print!("{}", guide::skill());
            } else if json {
                println!(
                    "{}",
                    serde_json::json!({ "context": guide::context(&dir), "guide": guide::GUIDE })
                );
            } else {
                println!("{}\n{}", guide::context(&dir), guide::GUIDE);
            }
        }
        Cmd::Desktop {
            cmd,
            node,
            user,
            port,
            no_browser,
            session,
            xfce,
            plain,
            screen,
        } => match cmd {
            Some(DesktopCmd::Setup {
                from,
                desktop: which,
                xfce,
                gpu,
                login,
            }) => {
                let b = desktop::bundle::setup(from.as_deref())?;
                say(json, &format!("desktop components installed in {}", b.dir.display()));
                if login {
                    let p = desktop::bundle::install_login_entry()?;
                    say(
                        json,
                        &format!(
                            "\"meshvpn desktop\" added to the login screen ({}): log in with it to get your desktop on the monitor",
                            p.display()
                        ),
                    );
                }
                if gpu {
                    desktop::bundle::install_gpu()?;
                    say(
                        json,
                        "GPU support installed: 3D programs in `meshvpn desktop` sessions render on the GPU, and the GPU encodes the picture",
                    );
                }
                if let Some(name) = which.or(xfce.then(|| "xfce".to_string())) {
                    desktop::bundle::install_desktop(&name)?;
                    say(
                        json,
                        &format!("{name} installed: `meshvpn desktop <this node>` now opens it"),
                    );
                }
            }
            Some(DesktopCmd::Local) => {
                #[cfg(unix)]
                desktop::local::run()?;
                #[cfg(windows)]
                desktop::session::local()?;
            }
            Some(DesktopCmd::Stop) => {
                if desktop::session::stop()? {
                    say(json, "desktop session ended");
                } else {
                    say(json, "no desktop session is running");
                }
            }
            Some(DesktopCmd::Attach { session }) => desktop::session::attach(&session)?,
            Some(DesktopCmd::Session { session }) => {
                init_logging(None)?;
                desktop::session::run(&session)?;
            }
            None => {
                let Some(node) = node else {
                    bail!("which node? e.g. meshvpn desktop <node> (see meshvpn nodes)");
                };
                if std::env::var_os("MESHVPN_DESKTOP_BRIDGE").is_some() {
                    let mut target = desktop::client::Target::test(&node, user.as_deref());
                    target.session = desktop_session(session.as_deref(), xfce, plain, screen);
                    desktop::client::run(target, port, !no_browser)?;
                    return Ok(0);
                }
                let st = agent::status(&dir)?;
                let targets = agent::select(&agent::nodes(&st), &[node])?;
                let [node] = <[agent::NodeView; 1]>::try_from(targets)
                    .map_err(|_| anyhow::anyhow!("select exactly one node"))?;
                let remote = agent::Remote {
                    // Default: a User from ~/.ssh/config, else the node's announced default.
                    user: user.unwrap_or_else(|| agent::Remote::login_user_for(&node)),
                    socks: st.socks.is_some(),
                    timeout: std::time::Duration::from_secs(30),
                };
                let session = desktop_session(session.as_deref(), xfce, plain, screen);
                desktop::client::run(
                    desktop::client::Target {
                        node,
                        remote,
                        session,
                        control: None,
                    },
                    port,
                    !no_browser,
                )?;
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
            // One sshd for all of this machine's networks: each one's keys, pinned to its addresses.
            if let Ok(rt) = tokio::runtime::Runtime::new() {
                for d in chosen_networks(&base, &dir, net_given) {
                    if let Ok(control::Response::Message { text }) = rt.block_on(control::request(&d, &req)) {
                        print!("{text}");
                    }
                }
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
        Cmd::External(args) => {
            return match crate::ext::get().and_then(|e| e.command(&dir, json, &args)) {
                Some(r) => r,
                None => bail!(
                    "unknown command {:?} - see meshvpn --help",
                    args.first().map(String::as_str).unwrap_or("")
                ),
            };
        }
        // Without --net: every network of this machine.
        Cmd::Install => {
            for d in chosen_networks(&base, &dir, net_given) {
                install(&d)?;
            }
            if let Some(path) = crate::completion::install()
                && !json
            {
                println!("Tab completion for bash: {} (in new shells)", path.display());
            }
        }
        Cmd::Dht { state } => dht_cmd(&dir, state.as_deref().map(|s| s == "on"), json)?,
        Cmd::Restart => {
            for d in chosen_networks(&base, &dir, net_given) {
                restart(&d)?;
            }
        }
        Cmd::Uninstall => {
            // The further ones first: the first network's goes last, with sshd's setup.
            for d in chosen_networks(&base, &dir, net_given).iter().rev() {
                uninstall(d)?;
            }
            if !net_given {
                crate::completion::uninstall();
            }
        }
        Cmd::Completion { .. } => print!("{}", crate::completion::BASH),
        Cmd::Complete { line, point } => {
            for c in crate::completion::complete(full_command(), &base, &line, point) {
                println!("{c}");
            }
        }
        Cmd::Networks { cmd: None } => print_networks(&base, json)?,
        Cmd::Networks {
            cmd: Some(NetworksCmd::Leave { name, yes }),
        } => leave_network(&base, &name, json, yes)?,
        Cmd::Leave { yes } => leave(&base, &dir, json, yes)?,
    }
    Ok(0)
}

/// All commands: meshvpn's and an extension's.
/// The session `meshvpn desktop <node>` asks the node for.
fn desktop_session(session: Option<&str>, xfce: bool, plain: bool, screen: bool) -> &'static str {
    match session {
        Some("xfce") => "xfce",
        Some("mate") => "mate",
        Some("cinnamon") => "cinnamon",
        Some(_) => "plain",
        None if screen => "screen",
        None if xfce => "xfce",
        None if plain => "plain",
        None => "auto",
    }
}

fn full_command() -> clap::Command {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    if let Some(ext) = crate::ext::get().and_then(|e| e.cli()) {
        for sub in ext.get_subcommands() {
            if cmd.find_subcommand(sub.get_name()).is_none() {
                cmd = cmd.subcommand(sub.clone());
            }
        }
    }
    cmd
}

/// The networks a command without --net is for: all of them (the first one alone if that's all).
fn chosen_networks(base: &Path, dir: &Path, net_given: bool) -> Vec<PathBuf> {
    if net_given {
        return vec![dir.to_path_buf()];
    }
    let all: Vec<PathBuf> = networks::all(base).into_iter().map(|(_, d)| d).collect();
    if all.is_empty() { vec![dir.to_path_buf()] } else { all }
}

/// `meshvpn networks`
fn print_networks(base: &Path, json: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let mut rows = vec![];
    for (name, d) in networks::all(base) {
        let Ok(cfg) = Config::load(&d) else { continue };
        let st = match rt.block_on(control::request(&d, &control::Request::Status)) {
            Ok(control::Response::Status(st)) => Some(st),
            _ => None,
        };
        let ident = Identity::from_config(&cfg)?;
        rows.push(serde_json::json!({
            "name": networks::display_name(&d),
            "first": name.is_empty(),
            "network": cfg.network,
            "node": cfg.name,
            "ip": overlay_ip(&ident.id).to_string(),
            "interface": st.as_ref().map(|s| s.interface.clone()).unwrap_or(cfg.interface.clone()),
            "port": cfg.listen_port(),
            "names": format!("<node>.{}", networks::suffix(&d)),
            "running": st.is_some(),
            "online": st.as_ref().map(|s| s.peers.iter().filter(|p| p.online).count()),
            "nodes": st.as_ref().map(|s| s.peers.len()),
            "dir": d.display().to_string(),
        }));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("This machine isn't in a network yet: meshvpn init, or meshvpn join <invite>.");
        return Ok(());
    }
    println!(
        "{:<14} {:<16} {:<16} {:<10} {:<6} {:<18} STATUS",
        "NETWORK", "THIS NODE", "ADDRESS", "INTERFACE", "PORT", "NAMES"
    );
    for r in &rows {
        let status = if r["running"] == true {
            format!("running, {} of {} nodes online", r["online"], r["nodes"])
        } else {
            "not running".to_string()
        };
        println!(
            "{:<14} {:<16} {:<16} {:<10} {:<6} {:<18} {status}",
            r["name"].as_str().unwrap_or(""),
            r["node"].as_str().unwrap_or(""),
            r["ip"].as_str().unwrap_or(""),
            r["interface"].as_str().unwrap_or(""),
            r["port"].as_u64().map(|p| p.to_string()).unwrap_or("-".into()),
            r["names"].as_str().unwrap_or(""),
        );
    }
    if rows.len() > 1 {
        println!();
        println!("Commands find a node's network by its name. For anything else: meshvpn --net <network> ...");
        println!("Leave a further network: meshvpn networks leave <network>");
    } else {
        println!();
        println!("To be in another network too, join it: meshvpn join <invite>");
    }
    Ok(())
}

/// `meshvpn networks leave NAME`: that network goes, the others stay as they are.
fn leave_network(base: &Path, name: &str, json: bool, yes: bool) -> Result<()> {
    let dir = networks::dir_of(base, name);
    if Config::path(&dir).exists() {
        return leave(base, &dir, json, yes);
    }
    if Config::load(base).is_ok_and(|c| c.network == name) {
        return leave(base, base, json, yes);
    }
    bail!("this machine isn't in a network called {name} (not found): see meshvpn networks")
}

/// What a network keeps in its directory (removed when it is left; nothing else is touched:
/// the directory may be one given with --dir).
const NETWORK_FILES: &[&str] = &[
    "config.toml",
    "state.json",
    "nonce-session",
    "proxy.env",
    "objects",
    "meshvpn.log",
    "known_hosts",
    "meshvpn.sock",
];

/// From the saved state: is this node the network's only admin? (meshvpn isn't running.)
fn only_admin_offline(dir: &Path, cfg: &Config) -> bool {
    let Ok(me) = crate::keys::Identity::from_config(cfg).map(|i| i.id.hex()) else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(dir.join("state.json")) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let Some(data) = v["roster"]["data"].as_str() else {
        return false; // an open network
    };
    let Ok(r) = serde_json::from_str::<serde_json::Value>(data) else {
        return false;
    };
    let admins: Vec<&str> = r["admins"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    admins.contains(&me.as_str()) && admins.len() == 1
}

/// `meshvpn leave`: the network forgets this node, meshvpn stops for it and its configuration
/// goes. If it was the machine's first network and there are others, the next one becomes the
/// first (its names are then `<node>.mesh`).
fn leave(base: &Path, dir: &Path, json: bool, yes: bool) -> Result<()> {
    use std::io::{IsTerminal as _, Write as _};
    let cfg = Config::load(dir)?;
    require_owner()?;
    config::set_rootless(dir);
    let label = networks::display_name(dir);
    if !yes && !json && std::io::stdin().is_terminal() {
        print!(
            "Leave network {label}? meshvpn stops for it here and its configuration and keys are removed \
             (to come back you need a new invite). [y/N] "
        );
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            bail!("not left");
        }
    }
    // Tell the network (and hand over the admin role); the last admin can't go.
    if !json {
        println!("Telling the network that {} leaves ...", cfg.name);
    }
    let rt = tokio::runtime::Runtime::new()?;
    // A meshvpn that doesn't answer (hung, or busy) mustn't keep this waiting: it is stopped below.
    let asked = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            control::request(dir, &control::Request::Leave),
        )
        .await
    });
    let asked = match asked {
        Ok(r) => r,
        Err(_) => {
            if !json {
                println!(
                    "meshvpn didn't answer within 15 seconds - leaving without telling the network (it is \
                     stopped now; the other nodes list {} as offline until one of them forgets it)",
                    cfg.name
                );
            }
            Ok(control::Response::Message { text: String::new() })
        }
    };
    match asked {
        Ok(control::Response::Message { text }) if text.is_empty() => {}
        Ok(control::Response::Message { text }) => {
            if !json {
                println!("{text}");
            }
            // Let it go out before meshvpn stops.
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
        Ok(_) => {}
        // Only "not running" goes on without telling the network; anything else stops here.
        Err(e) if !e.to_string().contains("meshvpn is not running") => return Err(e),
        Err(_) => {
            if only_admin_offline(dir, &cfg) {
                bail!(
                    "this node is the only admin of the network - start meshvpn, make another node admin \
                     (sudo meshvpn admin add <node>), then leave"
                );
            }
            if !json {
                println!(
                    "meshvpn isn't running, so the other nodes can't be told: they list {} as offline until one \
                     of them forgets it (meshvpn forget {})",
                    cfg.name, cfg.name
                );
            }
        }
    }
    let extra = networks::name(dir);
    if config::rootless() {
        uninstall_user(dir)?
    } else {
        uninstall(dir)?
    };
    #[cfg(unix)]
    for (pid, cmd) in stop_other_daemons(dir) {
        if !json {
            println!("Stopped meshvpn (pid {pid}: {cmd}).");
        }
    }
    // Its daemon removes its names from /etc/hosts as it stops; this is for one that didn't run.
    if !config::rootless() {
        let _ = hosts::write(extra.as_deref(), None);
        match &extra {
            Some(n) => {
                let _ = std::fs::remove_dir_all(format!("/var/lib/meshvpn/networks/{n}"));
            }
            None => {
                let _ = std::fs::remove_file("/var/lib/meshvpn/known_hosts");
            }
        }
    } else {
        node::user_ssh_config(dir, false);
    }
    match &extra {
        Some(_) => std::fs::remove_dir_all(dir).with_context(|| format!("removing {}", dir.display()))?,
        None => {
            for f in NETWORK_FILES {
                let p = dir.join(f);
                if p.is_dir() {
                    std::fs::remove_dir_all(&p).ok();
                } else {
                    std::fs::remove_file(&p).ok();
                }
            }
        }
    }
    say(
        json,
        &format!("left network {label}: its configuration is gone from this machine"),
    );
    if extra.is_none()
        && let Some((next, _)) = networks::all(base).into_iter().find(|(n, _)| !n.is_empty())
    {
        promote(base, &next)?;
        say(
            json,
            &format!("network {next} is now this machine's first network: its nodes are <node>.mesh now"),
        );
    }
    Ok(())
}

/// A further network becomes the machine's first one (after that was left).
fn promote(base: &Path, name: &str) -> Result<()> {
    let from = networks::dir_of(base, name);
    if config::rootless() {
        uninstall_user(&from)?
    } else {
        uninstall(&from)?
    };
    #[cfg(unix)]
    stop_other_daemons(&from);
    for e in std::fs::read_dir(&from)?.flatten() {
        std::fs::rename(e.path(), base.join(e.file_name()))
            .with_context(|| format!("moving {} to {}", e.path().display(), base.display()))?;
    }
    std::fs::remove_dir(&from).ok();
    if !config::rootless() {
        let _ = hosts::write(Some(name), None);
        let old = format!("/var/lib/meshvpn/networks/{name}");
        let _ = std::fs::rename(format!("{old}/known_hosts"), "/var/lib/meshvpn/known_hosts");
        let _ = std::fs::remove_dir_all(old);
        install(base)
    } else {
        install_user(base)
    }
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
            crate::sys::FROM_PROXY_FILE.lock().unwrap().push(key.to_string());
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

fn init_logging(file: Option<&Path>) -> Result<()> {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("meshvpn=info"));
    let log = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    match file {
        Some(path) => {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening {}", path.display()))?;
            log.with_ansi(false).with_writer(std::sync::Mutex::new(f)).init();
        }
        None => log.init(),
    }
    Ok(())
}

/// What became of the meshvpn that ran the configuration `--force` replaced.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Replaced {
    /// Nothing ran it.
    NotRunning,
    /// Stopped; it ran as a service, which starts again with the new configuration.
    Service,
    /// Stopped; it ran by hand (`meshvpn up`), so it is started by hand again.
    ByHand,
}

fn create(
    dir: &Path,
    o: NodeOpts,
    network: String,
    key: [u8; 32],
    bootstrap: Vec<String>,
) -> Result<(Config, Replaced)> {
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
    let mut o = o;
    if networks::is_extra(dir) {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            bail!(
                "this machine is in a network already, and being in a further one works on Linux and macOS only for now"
            );
        }
        // What the others of this machine don't use, unless chosen.
        let (iface, port, socks) = networks::free_slot(&networks::base(dir));
        if o.interface == "mesh0" {
            o.interface = iface;
        }
        if o.listen == format!("0.0.0.0:{DEFAULT_PORT}") {
            o.listen = format!("0.0.0.0:{port}");
        }
        if o.ssh_remote_port == DEFAULT_PORT {
            o.ssh_remote_port = port;
        }
        cfg.socks_listen = socks;
    }
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
    // A meshvpn still running the old configuration would stay in the old network with the old
    // keys, and keep writing the old network's state here: it stops first.
    let replaced = if Config::path(dir).exists() {
        stop_for_replace(dir)
    } else {
        Replaced::NotRunning
    };
    // Starting over: forget the nodes of the previous setup.
    let _ = std::fs::remove_file(SavedState::path(dir));
    cfg.save(dir)?;
    Ok((cfg, replaced))
}

/// Stops whatever runs network `dir` (its service, and a `meshvpn up` started by hand), for
/// `--force` to replace its configuration.
fn stop_for_replace(dir: &Path) -> Replaced {
    let running = control::is_running(dir);
    // Without systemd, `meshvpn install` runs meshvpn in the background: that counts as its service.
    let service = service_registered(dir) || (running && no_service_manager());
    if !running && !service {
        return Replaced::NotRunning;
    }
    if service {
        stop_service(dir);
    }
    let by_hand = !stop_other_daemons(dir).is_empty();
    // Windows lists no processes: a `meshvpn up` in a terminal there is still running.
    if control::is_running(dir) {
        eprintln!(
            "warning: a meshvpn of the previous configuration is still running - stop it (Ctrl+C in its \
             terminal), or it stays in the old network"
        );
    }
    match (service, by_hand || running) {
        (true, _) => Replaced::Service,
        (false, true) => Replaced::ByHand,
        (false, false) => Replaced::NotRunning,
    }
}

/// `meshvpn dht [on|off]`: shows or changes `dht` in the configuration; a running meshvpn restarts
/// to use it.
fn dht_cmd(dir: &Path, on: Option<bool>, json: bool) -> Result<()> {
    let mut cfg = Config::load(dir)?;
    let net = networks::flag(dir);
    let Some(on) = on else {
        if json {
            println!("{}", serde_json::json!({ "dht": cfg.dht }));
        } else if cfg.dht {
            println!("DHT rendezvous is on (meshvpn{net} status shows what it found).");
        } else {
            println!(
                "DHT rendezvous is off - switch it on with: {}",
                config::hint(&format!("sudo meshvpn{net} dht on"))
            );
        }
        return Ok(());
    };
    require_owner()?;
    let word = if on { "on" } else { "off" };
    if cfg.dht == on {
        say(json, &format!("DHT rendezvous is {word} already"));
        return Ok(());
    }
    cfg.dht = on;
    cfg.save(dir)?;
    if !control::is_running(dir) {
        say(json, &format!("DHT rendezvous {word} - it applies when meshvpn starts"));
        return Ok(());
    }
    say(json, &format!("DHT rendezvous {word} - restarting meshvpn to use it"));
    restart(dir)
        .map_err(|e| anyhow::anyhow!("the setting is saved, but meshvpn didn't restart: {e:#} - restart it yourself"))
}

/// Linux without systemd (containers, some small systems): `meshvpn install` runs meshvpn in the
/// background there, and at boot from cron.
fn no_service_manager() -> bool {
    cfg!(target_os = "linux")
        && if config::rootless() {
            !user_systemd()
        } else {
            !systemd_running()
        }
}

/// `meshvpn restart`: the service of network `dir` stops and starts again, however this system
/// runs it.
fn restart(dir: &Path) -> Result<()> {
    Config::load(dir)?;
    require_owner()?;
    let net = networks::flag(dir);
    let running = control::is_running(dir);
    let background = no_service_manager() && running;
    if !service_registered(dir) && !background {
        if running {
            bail!(
                "meshvpn runs here without a service (started with `meshvpn up`): stop it (Ctrl+C) and start \
                 it again, or let a service run it: {}",
                config::hint(&format!("sudo meshvpn{net} install"))
            );
        }
        bail!(
            "meshvpn isn't installed as a service here - start it with: {}",
            config::hint(&format!("sudo meshvpn{net} install"))
        );
    }
    let svc = networks::service(dir);
    if background {
        // No service manager: what `install` does, it does again (stop, start in the background).
        return install(dir);
    }
    if config::rootless() {
        if !user_unit_path(dir).is_ok_and(|u| u.exists()) {
            return install(dir); // started from cron at boot, in the background now
        }
        systemctl(&["--user", "restart", &svc])?;
    } else {
        #[cfg(windows)]
        {
            stop_service(dir);
            schtasks(&["/Run", "/TN", "meshvpn"])?;
        }
        #[cfg(not(windows))]
        {
            if cfg!(target_os = "macos") {
                // -k: kill the running one first, then start it.
                launchctl(&["kickstart", "-k", &format!("system/{}", launchd_label(dir))])?;
            } else {
                systemctl(&["restart", &svc])?;
            }
        }
    }
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if control::is_running(dir) {
            match networks::name(dir) {
                Some(n) => println!("meshvpn restarted for network {n}."),
                None => println!("meshvpn restarted."),
            }
            return Ok(());
        }
    }
    let logs = if config::rootless() {
        format!("journalctl --user -u {svc} -n 20")
    } else if cfg!(windows) {
        dir.join("meshvpn.log").display().to_string()
    } else if cfg!(target_os = "macos") {
        format!("tail /var/log/{svc}.log")
    } else {
        format!("journalctl -u {svc} -n 20")
    };
    bail!("meshvpn did not come back after the restart - see: {logs}")
}

/// Is a boot service (systemd unit, launch daemon, scheduled task, rootless autostart) set up for
/// network `dir`?
fn service_registered(dir: &Path) -> bool {
    if config::rootless() {
        let unit = user_unit_path(dir).is_ok_and(|u| u.exists());
        let cron = std::process::Command::new("crontab")
            .arg("-l")
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.ends_with(&cron_mark(dir)))
            })
            .unwrap_or(false);
        return unit || cron;
    }
    #[cfg(windows)]
    {
        schtasks(&["/Query", "/TN", "meshvpn"]).is_ok()
    }
    #[cfg(not(windows))]
    {
        if cfg!(target_os = "macos") {
            launchd_plist(dir).exists()
        } else {
            unit_path(dir).exists() && systemd_running()
        }
    }
}

/// Stops network `dir`'s service without removing it (the service manager would otherwise start
/// the old configuration again right away).
fn stop_service(dir: &Path) {
    if config::rootless() {
        if user_unit_path(dir).is_ok_and(|u| u.exists()) {
            let _ = systemctl(&["--user", "stop", &networks::service(dir)]);
        }
        return;
    }
    #[cfg(windows)]
    {
        let _ = schtasks(&["/End", "/TN", "meshvpn"]);
        for _ in 0..20 {
            if !control::is_running(dir) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    #[cfg(not(windows))]
    {
        if cfg!(target_os = "macos") {
            let _ = launchctl(&["bootout", &format!("system/{}", launchd_label(dir))]);
        } else if systemd_running() {
            let _ = systemctl(&["stop", &networks::service(dir)]);
        }
    }
}

/// After `--force`: the service starts again, now with the new configuration. True if meshvpn runs
/// with it.
fn restart_replaced(dir: &Path, replaced: Replaced) -> bool {
    match replaced {
        Replaced::NotRunning => false,
        Replaced::ByHand => {
            println!("Stopped the meshvpn that ran the previous configuration.");
            false
        }
        Replaced::Service => {
            println!("Restarting the service with the new configuration:");
            match install(dir) {
                Ok(()) => true,
                Err(e) => {
                    let net = networks::flag(dir);
                    eprintln!(
                        "warning: restarting it failed: {e:#}\n  start it with: {}",
                        config::hint(&format!("sudo meshvpn{net} install"))
                    );
                    false
                }
            }
        }
    }
}

/// Sets up sshd right away if the config asks for password-less logins. If that isn't possible
/// yet (e.g. meshvpn not installed to /usr/local/bin), the daemon retries at startup.
fn enable_ssh_logins(cfg: &Config) {
    if cfg.ssh_allow_all.is_empty() && cfg.ssh_allow.is_empty() && cfg.ssh_allow_keys.is_empty() {
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
    println!("  host name:   {}.{}", cfg.name, networks::current_suffix());
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

fn print_next_steps(dir: &Path, cfg: &Config, restarted: bool) {
    let net = networks::flag(dir);
    println!();
    if restarted {
        println!("meshvpn runs with the new configuration.");
        println!("  {:<22} # see who is connected", format!("meshvpn{net} status"));
        return;
    }
    if control::is_running(dir) {
        println!("meshvpn is still running with the previous configuration. Restart it:");
        println!("{}", config::hint(&format!("  sudo meshvpn{net} restart")));
        println!("  (or stop `meshvpn up` with Ctrl+C and start it again)");
        println!();
    }
    println!("Next steps:");
    println!(
        "  {:<22} # run now, in the foreground",
        config::hint(&format!("sudo meshvpn{net} up"))
    );
    println!(
        "  {:<22} # or: run in the background, also after reboot",
        config::hint(&format!("sudo meshvpn{net} install"))
    );
    println!("  {:<22} # see who is connected", format!("meshvpn{net} status"));
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
            Some(e) => println!("  sudo meshvpn connect {e}"),
            None => println!("  sudo meshvpn connect <public HOST:PORT that reaches this node>"),
        }
    }
}

fn make_invite(
    dir: &Path,
    cfg: &Config,
    uses: u32,
    valid_ms: u64,
    client: Option<proto::ClientGrant>,
) -> Result<Invite> {
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

    // A one-time key binds the ticket to this invite: its secret is only in the invite.
    let (ticket_key, bind) = keys::one_time_key();
    let (ticket, admins) = invite_ticket(dir, cfg, uses, valid_ms, client, bind)?;
    let ticket_key = ticket.as_ref().map(|_| ticket_key);
    // Where to meet if neither side can reach the other (only with the DHT on, see node/join.rs).
    let join = if cfg.dht && control::is_running(dir) {
        let req = control::Request::RegisterJoin {
            until: now_ms() + valid_ms,
        };
        match tokio::runtime::Runtime::new()?.block_on(control::request(dir, &req)) {
            Ok(control::Response::Message { text }) => serde_json::from_str(&text).ok(),
            _ => None,
        }
    } else {
        None
    };
    Ok(Invite {
        network: cfg.network.clone(),
        key: cfg.network_key.clone(),
        bootstrap: boot,
        id: cfg.network_id(),
        v: cfg.key_version,
        ticket,
        ticket_key,
        admins,
        join,
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
    client: Option<proto::ClientGrant>,
    bind: keys::NodeId,
) -> Result<(Option<proto::SignedDoc>, Vec<keys::NodeId>)> {
    if control::is_running(dir) {
        let req = control::Request::IssueTicket {
            uses,
            valid_ms,
            client,
            bind: Some(bind),
        };
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
        client,
        key: Some(bind),
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
    if proto::looks_like_ssh_key(who) {
        if allow && users.is_empty() {
            bail!("say which account: --as <user>");
        }
        let msg = if allow {
            config::SshAllowKey::allow(&mut cfg.ssh_allow_keys, who, &users)?
        } else {
            config::SshAllowKey::deny(&mut cfg.ssh_allow_keys, who, &users)?
        };
        cfg.save(dir)?;
        return Ok(format!("{msg} (takes effect when meshvpn starts)"));
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
    known.dedup_by_key(|i| i.id);
    // A permission must not land on whichever device took that name last.
    if known.len() > 1 {
        let ids: Vec<String> = known.iter().map(|i| format!("  {} ({})", i.id.hex(), i.name)).collect();
        bail!(
            "{} nodes match {node:?}. Say which one by its id, or by the user's SSH public key:\n{}",
            known.len(),
            ids.join("\n")
        );
    }
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

fn print_invite(
    dir: &Path,
    cfg: &Config,
    uses: u32,
    valid_ms: u64,
    client: Option<proto::ClientGrant>,
    json: bool,
) -> Result<()> {
    let until = client.as_ref().map(|c| c.until);
    let inv = make_invite(dir, cfg, uses, valid_ms, client)?;
    if until.is_some() && inv.ticket.is_none() {
        bail!("clients need a managed network (meshvpn admin enable)");
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "invite": inv.encode(),
                "managed": inv.ticket.is_some(),
                "uses": inv.ticket.as_ref().map(|_| uses),
                "expires_ms": inv.ticket.as_ref().map(|_| now_ms() + valid_ms),
                "client_until_ms": until,
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

/// `host` -> `host:7870`; `host:port`, `[v6]:port` and `ip:port` stay as they are.
fn with_default_port(addr: &str) -> String {
    let has_port = match addr.rsplit_once(':') {
        Some((host, port)) => port.parse::<u16>().is_ok() && (!host.contains(':') || host.ends_with(']')),
        None => false,
    };
    if has_port {
        addr.to_string()
    } else if addr.contains(':') && !addr.starts_with('[') {
        format!("[{addr}]:{DEFAULT_PORT}")
    } else {
        format!("{addr}:{DEFAULT_PORT}")
    }
}

fn print_status(st: &node::Status) {
    println!(
        "● {}  {}  ({} on {}, network \"{}\", meshvpn {})",
        st.name,
        st.ip,
        &st.id[..8],
        st.interface,
        st.network,
        st.version
    );
    if let Some(v) = &st.update_available {
        println!(
            "  \x1b[1;36mupdate:\x1b[0m meshvpn {v} is available - run: {}",
            config::hint("sudo meshvpn update")
        );
    }
    if let Some(ip6) = st.mesh_ip6 {
        println!("  IPv6:         {ip6}");
    }
    if !st.banned.is_empty() {
        println!("  banned:       {}", st.banned.join(", "));
    }
    if let Some(c) = &st.client {
        let left = c.until.saturating_sub(now_ms());
        if left == 0 {
            println!(
                "  \x1b[1;33mclient:\x1b[0m {}'s computer - the admission has ended; renew it (meshvpn login)",
                c.user
            );
        } else {
            println!(
                "  client:       {}'s computer, a member for {} more",
                c.user,
                human_duration(left)
            );
        }
    }
    for w in &st.warnings {
        println!("  \x1b[1;33mwarning:\x1b[0m {w}");
    }
    if st.admins.is_empty() {
        println!("  admins:       none (open network: every member may invite and ban)");
    } else {
        let names: Vec<String> = st
            .admins
            .iter()
            .map(|a| {
                if st.is_admin && *a == st.name {
                    format!("{a} (this node)")
                } else {
                    a.clone()
                }
            })
            .collect();
        println!("  admins:       {}", names.join(", "));
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
            "  ssh server:   built-in (ssh <user>@{}.{}, logins: meshvpn ssh list)",
            st.name,
            networks::current_suffix()
        );
    }
    if let Some(t) = &st.turned_away {
        println!("  \x1b[1;31mnot admitted:\x1b[0m {t}");
    }
    if let Some(o) = &st.outbound_via {
        println!("  outgoing via: {o}");
    }
    if let Some(e) = &st.exit_via {
        println!("  internet via: {e} (exit node; meshvpn exit off)");
    }
    if st.exit_offer {
        println!("  exit node:    offers its internet connection to the network");
    }
    if let (Some(e), Some(v)) = (crate::ext::get(), &st.extension) {
        for line in e.status_lines(v) {
            println!("  {line}");
        }
    }
    if let Some(p) = &st.port_mapping {
        println!("  port mapping: {p}");
    }
    if let Some(r) = &st.rendezvous {
        println!("  rendezvous:   {r}");
    }
    if let Some(nat) = &st.nat {
        println!("  NAT (IPv4):   {nat}");
        if st.ipv6.is_empty() {
            println!("  IPv6:         none on this network");
        } else {
            println!(
                "  IPv6:         {} (direct paths through firewalls)",
                st.ipv6.join(", ")
            );
        }
    }
    println!();
    if st.peers.is_empty() {
        println!("No other nodes known yet.");
        return;
    }
    let w = st.peers.iter().map(|p| p.name.len()).max().unwrap_or(4).max(4);
    println!(
        "{:<w$}  {:<15}  {:<7}  {:>6}  {:<8}  PATH",
        "NAME", "IP", "STATUS", "RTT", "VERSION"
    );
    for p in &st.peers {
        // Older than this node: highlighted (meshvpn update there).
        let version = if p.version.is_empty() {
            format!("{:<8}", "?")
        } else if update::is_newer(&st.version, &p.version) {
            format!("\x1b[33m{:<8}\x1b[0m", p.version)
        } else {
            format!("{:<8}", p.version)
        };
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
        let path = match &p.client {
            Some(u) => format!("{path}  (client: {u})"),
            None => path,
        };
        println!(
            "{:<w$}  {:<15}  {:<7}  {:>6}  {version}  {}",
            p.name, p.ip, status, rtt, path
        );
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
        if !update::is_newer(&tag, &update::current()) {
            println!("meshvpn {} is up to date", update::current());
        } else if check {
            println!("meshvpn {tag} is available (running {})", update::current());
        } else if update::is_dev_build() && !force {
            bail!("this is a development build - update it with git pull && cargo build (or use --force)");
        } else {
            let exe = update::install(&client, &tag).await?;
            println!("updated {} -> {tag} ({})", update::current(), exe.display());
        }
        Ok(())
    })
}

/// The systemd unit of a network: `meshvpn.service`, `meshvpn-<name>.service`.
fn unit_path(dir: &Path) -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{}.service", networks::service(dir)))
}
const BIN_PATH: &str = "/usr/local/bin/meshvpn";

fn require_root() -> Result<()> {
    if !sys::is_root() {
        if config::rootless() {
            bail!("this needs root (it changes the system, which a rootless install can't) - try again with sudo");
        }
        if cfg!(windows) {
            bail!("this needs administrator rights - run it in an administrator terminal");
        }
        bail!("this needs root - try again with sudo");
    }
    Ok(())
}

/// Root, or the user owning a rootless install.
pub(crate) fn require_owner() -> Result<()> {
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
    if cfg!(windows) {
        return install_windows(&std::path::absolute(dir)?);
    }
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
    if cfg!(target_os = "macos") {
        return install_launchd(&dir, &bin);
    }
    if !systemd_running() {
        for (pid, cmd) in stop_other_daemons(&dir) {
            println!("Stopped a meshvpn that was already running (pid {pid}: {cmd}).");
        }
        return install_background(
            &dir,
            &bin,
            &PathBuf::from(format!("/var/log/{}.log", networks::service(&dir))),
        );
    }
    let svc = networks::service(&dir);
    let unit = format!(
        "[Unit]\nDescription=meshvpn decentralized mesh VPN{}\nWants=network-online.target\nAfter=network-online.target\n\n\
         [Service]\nExecStart={} --dir {} up\nRestart=always\nRestartSec=3\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        networks::name(&dir)
            .map(|n| format!(", network {n}"))
            .unwrap_or_default(),
        bin.display(),
        dir.display()
    );
    std::fs::write(unit_path(&dir), unit)?;
    systemctl(&["daemon-reload"])?;
    // The service takes over: a meshvpn started by hand (or an old version) would hold the
    // network interface and make the service fail with "Resource busy".
    let _ = systemctl(&["stop", &svc]);
    for (pid, cmd) in stop_other_daemons(&dir) {
        println!("Stopped a meshvpn that was already running (pid {pid}: {cmd}).");
    }
    systemctl(&["enable", &svc])?;
    systemctl(&["restart", &svc])?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    let active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", &svc])
        .status()
        .is_ok_and(|s| s.success());
    if !active {
        bail!("the {svc} service did not start - see: journalctl -u {svc} -n 20");
    }
    let net = networks::flag(&dir);
    match networks::name(&dir) {
        Some(n) => println!("meshvpn is running for network {n} and will start at boot."),
        None => println!("meshvpn is running and will start at boot."),
    }
    println!("  status: meshvpn{net} status   logs: journalctl -u {svc} -f");
    Ok(())
}

#[cfg(windows)]
fn schtasks(args: &[&str]) -> Result<String> {
    let out = std::process::Command::new("schtasks")
        .args(args)
        .output()
        .context("running schtasks")?;
    if !out.status.success() {
        bail!(
            "schtasks {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Windows: a task that starts meshvpn at boot as SYSTEM and restarts it after failures. The
/// binary (with wintun.dll) lives in Program Files.
#[cfg(windows)]
fn install_windows(dir: &Path) -> Result<()> {
    let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let home = PathBuf::from(program_files).join("meshvpn");
    let exe = std::env::current_exe()?;
    let bin = home.join("meshvpn.exe");
    if exe.parent() != Some(home.as_path()) {
        std::fs::create_dir_all(&home)?;
        let _ = schtasks(&["/End", "/TN", "meshvpn"]);
        std::thread::sleep(std::time::Duration::from_secs(1));
        std::fs::copy(&exe, &bin).with_context(|| format!("copying meshvpn to {}", bin.display()))?;
        let dll = exe.with_file_name("wintun.dll");
        if dll.exists() {
            std::fs::copy(&dll, home.join("wintun.dll"))?;
        }
    }
    if !home.join("wintun.dll").exists() {
        bail!(
            "wintun.dll is missing next to {} - download the full Windows release",
            bin.display()
        );
    }
    let log = dir.join("meshvpn.log");
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>meshvpn decentralized mesh VPN</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
      <Arguments>--dir "{}" up --log-file "{}"</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        esc(&bin.display().to_string()),
        esc(&dir.display().to_string()),
        esc(&log.display().to_string())
    );
    // Task Scheduler wants UTF-16 with a byte order mark.
    let file = std::env::temp_dir().join("meshvpn-task.xml");
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(xml.encode_utf16().flat_map(|u| u.to_le_bytes()));
    std::fs::write(&file, bytes)?;
    let _ = schtasks(&["/End", "/TN", "meshvpn"]);
    let created = schtasks(&["/Create", "/TN", "meshvpn", "/XML", &file.to_string_lossy(), "/F"]);
    let _ = std::fs::remove_file(&file);
    created?;
    schtasks(&["/Run", "/TN", "meshvpn"])?;
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if control::is_running(dir) {
            println!("meshvpn is running and will start at boot.");
            println!("  status: meshvpn status   log: {}", log.display());
            return Ok(());
        }
    }
    bail!("the meshvpn task did not start - see {}", log.display())
}

#[cfg(unix)]
fn install_windows(_dir: &Path) -> Result<()> {
    unreachable!("Windows only")
}

const LAUNCHD_LABEL: &str = "ai.plugovr.meshvpn";

/// The launch daemon of a network: `ai.plugovr.meshvpn`, or `ai.plugovr.meshvpn.<name>` for a
/// further one.
fn launchd_label(dir: &Path) -> String {
    match networks::name(dir) {
        Some(n) => format!("{LAUNCHD_LABEL}.{n}"),
        None => LAUNCHD_LABEL.to_string(),
    }
}

fn launchd_plist(dir: &Path) -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{}.plist", launchd_label(dir)))
}

fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    let out = std::process::Command::new("launchctl")
        .args(args)
        .output()
        .context("running launchctl")?;
    if !out.status.success() {
        bail!(
            "launchctl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out)
}

/// macOS: a launch daemon that starts at boot and is restarted when it stops.
fn install_launchd(dir: &Path, bin: &Path) -> Result<()> {
    let label = launchd_label(dir);
    let plist_path = launchd_plist(dir);
    let log = format!("/var/log/{}.log", networks::service(dir));
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{}</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>--dir</string><string>{}</string><string>up</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>3</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        esc(&label),
        esc(&bin.display().to_string()),
        esc(&dir.display().to_string())
    );
    let target = format!("system/{label}");
    let _ = launchctl(&["bootout", &target]);
    for (pid, cmd) in stop_other_daemons(dir) {
        println!("Stopped a meshvpn that was already running (pid {pid}: {cmd}).");
    }
    std::fs::write(&plist_path, plist)?;
    let plist_arg = plist_path.to_string_lossy().into_owned();
    launchctl(&["bootstrap", "system", &plist_arg])?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    let running = launchctl(&["print", &target])
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("state = running"))
        .unwrap_or(false);
    if !running {
        bail!("the meshvpn service did not start - see: tail {log}");
    }
    match networks::name(dir) {
        Some(n) => println!("meshvpn is running for network {n} and will start at boot."),
        None => println!("meshvpn is running and will start at boot."),
    }
    println!("  status: meshvpn{} status   logs: tail -f {log}", networks::flag(dir));
    Ok(())
}

/// `meshvpn [options] up`, started from any path.
fn is_daemon_cmdline(args: &[String]) -> bool {
    let is_meshvpn = args
        .first()
        .is_some_and(|a| Path::new(a).file_name().is_some_and(|n| n == "meshvpn"));
    is_meshvpn && args.iter().skip(1).any(|a| a == "up")
}

/// The network directory a daemon's command line runs (None: the default one).
fn daemon_dir(args: &[String]) -> Option<PathBuf> {
    let i = args.iter().position(|a| a == "--dir")?;
    let d = PathBuf::from(args.get(i + 1)?);
    Some(std::path::absolute(&d).unwrap_or(d))
}

/// Is that daemon the one of network `dir`? One without --dir runs a machine's first network.
fn runs_network(args: &[String], dir: &Path) -> bool {
    let dir = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    // `meshvpn --net lab up`: a further network by its name.
    let net = args
        .iter()
        .enumerate()
        .find_map(|(i, a)| match a.strip_prefix("--net=") {
            Some(v) => Some(v.to_string()),
            None if a == "--net" => args.get(i + 1).cloned(),
            None => None,
        });
    if let Some(n) = net
        && daemon_dir(args).is_none()
    {
        return networks::name(&dir).as_deref() == Some(n.as_str());
    }
    match daemon_dir(args) {
        Some(d) => d == dir,
        None => !networks::is_extra(&dir),
    }
}

/// Stops meshvpn daemons (`meshvpn ... up`) of network `dir` other than this process (those of
/// the machine's other networks keep running). Returns what it stopped.
fn stop_other_daemons(dir: &Path) -> Vec<(i32, String)> {
    let me = std::process::id() as i32;
    let mut stopped = vec![];
    for (pid, args) in sys::processes() {
        if pid == me || !is_daemon_cmdline(&args) || !runs_network(&args, dir) {
            continue;
        }
        if !sys::terminate(pid) {
            continue; // another user's (rootless) meshvpn
        }
        for _ in 0..50 {
            if !sys::alive(pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if sys::alive(pid) {
            sys::kill(pid);
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
    #[cfg(windows)]
    {
        let _ = schtasks(&["/End", "/TN", "meshvpn"]);
        let _ = schtasks(&["/Delete", "/TN", "meshvpn", "/F"]);
    }
    if cfg!(target_os = "macos") {
        let _ = launchctl(&["bootout", &format!("system/{}", launchd_label(dir))]);
        std::fs::remove_file(launchd_plist(dir)).ok();
    } else if systemd_running() {
        let _ = systemctl(&["disable", "--now", &networks::service(dir)]);
    } else {
        remove_cron_entry(dir);
        for (pid, cmd) in stop_other_daemons(dir) {
            println!("Stopped meshvpn (pid {pid}: {cmd}).");
        }
    }
    match networks::name(dir) {
        Some(n) => {
            std::fs::remove_file(node::ssh_client_dropin_extra(&n)).ok();
        }
        None => {
            // sshd asks every network of this machine: it stays while one of them runs.
            if networks::all(dir).len() <= 1 {
                sshd::disable();
            }
            node::remove_ssh_client_config();
        }
    }
    std::fs::remove_file(unit_path(dir)).ok();
    let _ = systemctl(&["daemon-reload"]);
    match networks::name(dir) {
        Some(n) => println!("meshvpn service of network {n} removed (configuration kept)."),
        None => println!("meshvpn service removed (configuration kept)."),
    }
    Ok(())
}

const CRON_MARK: &str = "# meshvpn rootless";

/// The crontab mark of a network's entry.
fn cron_mark(dir: &Path) -> String {
    match networks::name(dir) {
        Some(n) => format!("{CRON_MARK} network {n}"),
        None => CRON_MARK.to_string(),
    }
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is not set"))
}

fn user_unit_path(dir: &Path) -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(x) => PathBuf::from(x),
        None => home()?.join(".config"),
    };
    Ok(base.join(format!("systemd/user/{}.service", networks::service(dir))))
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

fn remove_cron_entry(dir: &Path) {
    if let Some(lines) = crontab_lines(dir) {
        let before = std::process::Command::new("crontab")
            .arg("-l")
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.ends_with(&cron_mark(dir)))
            })
            .unwrap_or(false);
        if before {
            let _ = set_crontab(&lines);
        }
    }
}

fn crontab_lines(dir: &Path) -> Option<Vec<String>> {
    let out = std::process::Command::new("crontab").arg("-l").output().ok()?;
    // "no crontab for user" is an empty one; a missing crontab binary is None.
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.ends_with(&cron_mark(dir)))
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
    for (pid, cmd) in stop_other_daemons(&dir) {
        println!("Stopped a meshvpn that was already running (pid {pid}: {cmd}).");
    }
    if user_systemd() {
        let svc = networks::service(&dir);
        let unit_path = user_unit_path(&dir)?;
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
        systemctl(&["--user", "enable", &svc])?;
        systemctl(&["--user", "restart", &svc])?;
        std::thread::sleep(std::time::Duration::from_secs(2));
        let active = std::process::Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", &svc])
            .status()
            .is_ok_and(|s| s.success());
        if !active {
            bail!("the {svc} user service did not start - see: journalctl --user -u {svc} -n 20");
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
        println!(
            "  status: meshvpn{} status   logs: journalctl --user -u {svc} -f",
            networks::flag(&dir)
        );
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
    sys::detach(&mut c);
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
    let cron = crontab_lines(dir).filter(|_| !in_container).map(|mut lines| {
        lines.push(format!("@reboot {cmd} >> {} 2>&1 {}", log.display(), cron_mark(dir)));
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
    let net = networks::flag(dir);
    println!("  status: meshvpn{net} status   stop: meshvpn{net} uninstall");
    Ok(())
}

fn uninstall_user(dir: &Path) -> Result<()> {
    if let Ok(unit) = user_unit_path(dir)
        && unit.exists()
    {
        let _ = systemctl(&["--user", "disable", "--now", &networks::service(dir)]);
        std::fs::remove_file(&unit).ok();
        let _ = systemctl(&["--user", "daemon-reload"]);
    }
    remove_cron_entry(dir);
    for (pid, cmd) in stop_other_daemons(dir) {
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
    #[test]
    fn launch_daemons_per_network() {
        let first = Path::new("/etc/meshvpn");
        let lab = Path::new("/etc/meshvpn/networks/lab");
        assert_eq!(launchd_label(first), "ai.plugovr.meshvpn");
        assert_eq!(launchd_label(lab), "ai.plugovr.meshvpn.lab");
        assert_eq!(
            launchd_plist(lab),
            Path::new("/Library/LaunchDaemons/ai.plugovr.meshvpn.lab.plist")
        );
    }

    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    /// Splits a shell command line (quotes, no expansion).
    fn shell_words(line: &str) -> Vec<String> {
        let (mut words, mut cur, mut quote, mut any) = (vec![], String::new(), None, false);
        for c in line.chars() {
            match (quote, c) {
                (Some(q), c) if c == q => quote = None,
                (Some(_), c) => cur.push(c),
                (None, '\'' | '"') => {
                    quote = Some(c);
                    any = true;
                }
                (None, ' ') => {
                    if any || !cur.is_empty() {
                        words.push(std::mem::take(&mut cur));
                    }
                    any = false;
                }
                (None, c) => cur.push(c),
            }
        }
        if any || !cur.is_empty() {
            words.push(cur);
        }
        words
    }

    #[test]
    fn connect_adds_the_default_port() {
        assert_eq!(with_default_port("edge.example.com"), "edge.example.com:7870");
        assert_eq!(with_default_port("203.0.113.7"), "203.0.113.7:7870");
        assert_eq!(with_default_port("203.0.113.7:443"), "203.0.113.7:443");
        assert_eq!(with_default_port("2001:db8::1"), "[2001:db8::1]:7870");
        assert_eq!(with_default_port("[2001:db8::1]:443"), "[2001:db8::1]:443");
        assert!(Cli::try_parse_from(["meshvpn", "add-peer", "h:1"]).is_ok());
    }

    #[test]
    fn agent_guide_commands_parse() {
        // Every command in the guide's code blocks must be valid for this CLI.
        let mut in_code = false;
        let mut checked = 0;
        for line in guide::GUIDE.lines() {
            if line.starts_with("```") {
                in_code = !in_code;
                continue;
            }
            let line = line.split(" # ").next().unwrap().trim();
            if !in_code || !line.starts_with("meshvpn ") {
                continue;
            }
            let line = line
                .replace("<id>", "abc123")
                .replace("<name>", "data")
                .replace("<what for>", "test");
            let words = shell_words(&line);
            if let Err(e) = Cli::try_parse_from(&words) {
                panic!("guide command doesn't parse: {line}\n{e}");
            }
            checked += 1;
        }
        assert!(checked >= 20, "only {checked} commands found in the guide");
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

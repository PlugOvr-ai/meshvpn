//! `meshvpn doctor`: checks the things that typically go wrong and says how to fix them.

use serde::Serialize;
use std::path::Path;
use std::process::Command;

use crate::config::Config;
use crate::control;
use crate::node::Status;

#[derive(Serialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
    Skip,
}

#[derive(Serialize)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

fn check(name: &'static str, level: Level, detail: impl Into<String>, fix: Option<&str>) -> Check {
    Check {
        name,
        level,
        detail: detail.into(),
        fix: fix.map(crate::config::hint),
    }
}

fn root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    Some(format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// `meshvpn ... up` processes (pid, command line) of this machine - not of containers, whose
/// processes are visible from the host but live in other network namespaces.
fn daemons() -> Vec<(i32, String)> {
    let mut out = vec![];
    let my_net = std::fs::read_link("/proc/self/ns/net").ok();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|p| p.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let args: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let is = args
            .first()
            .is_some_and(|a| Path::new(a).file_name().is_some_and(|n| n == "meshvpn"));
        let same_net = my_net.is_none() || std::fs::read_link(format!("/proc/{pid}/ns/net")).ok() == my_net;
        if is && same_net && args.iter().skip(1).any(|a| a == "up") {
            out.push((pid, args.join(" ")));
        }
    }
    out
}

fn status(dir: &Path) -> Option<Status> {
    let rt = tokio::runtime::Runtime::new().ok()?;
    match rt.block_on(control::request(dir, &control::Request::Status)).ok()? {
        control::Response::Status(s) => Some(*s),
        _ => None,
    }
}

pub fn diagnose(dir: &Path) -> Vec<Check> {
    let mut c = vec![];
    let exe = crate::update::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    c.push(check(
        "version",
        Level::Info,
        format!("meshvpn {} ({exe})", env!("CARGO_PKG_VERSION")),
        None,
    ));
    if crate::config::rootless() {
        c.push(check(
            "privileges",
            Level::Info,
            format!(
                "rootless install in {}: userspace networking, no /etc/hosts entries, no firewall or sshd changes",
                dir.display()
            ),
            None,
        ));
    } else if !root() {
        c.push(check(
            "privileges",
            Level::Info,
            "not running as root: configuration, firewall and sshd checks are skipped",
            Some("run `sudo meshvpn doctor` for the full check"),
        ));
    }

    // --- configuration
    let cfg = match Config::load(dir) {
        Ok(cfg) => {
            c.push(check(
                "configuration",
                Level::Ok,
                format!("{} in network \"{}\"", cfg.name, cfg.network),
                None,
            ));
            Some(cfg)
        }
        Err(e) if e.to_string().contains("sudo") => {
            c.push(check("configuration", Level::Skip, "needs root to read", None));
            None
        }
        Err(e) => {
            c.push(check(
                "configuration",
                Level::Fail,
                format!("{e:#}"),
                Some("create a network with `sudo meshvpn init` or join one with `sudo meshvpn join <invite>`"),
            ));
            return c;
        }
    };

    // --- daemon
    let st = status(dir);
    let procs = daemons();
    let user: &[&str] = if crate::config::rootless() { &["--user"] } else { &[] };
    let service = run("systemctl", &[user, &["is-active", "meshvpn"]].concat()).map(|s| s.trim().to_string());
    match &st {
        Some(st) => c.push(check(
            "daemon",
            Level::Ok,
            format!("running ({} peers known)", st.peers.len()),
            None,
        )),
        None => {
            let journal = run(
                "journalctl",
                &[user, &["-u", "meshvpn", "-n", "30", "--no-pager"]].concat(),
            )
            .unwrap_or_default();
            let last_error = journal
                .lines()
                .rev()
                .find(|l| l.contains("error:"))
                .map(|l| l.split("error:").nth(1).unwrap_or(l).trim().to_string());
            if service.as_deref() == Some("activating") || last_error.as_deref().is_some_and(|e| e.contains("in use")) {
                let blockers: Vec<String> = procs.iter().map(|(p, cmd)| format!("{p} ({cmd})")).collect();
                c.push(check(
                    "daemon",
                    Level::Fail,
                    format!(
                        "the service keeps failing{}{}",
                        last_error.map(|e| format!(": {e}")).unwrap_or_default(),
                        if blockers.is_empty() {
                            String::new()
                        } else {
                            format!("; running: {}", blockers.join(", "))
                        }
                    ),
                    Some("stop other copies and restart: sudo pkill -f 'meshvpn.* up'; sudo systemctl restart meshvpn"),
                ));
            } else {
                c.push(check(
                    "daemon",
                    Level::Fail,
                    "meshvpn is not running",
                    Some("start it: sudo systemctl start meshvpn (or sudo meshvpn install / sudo meshvpn up)"),
                ));
            }
        }
    }
    if procs.len() > 1 {
        c.push(check(
            "daemon",
            Level::Warn,
            format!(
                "{} meshvpn daemons are running: {:?}",
                procs.len(),
                procs.iter().map(|p| p.0).collect::<Vec<_>>()
            ),
            Some("keep only the service: sudo pkill -f 'meshvpn.* up'; sudo systemctl restart meshvpn"),
        ));
    }
    let Some(st) = st else { return c };
    if let Some(t) = &st.turned_away {
        c.push(check(
            "membership",
            Level::Fail,
            format!("the network turned this node away ({t})"),
            Some("ask an admin for a new invite: meshvpn invite (on an admin node), then: sudo meshvpn join --force <invite>"),
        ));
    }
    let older = crate::update::is_newer(env!("CARGO_PKG_VERSION"), &st.version);
    if older {
        c.push(check(
            "daemon",
            Level::Warn,
            format!(
                "the running daemon is meshvpn {} - older than this one ({}), so newer checks and features are missing",
                st.version,
                env!("CARGO_PKG_VERSION")
            ),
            Some("sudo meshvpn update (or restart the service after installing)"),
        ));
    }

    // --- interface and address range
    if let Some(s) = &st.socks {
        c.push(check(
            "interface",
            Level::Info,
            format!("userspace mode (no TUN device): programs reach the mesh via socks5h://{s}"),
            if crate::config::rootless() {
                Some("for kernel mode (all programs, names in /etc/hosts) install meshvpn as root instead")
            } else {
                Some("for the full kernel mode give the container --cap-add=NET_ADMIN --device=/dev/net/tun")
            },
        ));
    } else {
        c.push(check(
            "interface",
            Level::Ok,
            format!("{} with {}", st.interface, st.ip),
            None,
        ));
    }
    if st.warnings.is_empty() {
        c.push(check(
            "address range",
            Level::Ok,
            "no other interface uses 100.64.0.0/10",
            None,
        ));
    }
    for w in &st.warnings {
        c.push(check("address range", Level::Fail, w.clone(), None));
    }

    // --- firewall
    if root() {
        let rules = run("iptables", &["-S"]).unwrap_or_default();
        if rules.contains("100.64.0.0/10") && rules.contains("ts-input") && rules.contains("DROP") {
            c.push(check(
                "firewall",
                Level::Fail,
                "Tailscale's firewall drops all mesh traffic (DROP 100.64.0.0/10 not from tailscale0)",
                Some("uninstall Tailscale on this machine, or: sudo tailscale down"),
            ));
        }
        let input_drop = rules.lines().any(|l| l == "-P INPUT DROP" || l == "-P INPUT REJECT");
        let mesh_allowed = rules.contains(&format!("-i {}", st.interface)) || rules.contains("-i mesh+");
        let ufw = run("ufw", &["status"]).unwrap_or_default();
        if ufw.contains("Status: active") && !ufw.contains(&st.interface) {
            c.push(check(
                "firewall",
                Level::Warn,
                "ufw is active and has no rule for the mesh interface: other nodes can't reach services here",
                Some(&format!("sudo ufw allow in on {}", st.interface)),
            ));
        } else if input_drop && !mesh_allowed && st.socks.is_none() {
            c.push(check(
                "firewall",
                Level::Warn,
                "the INPUT policy drops packets and nothing allows the mesh interface",
                Some(&format!("sudo iptables -I INPUT -i {} -j ACCEPT", st.interface)),
            ));
        } else if !rules.contains("ts-input") {
            c.push(check("firewall", Level::Ok, "nothing blocks the mesh interface", None));
        }
    } else {
        c.push(check("firewall", Level::Skip, "needs root", None));
    }

    // --- peers and paths
    let online: Vec<_> = st.peers.iter().filter(|p| p.online).collect();
    let offline = st.peers.len() - online.len();
    if st.peers.is_empty() {
        c.push(check(
            "peers",
            Level::Warn,
            "no other nodes known yet",
            Some("check the bootstrap address in the invite and that TCP 7870 is reachable there"),
        ));
    } else if online.is_empty() {
        c.push(check(
            "peers",
            Level::Fail,
            format!("none of the {} known nodes is online", st.peers.len()),
            Some("check the network connection, and that other nodes' TCP port 7870 is reachable"),
        ));
    } else {
        let relayed = online.iter().filter(|p| p.path.starts_with("relay")).count();
        c.push(check(
            "peers",
            Level::Ok,
            format!(
                "{} online, {offline} offline, {relayed} reached through a relay",
                online.len()
            ),
            None,
        ));
    }
    let udp = online.iter().filter(|p| p.path.contains("UDP")).count();
    let udp_off = cfg
        .as_ref()
        .is_some_and(|c| !c.udp || c.no_outbound || c.effective_socks().is_some());
    if udp_off {
        c.push(check(
            "udp",
            Level::Info,
            "direct UDP paths are off (udp = false, SSH tunnel or proxy)",
            None,
        ));
    } else if older && crate::update::is_newer("0.6.0", &st.version) {
        c.push(check(
            "udp",
            Level::Info,
            "the running daemon has no direct UDP paths yet (since v0.6)",
            None,
        ));
    } else if !online.is_empty() && udp == 0 {
        c.push(check(
            "udp",
            Level::Warn,
            "no direct UDP path to any node: traffic goes over TCP or relays (slower)",
            Some("allow UDP 7870 in front of public nodes; behind a 'hard' NAT that rewrites ports per destination it stays relayed"),
        ));
    } else if !online.is_empty() {
        c.push(check(
            "udp",
            Level::Ok,
            format!("direct UDP paths to {udp} of {} online nodes", online.len()),
            None,
        ));
    }
    if st.endpoints.is_empty() && st.socks.is_none() {
        c.push(check(
            "reachability",
            Level::Info,
            "this node advertises no address: others can't connect to it, it connects out (fine behind NAT)",
            None,
        ));
    }

    // --- SSH logins
    if let Some(last) = st.ssh_refused.last() {
        c.push(check(
            "ssh logins",
            Level::Warn,
            format!("refused recently ({last})"),
            Some("all recent ones: meshvpn ssh list"),
        ));
    }
    if let Some(cfg) = &cfg {
        let has_rules = !cfg.ssh_allow.is_empty() || !cfg.ssh_allow_all.is_empty();
        if st.ssh_server.as_deref() == Some("built-in") {
            c.push(check(
                "ssh logins",
                if has_rules { Level::Ok } else { Level::Info },
                if has_rules {
                    "meshvpn's built-in SSH server answers ssh to this node".to_string()
                } else {
                    "meshvpn's built-in SSH server answers ssh to this node, but nobody may log in yet".to_string()
                },
                (!has_rules).then_some("allow logins: sudo meshvpn ssh allow <user>@<node> --as <local user>"),
            ));
        } else if has_rules && (crate::config::rootless() || !crate::sshserver::sshd_installed()) {
            c.push(check(
                "ssh logins",
                Level::Warn,
                "password-less logins are configured, but nothing answers ssh here",
                Some("set ssh_server = \"auto\" (or \"always\") in the config and restart meshvpn"),
            ));
        } else if has_rules {
            let effective = run("sshd", &["-T"])
                .or_else(|| run("/usr/sbin/sshd", &["-T"]))
                .unwrap_or_default();
            if effective.contains("authorizedkeyscommand") && effective.contains("ssh-authorized-keys") {
                c.push(check(
                    "ssh logins",
                    Level::Ok,
                    "sshd asks meshvpn for allowed keys",
                    None,
                ));
            } else {
                c.push(check(
                    "ssh logins",
                    Level::Fail,
                    "password-less logins are configured, but sshd doesn't ask meshvpn",
                    Some("restart meshvpn (it sets sshd up when it starts), or run: sudo meshvpn ssh allow ..."),
                ));
            }
        }
    }

    // --- admins
    let admin = tokio::runtime::Runtime::new().ok().and_then(|rt| {
        match rt
            .block_on(control::request(dir, &control::Request::AdminStatus))
            .ok()?
        {
            control::Response::Message { text } => serde_json::from_str::<serde_json::Value>(&text).ok(),
            _ => None,
        }
    });
    match admin {
        Some(a) if a["managed"] == false => c.push(check(
            "admins",
            Level::Warn,
            "open network: every member may invite and ban",
            Some("on your main node: sudo meshvpn admin enable"),
        )),
        Some(a) if a["managed"] == true => {
            let admins: Vec<String> = a["admins"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(String::from))
                .collect();
            let online_admin = admins
                .iter()
                .any(|n| *n == st.name || online.iter().any(|p| p.name == *n));
            c.push(check(
                "admins",
                if online_admin { Level::Ok } else { Level::Info },
                format!(
                    "managed network, admins: {}{}",
                    admins.join(", "),
                    if online_admin {
                        ""
                    } else {
                        " (none online: no new invites right now)"
                    }
                ),
                None,
            ));
        }
        // A daemon that predates admin roles.
        _ => c.push(check(
            "admins",
            Level::Info,
            "the running daemon predates admin roles (v0.7)",
            Some("sudo meshvpn update"),
        )),
    }

    // --- updates
    if let Some(v) = &st.update_available {
        c.push(check(
            "updates",
            Level::Warn,
            format!("meshvpn {v} is available"),
            Some("sudo meshvpn update"),
        ));
    } else if cfg.as_ref().is_some_and(|c| !c.auto_update) {
        c.push(check(
            "updates",
            Level::Info,
            "automatic updates are off (auto_update = false)",
            None,
        ));
    } else {
        c.push(check("updates", Level::Ok, "up to date as far as known", None));
    }
    c
}

pub fn print(checks: &[Check]) {
    for ch in checks {
        let (mark, color) = match ch.level {
            Level::Ok => ("✓", "32"),
            Level::Info => ("·", "36"),
            Level::Warn => ("!", "33"),
            Level::Fail => ("✗", "31"),
            Level::Skip => ("-", "90"),
        };
        println!("\x1b[{color}m{mark}\x1b[0m {:<14} {}", ch.name, ch.detail);
        if let Some(f) = &ch.fix {
            println!("  {:<14} \x1b[1m→ {f}\x1b[0m", "");
        }
    }
    let fails = checks.iter().filter(|c| c.level == Level::Fail).count();
    let warns = checks.iter().filter(|c| c.level == Level::Warn).count();
    println!();
    match (fails, warns) {
        (0, 0) => println!("Everything looks fine."),
        _ => println!("{fails} problem(s), {warns} warning(s)."),
    }
}

//! Tab completion for bash (and zsh through bashcompinit).
//!
//! The shell asks meshvpn itself (`meshvpn __complete <line> <point>`) on every Tab, so commands
//! and options come from the same definition as the parser, an extension's commands included,
//! and node names, tags and networks are the ones of the network right now.

use std::path::{Path, PathBuf};

/// The script for ~/.bashrc or a bash-completion directory (`meshvpn completion bash`).
pub const BASH: &str = r#"# meshvpn bash completion (meshvpn completion bash)
_meshvpn() {
    local IFS=$'\n' cur=${COMP_WORDS[COMP_CWORD]} out c i files=0
    out=$("$1" __complete "$COMP_LINE" "$COMP_POINT" 2>/dev/null) || return 0
    COMPREPLY=()
    for c in $out; do
        if [[ $c == __files__ ]]; then files=1; else COMPREPLY+=("$c"); fi
    done
    # bash splits words at : and =, the candidates are whole words: keep what follows the split.
    local word=${COMP_LINE:0:COMP_POINT}
    word=${word##*[[:space:]]}
    local cut=$(( ${#word} - ${#cur} ))
    if (( cut > 0 )); then
        for i in "${!COMPREPLY[@]}"; do COMPREPLY[i]=${COMPREPLY[i]:cut}; done
    fi
    if (( files )); then
        COMPREPLY+=($(compgen -f -- "$cur"))
        compopt -o filenames 2>/dev/null
    fi
    # `node:` goes on with a path, `user@` with a node: no space after them.
    for c in "${COMPREPLY[@]}"; do
        if [[ $c == *: || $c == *@ ]]; then compopt -o nospace 2>/dev/null; break; fi
    done
}
complete -F _meshvpn meshvpn
"#;

/// Arguments that name nodes (`exec tag:gpu`, `ssh allow alice@laptop`, `desktop gpu1`).
const NODE_ARGS: &[&str] = &["selectors", "node", "nodes", "who", "master", "target", "peer", "from"];

/// What the network knows right now, for candidates.
#[derive(Default)]
struct Known {
    nodes: Vec<String>,
    tags: Vec<String>,
    networks: Vec<String>,
}

impl Known {
    fn load(base: &Path) -> Self {
        let mut k = Known::default();
        for (name, dir) in crate::networks::all(base) {
            if !name.is_empty() {
                k.networks.push(name);
            }
            let (nodes, tags) = nodes_of(&dir);
            k.nodes.extend(nodes);
            k.tags.extend(tags);
        }
        if crate::networks::all(base).is_empty() {
            let (nodes, tags) = nodes_of(base);
            k.nodes = nodes;
            k.tags = tags;
        }
        for v in [&mut k.nodes, &mut k.tags] {
            v.sort();
            v.dedup();
        }
        k
    }
}

/// Names and tags of a network's nodes: from its daemon (quickly), else from what it saved.
fn nodes_of(dir: &Path) -> (Vec<String>, Vec<String>) {
    let asked = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
        .and_then(|rt| {
            rt.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_millis(800),
                    crate::control::request(dir, &crate::control::Request::Status),
                )
                .await
                .ok()?
                .ok()
            })
        });
    if let Some(crate::control::Response::Status(st)) = asked {
        let tags = st
            .peers
            .iter()
            .flat_map(|p| p.tags.clone())
            .chain(st.tags.clone())
            .collect();
        let mut names: Vec<String> = st.peers.into_iter().map(|p| p.name).collect();
        names.push(st.name);
        return (names, tags);
    }
    let Ok(cfg) = crate::config::Config::load(dir) else {
        return (vec![], vec![]);
    };
    let net = cfg.network_id();
    let infos: Vec<crate::proto::NodeInfo> = crate::config::SavedState::load(dir)
        .peers
        .iter()
        .filter_map(|p| p.verify(&net).ok())
        .collect();
    let tags = infos.iter().flat_map(|i| i.tags.clone()).collect();
    let mut names: Vec<String> = infos.into_iter().map(|i| i.name).collect();
    names.push(cfg.name);
    (names, tags)
}

/// The words of `line` up to `point` (characters, as bash counts), the last one being the one
/// to complete ("" after a space).
fn words(line: &str, point: usize) -> Vec<String> {
    let before: String = line.chars().take(point).collect();
    let mut w: Vec<String> = before.split_whitespace().map(String::from).collect();
    if before.is_empty() || before.ends_with(char::is_whitespace) {
        w.push(String::new());
    }
    w
}

/// Candidates for the last word of `line`. `__files__` among them: file names fit too.
pub fn complete(mut cmd: clap::Command, base: &Path, line: &str, point: usize) -> Vec<String> {
    cmd.build();
    let words = words(line, point);
    let Some((cur, done)) = words.split_last() else {
        return vec![];
    };
    let mut cmd = &cmd;
    let mut pending: Option<&clap::Arg> = None;
    let mut positional = 0usize;
    let mut rest = false;
    for w in done.iter().skip(1) {
        if rest {
            continue;
        }
        if pending.take().is_some() {
            continue;
        }
        if w == "--" {
            rest = true;
        } else if let Some(long) = w.strip_prefix("--") {
            if !long.contains('=') {
                pending = cmd
                    .get_arguments()
                    .find(|a| a.get_long() == Some(long))
                    .filter(|a| takes_value(a));
            }
        } else if let Some(short) = w.strip_prefix('-').filter(|s| s.chars().count() == 1) {
            let c = short.chars().next().unwrap_or(' ');
            pending = cmd
                .get_arguments()
                .find(|a| a.get_short() == Some(c))
                .filter(|a| takes_value(a));
        } else if let Some(sub) = cmd.find_subcommand(w) {
            cmd = sub;
            positional = 0;
        } else {
            positional += 1;
        }
    }
    if rest {
        // The command for the nodes (`exec ... -- nvidia-smi`): the shell's own business.
        return vec!["__files__".into()];
    }
    let known = std::cell::OnceCell::new();
    let known = || known.get_or_init(|| Known::load(base));
    let mut out: Vec<String> = vec![];
    if let Some(arg) = pending {
        out = values(arg, cur, known);
    } else if let Some((long, value)) = cur.strip_prefix("--").and_then(|c| c.split_once('=')) {
        if let Some(arg) = cmd.get_arguments().find(|a| a.get_long() == Some(long)) {
            out = values(arg, value, known)
                .into_iter()
                .map(|v| if v == "__files__" { v } else { format!("--{long}={v}") })
                .collect();
        }
    } else if cur.starts_with('-') {
        for a in cmd.get_arguments().filter(|a| !a.is_hide_set()) {
            if let Some(l) = a.get_long() {
                out.push(format!("--{l}"));
            }
        }
    } else {
        out.extend(
            cmd.get_subcommands()
                .filter(|s| !s.is_hide_set() && s.get_name() != "help")
                .map(|s| s.get_name().to_string()),
        );
        if let Some(arg) = positional_arg(cmd, positional) {
            out.extend(values(arg, cur, known));
        }
    }
    out.retain(|c| c == "__files__" || c.starts_with(cur.as_str()));
    out.dedup();
    out
}

fn takes_value(a: &clap::Arg) -> bool {
    a.get_action().takes_values()
}

/// The positional argument the `n`-th free word goes to (the last one takes all the rest if it
/// takes several).
fn positional_arg(cmd: &clap::Command, n: usize) -> Option<&clap::Arg> {
    let mut left = n;
    for a in cmd.get_positionals() {
        let many = a.get_num_args().is_some_and(|r| r.max_values() > 1);
        if left == 0 || many {
            return Some(a);
        }
        left -= 1;
    }
    None
}

/// Candidates for a value of `arg`, the word typed so far being `cur`.
fn values<'a>(arg: &clap::Arg, cur: &str, known: impl Fn() -> &'a Known) -> Vec<String> {
    let id = arg.get_id().as_str();
    let possible: Vec<String> = arg
        .get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| v.get_name().to_string())
        .collect();
    if !possible.is_empty() {
        return possible;
    }
    if id == "net" {
        return known().networks.clone();
    }
    if NODE_ARGS.contains(&id) {
        let k = known();
        // `user@node`: the node part.
        let (user, _) = cur.rsplit_once('@').unwrap_or(("", cur));
        let at = if user.is_empty() {
            String::new()
        } else {
            format!("{user}@")
        };
        let mut out: Vec<String> = k.nodes.iter().map(|n| format!("{at}{n}")).collect();
        if at.is_empty() {
            if id == "who" {
                out.push("everyone".into());
            } else {
                out.push("all".into());
                out.extend(k.tags.iter().map(|t| format!("tag:{t}")));
            }
        }
        return out;
    }
    if id == "paths" {
        // `meshvpn cp ./data gpu1:/srv/`: local files, or a node and its path.
        if cur.contains(':') {
            return vec![];
        }
        let k = known();
        let mut out: Vec<String> = k.nodes.iter().map(|n| format!("{n}:")).collect();
        out.extend(k.tags.iter().map(|t| format!("tag:{t}:")));
        out.push("__files__".into());
        return out;
    }
    let path = arg.get_value_parser().type_id() == std::any::TypeId::of::<PathBuf>()
        || arg
            .get_value_names()
            .is_some_and(|n| n.iter().any(|v| ["FILE", "DIR", "PATH"].contains(&v.as_str())));
    if path {
        return vec!["__files__".into()];
    }
    vec![]
}

/// Where the script goes so bash finds it: bash-completion's directory (system or the user's).
fn script_path() -> Option<PathBuf> {
    if crate::sys::is_root() {
        let dirs = [
            "/usr/share/bash-completion/completions",
            "/usr/local/etc/bash_completion.d",
            "/etc/bash_completion.d",
        ];
        let dir = dirs
            .iter()
            .map(PathBuf::from)
            .find(|d| d.is_dir())
            .unwrap_or(PathBuf::from(dirs[2]));
        Some(dir.join("meshvpn"))
    } else {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
        Some(data.join("bash-completion/completions/meshvpn"))
    }
}

const BEGIN: &str = "# BEGIN meshvpn completion (managed by meshvpn install)";
const END: &str = "# END meshvpn completion";

/// Without bash-completion (many container images) nothing loads completion directories:
/// ~/.bashrc of whoever installs does, in a marked block.
fn bashrc() -> Option<PathBuf> {
    let framework = ["/usr/share/bash-completion/bash_completion", "/etc/bash_completion"]
        .iter()
        .any(|p| Path::new(p).exists());
    if framework {
        return None;
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".bashrc"))
}

/// `meshvpn install`: puts the script where bash finds it. Best effort: completion is a
/// convenience, nothing depends on it.
#[cfg(unix)]
pub fn install() -> Option<PathBuf> {
    let path = script_path()?;
    std::fs::create_dir_all(path.parent()?).ok()?;
    std::fs::write(&path, BASH).ok()?;
    if let Some(rc) = bashrc() {
        let have = std::fs::read_to_string(&rc).unwrap_or_default();
        if !have.contains(BEGIN) {
            let block = format!(
                "{BEGIN}\n[ -f {0} ] && . {0}\n{END}\n",
                crate::agent::sh_quote(&path.to_string_lossy())
            );
            let sep = if have.is_empty() || have.ends_with('\n') {
                ""
            } else {
                "\n"
            };
            std::fs::write(&rc, format!("{have}{sep}{block}")).ok()?;
        }
    }
    Some(path)
}

#[cfg(not(unix))]
pub fn install() -> Option<PathBuf> {
    None
}

/// `meshvpn uninstall` of all networks: the script and the block in ~/.bashrc go.
pub fn uninstall() {
    if let Some(path) = script_path()
        && std::fs::read_to_string(&path).is_ok_and(|t| t.starts_with("# meshvpn bash completion"))
    {
        let _ = std::fs::remove_file(path);
    }
    let Some(rc) = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".bashrc")) else {
        return;
    };
    let Ok(have) = std::fs::read_to_string(&rc) else { return };
    if !have.contains(BEGIN) {
        return;
    }
    let mut kept = String::new();
    let mut inside = false;
    for line in have.lines() {
        if line == BEGIN {
            inside = true;
        } else if line == END {
            inside = false;
        } else if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    let _ = std::fs::write(&rc, kept);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, Command};

    fn cli() -> Command {
        Command::new("meshvpn")
            .arg(Arg::new("net").long("net").global(true))
            .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).global(true))
            .subcommand(
                Command::new("exec")
                    .arg(Arg::new("user").long("user").short('u'))
                    .arg(Arg::new("selectors").num_args(1..).required(true))
                    .arg(Arg::new("command").last(true).num_args(1..)),
            )
            .subcommand(Command::new("cp").arg(Arg::new("paths").num_args(2..)))
            .subcommand(
                Command::new("ssh").subcommand(
                    Command::new("allow")
                        .arg(Arg::new("who"))
                        .arg(Arg::new("as").long("as").num_args(1..)),
                ),
            )
            .subcommand(Command::new("share").arg(Arg::new("path").value_parser(clap::value_parser!(PathBuf))))
            .subcommand(Command::new("hidden").hide(true))
    }

    fn c(line: &str) -> Vec<String> {
        // No network here: no nodes, so only the structure is tested.
        let base = std::env::temp_dir().join("mv-completion-none");
        complete(cli(), &base, line, line.chars().count())
    }

    #[test]
    fn commands_options_and_values() {
        assert_eq!(c("meshvpn e"), vec!["exec"]);
        let all = c("meshvpn ");
        assert!(all.contains(&"cp".to_string()) && all.contains(&"ssh".to_string()));
        assert!(!all.contains(&"hidden".to_string()), "hidden commands stay hidden");
        assert_eq!(c("meshvpn ssh a"), vec!["allow"]);
        assert_eq!(c("meshvpn ssh allow e"), vec!["everyone"]);
        let opts = c("meshvpn exec --");
        assert!(
            opts.contains(&"--user".to_string()) && opts.contains(&"--json".to_string()),
            "{opts:?}"
        );
        assert_eq!(c("meshvpn exec al"), vec!["all"]);
        // After --: the command for the nodes.
        assert_eq!(c("meshvpn exec all -- nvi"), vec!["__files__"]);
        // An option's value is not a positional.
        assert_eq!(c("meshvpn exec -u bob al"), vec!["all"]);
        assert_eq!(c("meshvpn share "), vec!["__files__"]);
        assert_eq!(c("meshvpn cp "), vec!["__files__"]);
        assert!(c("meshvpn cp gpu1:/sr").is_empty());
    }

    #[test]
    fn words_split_like_bash() {
        assert_eq!(words("meshvpn exec ", 13), vec!["meshvpn", "exec", ""]);
        assert_eq!(words("meshvpn exec gp", 15), vec!["meshvpn", "exec", "gp"]);
        assert_eq!(words("meshvpn exec gp", 12), vec!["meshvpn", "exec"]);
    }
}

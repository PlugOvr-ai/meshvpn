//! `meshvpn mcp`: a Model Context Protocol server on stdio, so AI agents (Claude Code, ...) can
//! work with the network directly: find nodes and GPUs, run commands, move files, measure the
//! network, prepare distributed training and distribute datasets.
//!
//! Add it to Claude Code with:  claude mcp add meshvpn -- meshvpn mcp

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::agent::{self, NodeView, Remote};
use crate::control::{self, Request, Response};

const PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

fn tools() -> Value {
    let selectors = json!({
        "type": "array", "items": {"type": "string"},
        "description": "Nodes: \"all\", \"tag:<tag>\" (e.g. tag:gpu), node names or mesh IPs. Several add up."
    });
    json!([
        {
            "name": "list_nodes",
            "description": "List the nodes of the mesh network with online state, tags, mesh IP, path (direct/relay) and hardware inventory: CPU, memory, disk, GPUs (model, memory, utilisation), driver/CUDA. Use it to pick machines for a job.",
            "inputSchema": {"type": "object", "properties": {
                "selectors": selectors,
                "online": {"type": "boolean", "description": "Only nodes that are online."},
                "free_gpus": {"type": "integer", "description": "Only nodes with at least this many idle GPUs."}
            }}
        },
        {
            "name": "exec",
            "description": "Run a shell command on one or many nodes in parallel (over SSH; the target nodes must allow this account to log in, see `meshvpn ssh`). Returns exit code, stdout and stderr per node. Output is capped at 1 MB per stream.",
            "inputSchema": {"type": "object", "required": ["selectors", "command"], "properties": {
                "selectors": selectors,
                "command": {"type": "string", "description": "Shell command line, e.g. \"nvidia-smi | head\"."},
                "user": {"type": "string", "description": "Account on the nodes (default: the account running meshvpn mcp)."},
                "timeout_s": {"type": "integer", "description": "Per-node timeout in seconds (default 600)."}
            }}
        },
        {
            "name": "copy_to_nodes",
            "description": "Copy local files/directories into a directory on one or many nodes (tar over SSH; keeps directory structure and permissions).",
            "inputSchema": {"type": "object", "required": ["selectors", "sources", "dest_dir"], "properties": {
                "selectors": selectors,
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Local paths."},
                "dest_dir": {"type": "string", "description": "Directory on the nodes (created if missing)."},
                "user": {"type": "string"}
            }}
        },
        {
            "name": "copy_from_nodes",
            "description": "Copy a file or directory from one or many nodes into a local directory (into <dest_dir>/<node>/ when several nodes are selected).",
            "inputSchema": {"type": "object", "required": ["selectors", "source", "dest_dir"], "properties": {
                "selectors": selectors,
                "source": {"type": "string", "description": "Path on the nodes."},
                "dest_dir": {"type": "string", "description": "Local directory."},
                "user": {"type": "string"}
            }}
        },
        {
            "name": "network_matrix",
            "description": "Latency (RTT), mesh throughput and direct LAN paths between nodes. With measure=true the nodes run fresh tests first (sends `mb` MB per pair). Use it to decide where to run communication-heavy jobs and whether nodes share a fast LAN.",
            "inputSchema": {"type": "object", "properties": {
                "selectors": selectors,
                "measure": {"type": "boolean"},
                "mb": {"type": "integer", "description": "Test data per pair in MB (default 16)."}
            }}
        },
        {
            "name": "training_env",
            "description": "Environment for multi-node distributed training (torchrun/NCCL) for every node of a group: MASTER_ADDR, MASTER_PORT, NNODES, NODE_RANK, NCCL_SOCKET_IFNAME, GLOO_SOCKET_IFNAME. Uses a shared LAN when every pair has one (fast), otherwise the encrypted mesh for all. Start each node with its own environment, e.g. via exec: `env VAR=... torchrun --nnodes=$NNODES --node_rank=$NODE_RANK --master_addr=$MASTER_ADDR ...`.",
            "inputSchema": {"type": "object", "required": ["selectors"], "properties": {
                "selectors": selectors,
                "master": {"type": "string", "description": "Rank-0 node (default: first by name)."},
                "port": {"type": "integer", "description": "MASTER_PORT (default 29500)."},
                "user": {"type": "string"}
            }}
        },
        {
            "name": "share",
            "description": "Share a local file or directory (dataset, checkpoint) with the network. Returns its id; other nodes download it with fetch. Needs meshvpn mcp to run as root.",
            "inputSchema": {"type": "object", "required": ["path"], "properties": {
                "path": {"type": "string"},
                "name": {"type": "string"}
            }}
        },
        {
            "name": "fetch",
            "description": "Download a shared object (by id) into a local directory, in parallel from every node that has it, over LAN paths where possible; every chunk is verified and existing data is reused. To put a dataset on many nodes, run `meshvpn fetch <id> <dir>` on them with exec (they then also serve each other). Needs root.",
            "inputSchema": {"type": "object", "required": ["id", "dest_dir"], "properties": {
                "id": {"type": "string"},
                "dest_dir": {"type": "string"}
            }}
        },
        {
            "name": "list_objects",
            "description": "Shared datasets/checkpoints in the network and which nodes have them.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "set_tags",
            "description": "Add or remove tags of THIS node (e.g. gpu, trainer). Needs root.",
            "inputSchema": {"type": "object", "properties": {
                "add": {"type": "array", "items": {"type": "string"}},
                "remove": {"type": "array", "items": {"type": "string"}}
            }}
        },
        {
            "name": "node_status",
            "description": "Status of this node: name, mesh IP, mode (kernel/userspace), endpoints, warnings, update availability.",
            "inputSchema": {"type": "object", "properties": {}}
        }
    ])
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing argument {key:?}"))
}

fn remote(st: &crate::node::Status, args: &Value, timeout: u64) -> Remote {
    Remote {
        user: args
            .get("user")
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_else(Remote::default_user),
        socks: st.socks.is_some(),
        timeout: Duration::from_secs(args.get("timeout_s").and_then(Value::as_u64).unwrap_or(timeout)),
    }
}

fn targets(dir: &Path, args: &Value) -> Result<(crate::node::Status, Vec<NodeView>)> {
    let st = agent::status(dir)?;
    let mut sel = strings(args, "selectors");
    if sel.is_empty() {
        sel.push("all".into());
    }
    let nodes = agent::select(&agent::nodes(&st), &sel)?;
    Ok((st, nodes))
}

fn daemon(dir: &Path, req: Request) -> Result<Value> {
    let rt = tokio::runtime::Runtime::new()?;
    match rt.block_on(control::request(dir, &req))? {
        Response::Message { text } => Ok(serde_json::from_str(&text).unwrap_or(Value::String(text))),
        Response::Ok => Ok(json!({"ok": true})),
        _ => bail!("unexpected answer from meshvpn"),
    }
}

fn call(dir: &Path, name: &str, args: &Value) -> Result<Value> {
    match name {
        "list_nodes" => {
            let (_, mut nodes) = targets(dir, args)?;
            let online = args.get("online").and_then(Value::as_bool).unwrap_or(false);
            let free = args.get("free_gpus").and_then(Value::as_u64).map(|g| g as usize);
            nodes.retain(|n| (!online || n.online) && free.is_none_or(|g| n.free_gpus() >= g));
            Ok(serde_json::to_value(nodes)?)
        }
        "exec" => {
            let (st, nodes) = targets(dir, args)?;
            let results = agent::exec(&nodes, &remote(&st, args, 600), &[text(args, "command")?.to_string()]);
            Ok(agent::results_json(&results))
        }
        "copy_to_nodes" => {
            let (st, nodes) = targets(dir, args)?;
            let results = agent::upload(
                &nodes,
                &remote(&st, args, 3600),
                &strings(args, "sources"),
                text(args, "dest_dir")?,
            )?;
            Ok(agent::results_json(&results))
        }
        "copy_from_nodes" => {
            let (st, nodes) = targets(dir, args)?;
            let results = agent::download(
                &nodes,
                &remote(&st, args, 3600),
                text(args, "source")?,
                text(args, "dest_dir")?,
            )?;
            Ok(agent::results_json(&results))
        }
        "network_matrix" => {
            let (_, mut nodes) = targets(dir, args)?;
            if args.get("measure").and_then(Value::as_bool).unwrap_or(false) {
                let mb = args.get("mb").and_then(Value::as_u64).unwrap_or(16);
                nodes = agent::measure(dir, &nodes, mb)?;
            }
            Ok(serde_json::to_value(agent::matrix(&nodes))?)
        }
        "training_env" => {
            let (st, group) = targets(dir, args)?;
            let all = agent::nodes(&st);
            let master = match args.get("master").and_then(Value::as_str) {
                Some(m) => agent::select(&all, &[m.to_string()])?.remove(0),
                None => group
                    .iter()
                    .min_by_key(|n| n.name.clone())
                    .cloned()
                    .ok_or_else(|| anyhow!("empty group"))?,
            };
            let port = args.get("port").and_then(Value::as_u64).unwrap_or(29500);
            // Each node knows its own interface names: ask every node for its environment.
            let names: Vec<String> = group.iter().map(|n| n.name.clone()).collect();
            let cmd = format!(
                "meshvpn net env --json --master {} --port {port} {}",
                agent::sh_quote(&master.name),
                names.iter().map(|n| agent::sh_quote(n)).collect::<Vec<_>>().join(" ")
            );
            let results = agent::exec(&group, &remote(&st, args, 60), &[cmd]);
            let mut envs = serde_json::Map::new();
            for r in results {
                let v = if r.ok {
                    serde_json::from_str(r.stdout.trim()).unwrap_or(Value::String(r.stdout))
                } else {
                    json!({"error": format!("{}{}", r.stdout, r.stderr).trim()})
                };
                envs.insert(r.node, v);
            }
            Ok(json!({"master": master.name, "nodes": envs}))
        }
        "share" => daemon(
            dir,
            Request::Share {
                path: std::path::absolute(text(args, "path")?)?.to_string_lossy().into_owned(),
                name: args.get("name").and_then(Value::as_str).map(String::from),
            },
        ),
        "fetch" => daemon(
            dir,
            Request::Fetch {
                id: text(args, "id")?.into(),
                dest: std::path::absolute(text(args, "dest_dir")?)?
                    .to_string_lossy()
                    .into_owned(),
                owner: None,
            },
        ),
        "list_objects" => {
            let st = agent::status(dir)?;
            let mut out: Vec<Value> = vec![];
            for n in agent::nodes(&st) {
                let list = if n.is_self {
                    st.objects.clone()
                } else {
                    n.objects.clone()
                };
                for o in list {
                    match out.iter_mut().find(|x| x["id"] == o.id) {
                        Some(x) => x["holders"].as_array_mut().unwrap().push(json!(n.name)),
                        None => out.push(json!({"id": o.id, "name": o.name, "size": o.size, "holders": [n.name]})),
                    }
                }
            }
            Ok(Value::Array(out))
        }
        "set_tags" => daemon(
            dir,
            Request::Tags {
                add: strings(args, "add"),
                remove: strings(args, "remove"),
            },
        ),
        "node_status" => {
            let mut st = serde_json::to_value(agent::status(dir)?)?;
            if let Some(o) = st.as_object_mut() {
                o.remove("peers"); // list_nodes has them, with more detail
            }
            Ok(st)
        }
        _ => bail!("unknown tool {name:?}"),
    }
}

fn handle(dir: &Path, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => {
            let asked = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(PROTOCOLS[0]);
            let version = if PROTOCOLS.contains(&asked) {
                asked
            } else {
                PROTOCOLS[0]
            };
            Ok(json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "meshvpn", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "meshvpn connects machines into a private mesh network. Use list_nodes to find machines and GPUs (select them with names, tag:<tag> or all), exec / copy_to_nodes / copy_from_nodes to work on them, network_matrix and training_env for distributed training, share/fetch to distribute datasets and checkpoints."
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            Ok(match call(dir, name, &args) {
                Ok(v) => json!({
                    "content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap()}],
                    "isError": false
                }),
                Err(e) => json!({
                    "content": [{"type": "text", "text": format!("error: {e:#}")}],
                    "isError": true
                }),
            })
        }
        m if m.starts_with("notifications/") => return None,
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    let id = id?; // notifications get no answer
    Some(match result {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    })
}

pub fn serve(dir: PathBuf) -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&dir, &msg),
            Err(e) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}})),
        };
        if let Some(r) = reply {
            writeln!(out, "{r}")?;
            out.flush()?;
        }
    }
    Ok(())
}

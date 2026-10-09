//! `meshvpn guide`: how to work with meshvpn, written for AI agents (also sent to MCP clients
//! as the server's instructions). Starts with the live state of the network.

use std::path::Path;

/// The instructions; kept short and exact - agents follow them literally.
pub const GUIDE: &str = r#"# meshvpn for agents

meshvpn connects machines (nodes) into one private network. Every node has a name, reachable as
`<name>.mesh`, and a fixed address in 100.64.0.0/10. You can run commands on nodes, copy files, use
their GPUs and start distributed jobs - from the node you are on, over SSH logins meshvpn manages.

## Rules

- Put `--json` right after `meshvpn` (`meshvpn --json nodes`): stable JSON on stdout, errors too.
  Exit codes: 0 ok, 1 error, 2 usage, 3 meshvpn not running, 4 needs root, 5 node not found.
- Select nodes with selectors: a name (`gpu1`), `tag:<tag>`, `all`, a mesh IP; several add up.
  A selector that matches nothing is an error (exit 5) - check names with `meshvpn --json nodes`.
- Never run interactive commands: `meshvpn console`, `meshvpn desktop`, plain `meshvpn ssh`, `ssh`
  without a command. Use `exec`, `cp` and `jobs` instead.
- Ask the human first before anything that changes the network or other people's access:
  `ban`, `forget`, `admin`, `invite`, `ssh allow/deny/default-user`, `rename`, `update`, `install`,
  `uninstall`, `join`, `init`, `desktop stop`. Don't edit /etc/meshvpn by hand.
- Clean up what you start: release GPU reservations (`gpu release`), stop jobs you no longer need
  (`jobs stop`). Other people share these machines.
- Commands that need root say so (exit 4). Don't retry them with sudo unless the human allows it.

## Find machines

```sh
meshvpn --json status                   # this node, its peers, paths, versions
meshvpn --json nodes                    # all nodes: online, tags, CPUs, memory, GPUs, login_user
meshvpn --json nodes tag:gpu --online   # a group
meshvpn --json nodes --free-gpus 4      # nodes with at least 4 idle GPUs
meshvpn --json gpu list                 # every GPU: free, busy (utilization) or reserved (by whom)
```

`login_user` is the account a node expects logins as. `exec`, `cp` and `launch` log in as the
current user unless you pass `-u <user>`; use `-u <login_user>` when it differs.

## Run commands and move files

```sh
meshvpn --json exec tag:gpu -- 'nvidia-smi --query-gpu=name,memory.used --format=csv'
meshvpn --json exec gpu1 gpu2 -u ubuntu --timeout 600 -- 'cd ~/project && git pull'
meshvpn cp ./project tag:gpu:/home/ubuntu/            # to every selected node (destination = dir)
meshvpn cp gpu1:/home/ubuntu/project/out.log ./logs/  # back (from several nodes: ./logs/<node>/...)
```

`exec` returns `{"ok": bool, "results": [{"node", "ok", "exit_code", "stdout", "stderr",
"duration_ms"}]}`; one argument after `--` is a shell command line. `--online` skips offline nodes
instead of failing on them.

## GPUs

```sh
meshvpn --json gpu reserve tag:gpu -n 2 --for 2h --note "<what for>"   # prints CUDA_VISIBLE_DEVICES per node
meshvpn --json gpu reserve tag:gpu --one -n 4 --for 1h                 # the single best node
meshvpn --json gpu renew <id> --for 2h
meshvpn --json gpu release <id>
```

Reservations never collide (the node with the GPUs grants them). Respect other people's
reservations; don't use GPUs reserved by someone else.

## Distributed training

```sh
meshvpn --json net matrix --measure tag:gpu        # latency, throughput, shared LANs between nodes
meshvpn launch tag:gpu --gpus 4 --detach -- torchrun train.py   # prints the job id
meshvpn --json jobs list
meshvpn --json jobs show <id>                      # state, environment, end of each node's log
meshvpn jobs logs <id> --node gpu1 --tail 200
meshvpn --json jobs stop <id>
```

`launch` sets MASTER_ADDR, MASTER_PORT, NNODES, NODE_RANK, NCCL_SOCKET_IFNAME and GLOO_SOCKET_IFNAME on
every node (LAN if all pairs share one, else the mesh) and adds the rendezvous arguments to a
`torchrun` command. With `--gpus N` it reserves N GPUs per node first and releases them at the end.
If one node fails, the others are stopped. Commands over SSH don't activate conda/venv: use the full
path to torchrun or a wrapper script (see examples/distributed-training/run.sh in the meshvpn repo).
For other launchers: `eval $(meshvpn net env --master gpu1 tag:gpu)` on each node.

## Datasets and checkpoints

```sh
meshvpn --json share /data/set --name <name>       # prints an id (root on root installs)
meshvpn --json objects                             # what is shared, and which nodes have it
meshvpn --json fetch <id> /data                    # in parallel from all holders (root on root installs)
```

## When something fails

- `meshvpn --json doctor` checks this node and says how to fix problems.
- `Permission denied` on exec/cp/launch: no SSH login for this user on that node. Tell the human:
  on the target, `meshvpn ssh list` shows the rules and recent refusals with the reason.
- exit 3: meshvpn isn't running on this machine - tell the human (`sudo meshvpn install`).
- A node is `offline`: skip it with `--online`, or report it.
"#;

/// The live state in front of the guide: where the agent is and what is there.
pub fn context(dir: &Path) -> String {
    let Ok(st) = crate::agent::status(dir) else {
        return "## Right now\n\nmeshvpn is not running on this machine (or this user can't see it): most \
                commands below will fail with exit code 3. Tell the human.\n"
            .into();
    };
    let nodes = crate::agent::nodes(&st);
    let online = nodes.iter().filter(|n| n.online && !n.is_self).count();
    let mut tags: std::collections::BTreeMap<&str, usize> = Default::default();
    for n in &nodes {
        for t in &n.tags {
            *tags.entry(t.as_str()).or_default() += 1;
        }
    }
    let gpus: usize = nodes
        .iter()
        .filter_map(|n| n.inventory.as_ref())
        .map(|i| i.gpus.len())
        .sum();
    let free: usize = nodes.iter().filter(|n| n.online).map(|n| n.free_gpus()).sum();
    let mut out = format!(
        "## Right now\n\n- You are on node **{}** ({}.mesh, {}), meshvpn {}, network \"{}\", as user `{}`.\n\
         - {} other node(s), {} online.\n",
        st.name,
        st.name,
        st.ip,
        st.version,
        st.network,
        crate::agent::Remote::default_user(),
        nodes.len() - 1,
        online
    );
    if !tags.is_empty() {
        let t: Vec<String> = tags.iter().map(|(t, n)| format!("`tag:{t}` ({n})")).collect();
        out.push_str(&format!("- Tags: {}.\n", t.join(", ")));
    }
    if gpus > 0 {
        out.push_str(&format!(
            "- GPUs: {gpus} in the network, {free} idle and unreserved on online nodes.\n"
        ));
    }
    if st.socks.is_some() {
        out.push_str(
            "- This node runs in userspace mode: other programs reach the mesh only through \
             socks5h://127.0.0.1:1055 (meshvpn's own commands work normally).\n",
        );
    }
    out.push_str("- Details: `meshvpn --json nodes`.\n");
    out
}

/// What MCP clients get when they connect: the same rules in terms of the tools, and the
/// network right now.
pub fn mcp_instructions(dir: &Path) -> String {
    format!(
        "meshvpn connects machines (nodes) into one private network; you work on them through these tools.\n\n\
         - Start with list_nodes (names, tags, online, GPUs, login_user) and gpu_list. Select nodes with names, \
         `tag:<tag>` or `all`.\n\
         - exec runs a shell command on nodes and returns stdout/stderr/exit code per node; copy_to_nodes / \
         copy_from_nodes move files. Pass the node's login_user as user when it differs from yours.\n\
         - GPUs: gpu_reserve before using GPUs on shared machines, gpu_release when done; never use GPUs \
         reserved by someone else.\n\
         - Training: network_matrix (shared LANs, throughput), launch (sets MASTER_ADDR/NODE_RANK/NCCL_SOCKET_IFNAME \
         on every node, adds torchrun's rendezvous arguments, stops all nodes if one fails), job_status / \
         list_jobs / job_stop. Stop jobs you no longer need.\n\
         - Data: share / fetch / list_objects distribute datasets and checkpoints between nodes.\n\
         - Problems: doctor; a 'Permission denied' means no SSH login for that user on that node - tell the human.\n\
         - Ask the human before changing other people's access or the network (tags of other nodes, bans, SSH rules).\n\n{}",
        context(dir)
    )
}

/// A Claude Code skill (SKILL.md) with the guide.
pub fn skill() -> String {
    format!(
        "---\nname: meshvpn\ndescription: Work with the machines of a meshvpn network - find nodes and GPUs, \
         run commands and copy files on them, reserve GPUs, launch distributed training, share datasets. Use \
         when a task involves other machines, GPUs, nodes, <name>.mesh hosts or the meshvpn command.\n---\n\n\
         Run `meshvpn guide` first: it shows the current state of the network (nodes, tags, GPUs).\n\n{GUIDE}"
    )
}

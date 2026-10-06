# Distributed training with meshvpn

This tutorial trains a model on several machines at once: the GPU servers in your lab, a cloud machine, a workstation
under a desk, wherever they are. meshvpn connects them, works out the rendezvous for PyTorch (who is rank 0, which
address and network interface to use), starts the job on every node and stops all of them if one fails.

It uses the small example in [`examples/distributed-training`](../examples/distributed-training): a real DDP
training that runs on GPUs (NCCL) and also on plain CPUs (gloo), so you can follow along on any machines. Everything
shown here was run on real meshvpn nodes; the output is copied from those runs.

If your network isn't set up yet, start with the [general tutorial](tutorial.md).

**Contents**

1. [What `meshvpn launch` does](#1-what-meshvpn-launch-does)
2. [Prepare the nodes](#2-prepare-the-nodes)
3. [Look at the group](#3-look-at-the-group)
4. [Code and data to the nodes](#4-code-and-data-to-the-nodes)
5. [Train](#5-train)
6. [GPUs](#6-gpus)
7. [Long runs: detach, logs, checkpoints](#7-long-runs-detach-logs-checkpoints)
8. [Your own code and other frameworks](#8-your-own-code-and-other-frameworks)
9. [Performance](#9-performance)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. What `meshvpn launch` does

```sh
meshvpn launch tag:gpu -- torchrun train.py
```

1. **Picks the group:** all nodes tagged `gpu` (or any selectors: names, `all`, mesh IPs).
2. **Works out the rendezvous:** rank 0 (the *master*) is the first node by name, or `--master <node>`. If every pair
   of nodes shares a LAN, the job talks over the LAN (faster); otherwise everyone uses the mesh. It never mixes the
   two, because NCCL hangs when some nodes use one network and some the other.
3. **Starts the command on every node over SSH**, with `MASTER_ADDR`, `MASTER_PORT`, `NNODES`, `NODE_RANK`,
   `NCCL_SOCKET_IFNAME` and `GLOO_SOCKET_IFNAME` set. If the command is `torchrun`, it adds `--nnodes`, `--node_rank`,
   `--master_addr` and `--master_port` (and `--nproc_per_node` with `--gpus`).
4. **Watches the job:** each node's output is shown with the node name in front. If one node fails, the others are
   stopped (`--keep-going` turns that off). If you close the terminal or the SSH connection, the job stops on all
   nodes, unless it runs with `--detach`.

## 2. Prepare the nodes

Each training node needs:

* **meshvpn as root, with its network interface** (`mesh0`): normal installs and containers started with
  `--cap-add=NET_ADMIN --device /dev/net/tun`. NCCL and gloo open their own connections and need a real interface. A
  node in userspace mode (rootless, or a container without NET_ADMIN) can only take part if all nodes of the job share
  a LAN.
* **Tags**, so the group is easy to select: `sudo meshvpn tag add gpu` on each node (or `--tag gpu` when joining).
* **SSH logins** from the machine you launch on, as the same user on every node, without a password. On cluster
  machines the easiest way is to join with `--ssh-allow-all <user>`; otherwise on each node
  `sudo meshvpn ssh allow <you>@<launch-machine> --as <user>` (see [SSH between nodes](tutorial.md#7-ssh-between-nodes)).
  Test it: `meshvpn exec tag:gpu -- hostname`.
* **Python with PyTorch**, the same versions everywhere (the example needs `torch` and `numpy`). A virtualenv or
  conda environment is fine; section 4 shows how the job uses it.

The machine you start the job from can be any node, also one without GPUs (your notebook, the server you SSH into).

## 3. Look at the group

```sh
meshvpn nodes tag:gpu                   # online? CPUs, memory, GPUs
meshvpn gpu list tag:gpu                # which GPUs are free, busy or reserved
meshvpn net matrix --measure tag:gpu    # latency, throughput and shared LANs between them
```

The matrix tells you how the job will communicate:

```
FROM  TO          RTT          MESH  LAN PATH           AGE
gpu1  gpu2     0.0 ms    860 Mbit/s  172.23.0.4         0s
gpu2  gpu1     1.0 ms    863 Mbit/s  172.23.0.3         0s
```

A `LAN PATH` for every pair means the job runs over the LAN. Measure once before the first job of a new group: launch
uses the LAN only where a measurement has confirmed it.

## 4. Code and data to the nodes

**The code.** Copy the example to every node:

```sh
git clone https://github.com/PlugOvr-ai/meshvpn && cd meshvpn/examples
meshvpn cp ./distributed-training tag:gpu:/home/$USER/
```

`meshvpn cp` copies to all selected nodes at once; `--json` reports per node. (Or `git clone` on each node with
`meshvpn exec tag:gpu -- 'git clone …'`.)

**The Python environment.** A command started over SSH doesn't activate conda or a virtualenv, so `torchrun` is often
not found. The example's `run.sh` is the usual fix, a small wrapper that activates the environment and passes
meshvpn's rendezvous to torchrun:

```sh
if [ -f "$HOME/venv/bin/activate" ]; then . "$HOME/venv/bin/activate"; fi
# conda:  . "$HOME/miniconda3/etc/profile.d/conda.sh" && conda activate myenv
exec torchrun \
    --nnodes="${NNODES:-1}" --node_rank="${NODE_RANK:-0}" \
    --master_addr="${MASTER_ADDR:-127.0.0.1}" --master_port="${MASTER_PORT:-29500}" \
    --nproc_per_node="$nproc" \
    train.py "$@"
```

Adjust the activation line to your environment. (Alternatively, call torchrun by its full path, e.g.
`-- /home/you/venv/bin/torchrun train.py`; meshvpn then adds the rendezvous arguments itself.)

**The data.** Small datasets can be copied like the code. For bigger ones, share them once and let the nodes fetch
them in parallel: every node that has a piece serves it to the others, over the LAN where possible.

```sh
cd distributed-training && python prepare_data.py        # writes data/spirals.pt
sudo meshvpn share data --name spirals                   # prints an id
```

On each training node:

```sh
sudo meshvpn fetch <id> ~/distributed-training           # the files belong to you afterwards
```

```
gpu1 fetched spirals into /home/agent/meshvpn-example: 962 kB in 0.1s (126 Mbit/s) from hub 962 kB
gpu2 fetched spirals into /home/agent/meshvpn-example: 962 kB in 0.1s (109 Mbit/s) from gpu1 962 kB
```

Note how gpu2 got the data from gpu1, which had just fetched it. `meshvpn objects` lists what is shared and where.
(The example also generates the dataset on the fly if the file is missing.)

## 5. Train

```sh
meshvpn launch tag:gpu --workdir distributed-training -- ./run.sh --epochs 10
```

`--workdir` is relative to the home directory on each node. Arguments after `./run.sh` go to `train.py`. The output
of a run on two nodes sharing a LAN:

```
job bb8ae227: ./run.sh --epochs 3 on 2 node(s), master gpu1 via lan - logs in /home/agent/.local/state/meshvpn/jobs/bb8ae227
[gpu1] 2 processes on 2 node(s): gpu1/cpu, gpu2/cpu
[gpu1] backend gloo, rendezvous 172.23.0.3:29500, network lan (eth0)
[gpu1] epoch 1/3: loss 0.9680, test accuracy 66.4%, 17,104 samples/s
[gpu1] epoch 2/3: loss 0.6676, test accuracy 77.8%, 14,897 samples/s
[gpu1] epoch 3/3: loss 0.4983, test accuracy 81.6%, 17,304 samples/s
[gpu1] done - checkpoint in /home/agent/meshvpn-example/checkpoints/last.pt on gpu1
job bb8ae227: succeeded - logs in /home/agent/.local/state/meshvpn/jobs/bb8ae227
```

And the same job on two nodes in different networks, connected only through the mesh:

```
[gpu1] backend gloo, rendezvous 100.81.231.63:29500, network mesh (mesh0)
```

The example prints which nodes and devices take part, the backend, the rendezvous and the network meshvpn chose,
then one line per epoch (loss and throughput summed over all processes, accuracy on held-out data). Rank 0 writes a
checkpoint after every epoch.

**Choosing the master:** `--master gpu3` (the node with the fastest connection to the others is a good choice).
**The port:** `--port 29600` if 29500 is taken (e.g. two jobs at once).

## 6. GPUs

On a shared machine, reserve GPUs, so two people's jobs don't land on the same ones:

```sh
meshvpn launch tag:gpu --gpus 4 --workdir distributed-training -- ./run.sh
```

`--gpus 4` reserves 4 free GPUs on every node before anything starts (or fails right away if they aren't free),
sets `CUDA_VISIBLE_DEVICES` to them, starts one process per GPU (`MESHVPN_GPUS`, which `run.sh` passes to torchrun as
`--nproc_per_node`), renews the reservation while the job runs and releases it at the end. Others see the
reservation in `meshvpn gpu list`.

Without `--gpus`, `run.sh` starts one process per GPU of the node (`nvidia-smi -L`), or one on machines without GPUs.

Reservations without a job (e.g. for an interactive session):

```sh
meshvpn gpu reserve gpu1 -n 2 --for 4h --note "debugging"     # prints CUDA_VISIBLE_DEVICES
meshvpn gpu release <id>
```

## 7. Long runs: detach, logs, checkpoints

A job started normally lives as long as your terminal. For runs of hours or days:

```sh
meshvpn launch tag:gpu --detach --workdir distributed-training -- ./run.sh --epochs 500
meshvpn jobs list                 # your jobs: running, succeeded, failed, stopped
meshvpn jobs show <id>            # state, environment, the end of each node's log
meshvpn jobs logs <id>            # the log (--node gpu1 for one node, --tail 1000 for more)
meshvpn jobs stop <id>            # stop it on all nodes
```

A detached job is supervised by a background process on the machine you launched from; keep that machine running
(or launch from a node that stays up, e.g. the server).

**Checkpoints and resuming:** the example saves `checkpoints/last.pt` on the master after every epoch and continues
from there with `--resume`:

```sh
meshvpn launch tag:gpu --workdir distributed-training -- ./run.sh --epochs 500 --resume
```

**Getting results back:**

```sh
meshvpn cp gpu1:/home/$USER/distributed-training/checkpoints ./results/
sudo meshvpn share ~/distributed-training/checkpoints --name run-42   # or share them with the team
```

## 8. Your own code and other frameworks

**Your own PyTorch script** works like the example: everything torchrun sets (`RANK`, `LOCAL_RANK`, `WORLD_SIZE`,
`MASTER_ADDR`, `MASTER_PORT`) is there, so `torch.distributed.init_process_group("nccl")` just works.

**Without torchrun**, or with another launcher (DeepSpeed, Lightning, Accelerate, Horovod, JAX), use meshvpn only for
the rendezvous. On each node of the group:

```sh
eval $(meshvpn net env --master gpu1 tag:gpu)
echo $MASTER_ADDR $NODE_RANK $NNODES $NCCL_SOCKET_IFNAME
```

This prints the same variables `launch` sets, for the node it runs on. Pass them to your launcher, e.g.
`--num_nodes $NNODES --node_rank $NODE_RANK` for Lightning, or put the command into a wrapper like `run.sh` and start
it with `meshvpn launch`, which still gives you the start on all nodes, the log prefixes and the failure handling.

**AI agents:** with `claude mcp add meshvpn -- meshvpn mcp`, an agent can list the nodes, reserve GPUs, launch jobs and
read their logs by itself.

## 9. Performance

* **A shared LAN is best.** Within a lab or a data center, all nodes on one network: the job runs over it at full
  speed, meshvpn only does the setup. `meshvpn net matrix --measure` shows whether every pair shares a LAN.
* **Over the mesh**, the job's traffic is encrypted and takes the mesh's paths (direct UDP where possible). That is
  fine for experiments, smaller models and data-parallel jobs with modest gradient traffic across sites; for large
  models across the internet, expect the network to be the bottleneck. The matrix's `MESH` column shows the
  throughput the job can expect between each pair.
* **The master** should be the node with the best connection to the others.
* **Gradient traffic** shrinks with larger batches per GPU, gradient accumulation, or mixed precision.

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `torchrun: not found` / `No module named torch` | The Python environment isn't active in an SSH command: use `run.sh` (adjust its activation line) or the full path to torchrun. |
| `Permission denied` before anything starts | No SSH login on a node: `meshvpn exec tag:gpu -- hostname` shows which; see [SSH between nodes](tutorial.md#7-ssh-between-nodes). |
| `RuntimeError: Numpy is not available` | Install numpy in the environment (`pip install numpy`); CPU builds of PyTorch need it. |
| The job hangs at the start (rendezvous) | A firewall blocks port 29500 (or NCCL's ports) on the master: `sudo meshvpn doctor` on the master checks the mesh interface; on a LAN, allow the nodes to reach each other. |
| `no LAN path between all nodes, and … runs in userspace mode` | That node has no network interface for NCCL: give its container `--cap-add=NET_ADMIN --device /dev/net/tun`, or use nodes that share a LAN. |
| The job goes over the mesh although the nodes share a LAN | No measurement yet: run `meshvpn net matrix --measure tag:gpu` once. |
| `could not reserve GPUs: …` | They are taken: `meshvpn gpu list` shows who reserved them and until when. |
| One node fails, all stop | Intended (one failed rank stalls the others). The log of the failed node is in `meshvpn jobs show <id>`; `--keep-going` if you really want the rest to continue. |

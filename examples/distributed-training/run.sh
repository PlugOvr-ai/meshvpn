#!/bin/sh
# Started by `meshvpn launch` on every node of the job:
#
#   meshvpn launch tag:gpu --workdir meshvpn-example -- ./run.sh [train.py options]
#
# meshvpn exports the rendezvous for this node (MASTER_ADDR, MASTER_PORT, NNODES, NODE_RANK,
# NCCL_SOCKET_IFNAME, ...); this script passes it to torchrun. A wrapper like this is the way to
# use a virtualenv or conda environment, which a plain `ssh node command` doesn't activate.
set -e
cd "$(dirname "$0")"

# Your Python environment, if any (adjust or remove):
# shellcheck disable=SC1091
if [ -f "$HOME/venv/bin/activate" ]; then . "$HOME/venv/bin/activate"; fi
# conda:  . "$HOME/miniconda3/etc/profile.d/conda.sh" && conda activate myenv

# One process per GPU reserved with `--gpus N`, else per GPU of the node, else one (CPU).
if [ -n "${MESHVPN_GPUS:-}" ]; then
    nproc="$MESHVPN_GPUS"
elif command -v nvidia-smi >/dev/null 2>&1; then
    nproc="$(nvidia-smi -L | wc -l)"
else
    nproc=1
fi

exec torchrun \
    --nnodes="${NNODES:-1}" --node_rank="${NODE_RANK:-0}" \
    --master_addr="${MASTER_ADDR:-127.0.0.1}" --master_port="${MASTER_PORT:-29500}" \
    --nproc_per_node="$nproc" \
    train.py "$@"

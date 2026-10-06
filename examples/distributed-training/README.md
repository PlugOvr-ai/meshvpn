# Example: distributed training with meshvpn

A small but real PyTorch DDP training (an MLP learning to classify three interleaved spirals) to try
`meshvpn launch` with. It uses the GPUs if there are any (NCCL), otherwise the CPUs (gloo), so it runs on any group of
nodes, also on machines without GPUs. One epoch takes seconds.

| File | What |
|---|---|
| `train.py` | the training: DDP, `DistributedSampler`, checkpoints, `--resume` |
| `prepare_data.py` | writes the dataset `data/spirals.pt` (to try `meshvpn share` / `fetch`) |
| `run.sh` | started by `meshvpn launch` on every node: activates your Python environment, starts torchrun |
| `requirements.txt` | `torch`, `numpy` |

Quick start, assuming nodes tagged `gpu` and PyTorch in `~/venv` on each (adjust `run.sh` for conda):

```sh
meshvpn cp ./distributed-training tag:gpu:/home/$USER/            # the code to every node
meshvpn launch tag:gpu --workdir distributed-training -- ./run.sh  # train on all of them
```

On one machine, without meshvpn: `torchrun --standalone --nproc_per_node=2 train.py`.

The full walk-through, with data distribution, GPU reservations, long runs and troubleshooting, is in
[docs/distributed-training.md](../../docs/distributed-training.md).

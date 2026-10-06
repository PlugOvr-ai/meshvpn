"""Generates the example dataset: points on three interleaved spirals, one class each.

    python prepare_data.py            # writes data/spirals.pt
    meshvpn share data                # then: meshvpn fetch <id> . on the other nodes

(train.py also generates it on the fly if the file is missing.)
"""
import argparse
import math
import os

import torch


def spirals(n=60_000, classes=3, noise=0.15, seed=0):
    g = torch.Generator().manual_seed(seed)
    per = n // classes
    xs, ys = [], []
    for c in range(classes):
        t = torch.rand(per, generator=g) * 3 * math.pi + 0.3
        angle = t + c * 2 * math.pi / classes
        r = t / (3 * math.pi)
        pts = torch.stack([r * torch.cos(angle), r * torch.sin(angle)], 1)
        xs.append(pts + noise * r.unsqueeze(1) * torch.randn(per, 2, generator=g))
        ys.append(torch.full((per,), c))
    x, y = torch.cat(xs), torch.cat(ys)
    order = torch.randperm(len(x), generator=g)
    return x[order], y[order]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/spirals.pt")
    ap.add_argument("-n", type=int, default=60_000)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    torch.save(spirals(args.n), args.out)
    print(f"wrote {args.n} samples to {args.out}")

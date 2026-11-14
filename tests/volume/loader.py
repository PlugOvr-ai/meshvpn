#!/usr/bin/env python3
"""A training job's data loading, without the training: one rank of a DistributedSampler.

    loader.py ROOT small|large RANK WORLD EPOCH [WORKERS]

small: every file is a sample, read whole (images, audio clips).
large: 1 MB samples at random places in big files (shards, packed arrays).
The order is shuffled per epoch, the same on every rank; rank r takes every WORLD-th sample.
Prints one JSON line: samples, bytes, seconds, MB/s.
"""
import json
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor

SAMPLE = 1 << 20


def main():
    root, mode, rank, world, epoch = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
    workers = int(sys.argv[6]) if len(sys.argv) > 6 else 16
    files = sorted(os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs)
    if mode == "small":
        items = files

        def load(p):
            with open(p, "rb") as f:
                return len(f.read())
    else:
        items = [(p, o) for p in files for o in range(0, os.path.getsize(p) - SAMPLE + 1, SAMPLE)]

        def load(item):
            fd = os.open(item[0], os.O_RDONLY)
            try:
                return len(os.pread(fd, SAMPLE, item[1]))
            finally:
                os.close(fd)
    order = list(range(len(items)))
    random.Random(epoch).shuffle(order)
    mine = [items[i] for i in order[rank::world]]
    start = time.time()
    with ThreadPoolExecutor(workers) as ex:
        total = sum(ex.map(load, mine, chunksize=8))
    secs = time.time() - start
    print(json.dumps({"rank": rank, "samples": len(mine), "bytes": total, "secs": round(secs, 2),
                      "mb_s": round(total / secs / 1e6, 1)}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Stand-in for /opt/memory_pressure. It sets a memory limit and breaches it."""

import argparse
import os
import sys
import time
import typing as t

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
# Chunks avoid the 2x peak of one big extend. A 2x peak changes the OOM victim.
CHUNK_BYTES = 64 * 1024 * 1024
# The margin must exceed the interpreter size (about 15 MB). Then the limit
# does not fire before the log flush.
OOM_HEADROOM = 0.9
# The margin keeps the kill a cgroup OOM, not a global OOM.
MEM_AVAILABLE_MARGIN_BYTES = 1024 * 1024 * 1024
MEMINFO_PATH = "/proc/meminfo"


def child_cgroup_path(cgroup_slice: str) -> str:
    return f"/sys/fs/cgroup/{cgroup_slice}/memory-pressure"


def parse_args(argv: t.Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", dest="cgroup_slice", required=True)
    parser.add_argument("-m", dest="megabytes", type=int, required=True)
    parser.add_argument("-t", dest="duration_s", type=int, required=True)
    parser.add_argument("-k", dest="keep_alive", action="store_true")
    parser.add_argument("-i", dest="initial_megabytes", type=int, default=0)
    parser.add_argument("-s", dest="oom_score_adj", type=int, default=0)
    return parser.parse_args(list(argv))


def _join_cgroup(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "cgroup.procs"), "w") as f:
        f.write(str(os.getpid()))
    # Without "memory" in the parent's subtree_control, the parent gets the blame.
    if not os.path.exists(os.path.join(path, "memory.current")):
        raise SystemExit(
            f"{path} has no memory controller -- 'memory' is not in the "
            f"parent's cgroup.subtree_control, so an OOM kill here would be "
            f"attributed to the parent slice instead of memory-pressure"
        )


def _parent_memory_max(path: str) -> t.Optional[int]:
    try:
        with open(os.path.join(os.path.dirname(path), "memory.max")) as f:
            raw = f.read().strip()
    except OSError:
        return None
    return int(raw) if raw.isdigit() else None


def _set_memory_limit(path: str, target_bytes: int) -> int:
    limit = int(target_bytes * OOM_HEADROOM)
    parent_max = _parent_memory_max(path)
    if parent_max is not None:
        limit = min(limit, parent_max)
    try:
        with open(MEMINFO_PATH) as f:
            available_kb = next(
                int(line.split()[1]) for line in f if line.startswith("MemAvailable:")
            )
        limit = min(limit, max(available_kb * 1024 - MEM_AVAILABLE_MARGIN_BYTES, 0))
    except (OSError, StopIteration, ValueError):
        pass
    with open(os.path.join(path, "memory.max"), "w") as f:
        f.write(str(limit))
    try:
        # With swap, the kernel pages the allocation out and the limit does not fire.
        # The file is absent on a kernel without swap accounting.
        with open(os.path.join(path, "memory.swap.max"), "w") as f:
            f.write("0")
    except OSError:
        pass
    return limit


def _set_oom_score_adj(value: int) -> None:
    with open("/proc/self/oom_score_adj", "w") as f:
        f.write(str(value))


def _touch(buf: bytearray, start: int) -> None:
    for i in range(start, len(buf), PAGE_SIZE):
        buf[i] = 1


def _allocate_and_hold(
    megabytes: int, duration_s: int, initial_megabytes: int, keep_alive: bool
) -> None:
    target_bytes = megabytes * 1024 * 1024
    initial_bytes = min(initial_megabytes, megabytes) * 1024 * 1024
    # bytearray(n) uses calloc, so the pages are not resident until touched.
    buf = bytearray(initial_bytes)
    _touch(buf, 0)
    while len(buf) < target_bytes:
        already = len(buf)
        buf.extend(bytes(min(CHUNK_BYTES, target_bytes - already)))
        _touch(buf, already)
    time.sleep(duration_s)
    while keep_alive:
        time.sleep(60)


def main(argv: t.Optional[t.Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    path = child_cgroup_path(args.cgroup_slice)
    # Flush before any step can fail, so the log shows how the run ended.
    print(
        f"cgroup={path} megabytes={args.megabytes} duration_s={args.duration_s} "
        f"initial_megabytes={args.initial_megabytes} "
        f"keep_alive={args.keep_alive} oom_score_adj={args.oom_score_adj}",
        flush=True,
    )
    _join_cgroup(path)
    _set_oom_score_adj(args.oom_score_adj)
    limit = _set_memory_limit(path, args.megabytes * 1024 * 1024)
    print(f"{path}/memory.max={limit}; allocating", flush=True)
    _allocate_and_hold(
        args.megabytes, args.duration_s, args.initial_megabytes, args.keep_alive
    )
    print("completed without an OOM kill", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

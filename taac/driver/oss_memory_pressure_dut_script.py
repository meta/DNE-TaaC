#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Stand-in for Meta's ``/opt/memory_pressure`` on an OSS DUT.

``AllocateCgroupSliceMemory`` (taac/steps/step_definitions.py) and the
legacy task (taac/tasks/all.py) shell out to a fixed executable with a fixed
CLI; this script implements that same CLI so it drops in unmodified under
OSS, where the Meta binary doesn't exist:

    memory_pressure -c <cgroup slice> -m <MB> -t <seconds> [-k]
                    [-i <MB>] [-s <oom_score_adj>]

``-c`` is passed already suffixed (``system.slice``), so it is used as-is.
The script moves itself into a child cgroup ``<-c>/memory-pressure`` -- the
kill is then attributable by that path segment, which is what
``OomdKillHealthCheck`` matches on (the kernel's ``task=`` comm name is
truncated to 15 chars, so it is not used). It then sets its own
oom_score_adj, caps that child cgroup's ``memory.max`` below the target,
allocates ``-i`` megabytes if given, grows to ``-m`` megabytes total, and
holds for ``-t`` seconds -- or forever, if ``-k`` (keep-alive) was passed,
on the expectation that an OOM kill ends it.

OSS semantics differ from Meta's here, deliberately. Meta's memory_pressure
just allocates; fb-oomd then kills it off PSI pressure thresholds configured
on the slice. OSS has no oomd, and on a stock DUT ``system.slice`` carries
``memory.max = max`` (unlimited), so allocating a calibrated fraction of RAM
produces no OOM condition at all -- the allocation simply succeeds and the health
check finds nothing. So the OSS stand-in creates the limit it is going to
breach: it writes ``memory.max`` on its own child cgroup (the smaller of
``OOM_HEADROOM`` x target and the parent slice's own limit, when the parent
has one) and disables swap accounting for it, then allocates past it. The
kernel then OOM-kills inside the cgroup and logs
``oom-kill:constraint=CONSTRAINT_MEMCG,...,task_memcg=/<slice>/memory-pressure``,
which is the record ``OomdKillHealthCheck`` reads. What is exercised is the
kernel's memcg OOM path rather than oomd's pressure path; the blast radius
(one cgroup, one victim, the slice's own accounting) is the same.

Every phase prints to stdout, flushed, before it can die: the step redirects
that to ``/tmp/taac_oss_memory_pressure.log`` and the health check prints the
file when a kill is missing, so "empty" means never started, "allocating..."
as the last line means killed as intended, and "completed without an OOM
kill" names the failure outright.

Note on ``-k``: the driver's shell timeout is 300 s, and the step launches
this fire-and-forget, so with ``-k`` the caller's thread ends in a timeout
and this process' fate then depends on whether the channel close delivers
SIGHUP. A caller that does not pass keep_alive does not hit that path; one
that does should set the step's duration and the driver timeout deliberately
rather than relying on it.

This file is pushed to the DUT byte-for-byte (see
``AllocateCgroupSliceMemory.run``) and run there with the DUT's system
python3, so it is stdlib-only and self-contained -- no taac install on the
DUT required.
"""

import argparse
import os
import sys
import time
import typing as t

# Not hardcoded 4096: aarch64 CPU/BMC cards run 16K/64K pages, where a 4096
# stride just over-touches.
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
# Grow in chunks rather than one big extend: ``b"\0" * n`` materialises the
# whole temporary (memset, so fully resident) before extend copies it in,
# which peaks at ~2x the requested allocation. This step exists to apply a
# calibrated fraction of RAM, and a 2x transient changes both which process
# the kernel picks and what the postcheck sees.
CHUNK_BYTES = 64 * 1024 * 1024
# The child cgroup's memory.max, as a fraction of the target allocation: the
# allocation has to overshoot the limit for the kernel to act, and the margin
# has to clear the interpreter's own resident set (~15 MB) so the cap does not
# fire before the log lines above it are flushed.
OOM_HEADROOM = 0.9


def child_cgroup_path(cgroup_slice: str) -> str:
    """The child cgroup this script joins, e.g. ``system.slice`` ->
    ``/sys/fs/cgroup/system.slice/memory-pressure``."""
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
    """Create the child cgroup, move this process into it, and prove the
    memory controller is actually enabled there.

    Without ``memory`` in the parent's ``cgroup.subtree_control`` the child
    has no memory controller, and the kernel then attributes the kill to the
    nearest enabling ancestor -- ``task_memcg=/system.slice``. The health
    check's last-two-path-segments split turns that into slice ``""`` and
    process ``"system.slice"``: a FAIL whose message points at nothing.
    Failing here instead makes the real cause readable.
    """
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "cgroup.procs"), "w") as f:
        f.write(str(os.getpid()))
    if not os.path.exists(os.path.join(path, "memory.current")):
        raise SystemExit(
            f"{path} has no memory controller -- 'memory' is not in the "
            f"parent's cgroup.subtree_control, so an OOM kill here would be "
            f"attributed to the parent slice instead of memory-pressure"
        )


def _parent_memory_max(path: str) -> t.Optional[int]:
    """The parent slice's ``memory.max`` in bytes, or ``None`` when it is
    unlimited (the stock OSS case) or unreadable."""
    try:
        with open(os.path.join(os.path.dirname(path), "memory.max")) as f:
            raw = f.read().strip()
    except OSError:
        return None
    return int(raw) if raw.isdigit() else None


def _set_memory_limit(path: str, target_bytes: int) -> int:
    """Give the child cgroup the limit the allocation will breach.

    Returns the byte value written. Capped by the parent slice's own limit
    when it has one, so a DUT that *does* budget the slice is stressed
    against that budget rather than past it.
    """
    limit = int(target_bytes * OOM_HEADROOM)
    parent_max = _parent_memory_max(path)
    if parent_max is not None:
        limit = min(limit, parent_max)
    with open(os.path.join(path, "memory.max"), "w") as f:
        f.write(str(limit))
    try:
        # A DUT with swap would page the allocation out and never hit the
        # limit. Absent on a kernel built without swap accounting, which is
        # the same as having none.
        with open(os.path.join(path, "memory.swap.max"), "w") as f:
            f.write("0")
    except OSError:
        pass
    return limit


def _set_oom_score_adj(value: int) -> None:
    with open("/proc/self/oom_score_adj", "w") as f:
        f.write(str(value))


def _touch(buf: bytearray, start: int) -> None:
    """Fault in every page from ``start`` on, so the memory is resident and
    counts against the slice rather than staying an untouched mapping."""
    for i in range(start, len(buf), PAGE_SIZE):
        buf[i] = 1


def _allocate_and_hold(
    megabytes: int, duration_s: int, initial_megabytes: int, keep_alive: bool
) -> None:
    target_bytes = megabytes * 1024 * 1024
    initial_bytes = min(initial_megabytes, megabytes) * 1024 * 1024
    # bytearray(n) is calloc'd, so the pages are not resident until touched.
    buf = bytearray(initial_bytes)
    _touch(buf, 0)
    while len(buf) < target_bytes:
        already = len(buf)
        buf.extend(bytes(min(CHUNK_BYTES, target_bytes - already)))
        _touch(buf, already)
    time.sleep(duration_s)
    while keep_alive:
        # The caller expects the OOM killer, not this sleep, to end us.
        time.sleep(60)


def main(argv: t.Optional[t.Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    path = child_cgroup_path(args.cgroup_slice)
    # Flushed before anything that can fail, so the redirected log tells a
    # crash apart from an OOM kill apart from a no-op.
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

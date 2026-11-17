# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

import io
import contextlib
import os
import tempfile
import unittest
from unittest.mock import patch

from taac.driver import oss_memory_pressure_dut_script as module


class OssMemoryPressureDutScriptTest(unittest.TestCase):
    def test_parses_the_meta_binary_cli(self) -> None:
        args = module.parse_args(
            ["-c", "system.slice", "-m", "2048", "-t", "180", "-k", "-s", "1000"]
        )
        self.assertEqual(args.cgroup_slice, "system.slice")
        self.assertEqual(args.megabytes, 2048)
        self.assertEqual(args.duration_s, 180)
        self.assertTrue(args.keep_alive)
        self.assertEqual(args.oom_score_adj, 1000)

    def test_dash_i_is_accepted(self) -> None:
        """The step and the legacy task both emit -i for
        initial_memory_allocation; argparse used to exit 2 on it."""
        args = module.parse_args(
            ["-c", "system.slice", "-m", "2048", "-t", "180", "-i", "512"]
        )
        self.assertEqual(args.initial_megabytes, 512)

    def test_optional_flags_default_off(self) -> None:
        args = module.parse_args(["-c", "system.slice", "-m", "2048", "-t", "180"])
        self.assertFalse(args.keep_alive)
        self.assertEqual(args.oom_score_adj, 0)
        self.assertEqual(args.initial_megabytes, 0)

    def test_missing_required_flag_raises(self) -> None:
        with self.assertRaises(SystemExit):
            module.parse_args(["-m", "2048", "-t", "180"])

    def test_child_cgroup_path_is_named_memory_pressure_under_the_slice(self) -> None:
        self.assertEqual(
            module.child_cgroup_path("system.slice"),
            "/sys/fs/cgroup/system.slice/memory-pressure",
        )


class JoinCgroupTest(unittest.TestCase):
    """The cgroup tree is faked on disk: the point is the controller
    read-back, not real cgroup semantics."""

    def _join(self, tmp, write_memory_current):
        path = os.path.join(tmp, "memory-pressure")

        real_makedirs = os.makedirs

        def fake_makedirs(p, exist_ok=False):
            real_makedirs(p, exist_ok=exist_ok)
            if write_memory_current:
                with open(os.path.join(p, "memory.current"), "w") as f:
                    f.write("0\n")

        with patch.object(module.os, "makedirs", fake_makedirs):
            module._join_cgroup(path)
        return path

    def test_joins_when_the_memory_controller_is_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._join(tmp, write_memory_current=True)
            with open(os.path.join(path, "cgroup.procs")) as f:
                self.assertEqual(f.read(), str(os.getpid()))

    def test_no_memory_controller_fails_loudly(self) -> None:
        """Without 'memory' in the parent's subtree_control the kernel
        attributes the kill to the parent slice, and the health check's
        last-two-segments split then reports a process of "system.slice"
        and an empty slice -- a FAIL pointing at nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as caught:
                self._join(tmp, write_memory_current=False)
            self.assertIn("no memory controller", str(caught.exception))


class SetMemoryLimitTest(unittest.TestCase):
    """Without a limit there is no OOM kill: stock OSS leaves system.slice at
    memory.max=max, so a calibrated fraction of RAM allocates cleanly and the
    kernel never acts."""

    def _tree(self, tmp, parent_max):
        child = os.path.join(tmp, "memory-pressure")
        os.makedirs(child)
        if parent_max is not None:
            with open(os.path.join(tmp, "memory.max"), "w") as f:
                f.write(f"{parent_max}\n")
        return child

    def _written(self, child, name="memory.max"):
        with open(os.path.join(child, name)) as f:
            return f.read()

    def test_unlimited_parent_gets_a_limit_below_the_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max="max")
            limit = module._set_memory_limit(child, 1000)
            self.assertEqual(limit, int(1000 * module.OOM_HEADROOM))
            self.assertEqual(self._written(child), str(limit))
            self.assertLess(limit, 1000)

    def test_missing_parent_memory_max_still_gets_a_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max=None)
            self.assertEqual(
                module._set_memory_limit(child, 1000),
                int(1000 * module.OOM_HEADROOM),
            )

    def test_a_budgeted_parent_caps_the_limit(self) -> None:
        """A DUT that does budget the slice is stressed against that budget,
        not past it."""
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max=500)
            self.assertEqual(module._set_memory_limit(child, 1000), 500)

    def test_swap_is_disabled_so_the_allocation_cannot_be_paged_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max="max")
            open(os.path.join(child, "memory.swap.max"), "w").close()
            module._set_memory_limit(child, 1000)
            self.assertEqual(self._written(child, "memory.swap.max"), "0")

    def test_unwritable_swap_max_is_not_an_error(self) -> None:
        """memory.swap.max is absent on a kernel built without swap
        accounting, which is the same as having no swap -- and must not take
        the limit write down with it. Faked as a directory, the portable way
        to make open(..., "w") raise OSError."""
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max="max")
            os.makedirs(os.path.join(child, "memory.swap.max"))
            self.assertEqual(
                module._set_memory_limit(child, 1000),
                int(1000 * module.OOM_HEADROOM),
            )


class MainLogsBeforeAllocatingTest(unittest.TestCase):
    def test_args_and_limit_are_flushed_before_the_allocation(self) -> None:
        """An empty /tmp/taac_oss_memory_pressure.log has to mean "never
        started" -- previously it meant nothing, because the script
        printed nothing."""
        order = []
        out = io.StringIO()
        with patch.object(module, "_join_cgroup", lambda p: order.append("join")):
            with patch.object(module, "_set_oom_score_adj", lambda v: None):
                with patch.object(
                    module, "_set_memory_limit", lambda p, b: 900
                ):
                    with patch.object(
                        module,
                        "_allocate_and_hold",
                        lambda *a: order.append("allocate"),
                    ):
                        with contextlib.redirect_stdout(out):
                            module.main(
                                ["-c", "system.slice", "-m", "10", "-t", "0"]
                            )
        logged = out.getvalue()
        self.assertEqual(order, ["join", "allocate"])
        self.assertIn("megabytes=10", logged)
        self.assertIn(
            "/sys/fs/cgroup/system.slice/memory-pressure/memory.max=900", logged
        )
        self.assertLess(logged.index("memory.max=900"), logged.index("allocating"))
        # The giveaway line when the kernel did not act.
        self.assertIn("completed without an OOM kill", logged)


class AllocateAndHoldTest(unittest.TestCase):
    def test_grows_from_the_initial_allocation_to_the_full_target(self) -> None:
        sizes = []
        with patch.object(module, "_touch", lambda buf, start: sizes.append(len(buf))):
            with patch.object(module.time, "sleep", lambda _s: None):
                module._allocate_and_hold(
                    megabytes=2, duration_s=0, initial_megabytes=1, keep_alive=False
                )
        self.assertEqual(sizes, [1 * 1024**2, 2 * 1024**2])

    def test_growth_is_chunked_so_peak_stays_near_the_target(self) -> None:
        """A single ``buf.extend(b"\\0" * n)`` materialises the whole
        temporary before copying it in, peaking at ~2x the requested
        allocation -- which would move the kill off the calibrated steady
        state this step exists to apply. Observed through the per-chunk
        _touch offsets: one extend per chunk, never one for the whole
        target."""
        chunk = module.CHUNK_BYTES
        starts, lengths = [], []

        def spy_touch(buf, start):
            starts.append(start)
            lengths.append(len(buf))

        with patch.object(module, "_touch", spy_touch):
            with patch.object(module.time, "sleep", lambda _s: None):
                module._allocate_and_hold(
                    megabytes=(chunk // 1024**2) * 3,
                    duration_s=0,
                    initial_megabytes=0,
                    keep_alive=False,
                )
        # The initial (empty) touch, then one per chunk.
        self.assertEqual(starts, [0, 0, chunk, 2 * chunk])
        self.assertEqual(lengths, [0, chunk, 2 * chunk, 3 * chunk])

    def test_keep_alive_sleeps_past_the_duration(self) -> None:
        """-k means the caller expects the OOM killer to end this process,
        not the -t timer."""
        calls = []

        def fake_sleep(seconds):
            calls.append(seconds)
            if len(calls) > 2:
                raise KeyboardInterrupt

        with patch.object(module, "_touch", lambda buf, start: None):
            with patch.object(module.time, "sleep", fake_sleep):
                with self.assertRaises(KeyboardInterrupt):
                    module._allocate_and_hold(
                        megabytes=1, duration_s=5, initial_megabytes=0, keep_alive=True
                    )
        self.assertEqual(calls[0], 5)
        self.assertEqual(calls[1], 60)


if __name__ == "__main__":
    unittest.main()

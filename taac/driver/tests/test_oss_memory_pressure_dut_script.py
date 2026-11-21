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
            ["-c", "system.slice", "-m", "10480", "-t", "180", "-k", "-s", "1000"]
        )
        self.assertEqual(args.cgroup_slice, "system.slice")
        self.assertEqual(args.megabytes, 10480)
        self.assertEqual(args.duration_s, 180)
        self.assertTrue(args.keep_alive)
        self.assertEqual(args.oom_score_adj, 1000)

    def test_dash_i_is_accepted(self) -> None:
        args = module.parse_args(
            ["-c", "system.slice", "-m", "10480", "-t", "180", "-i", "512"]
        )
        self.assertEqual(args.initial_megabytes, 512)

    def test_optional_flags_default_off(self) -> None:
        args = module.parse_args(["-c", "system.slice", "-m", "10480", "-t", "180"])
        self.assertFalse(args.keep_alive)
        self.assertEqual(args.oom_score_adj, 0)
        self.assertEqual(args.initial_megabytes, 0)

    def test_missing_required_flag_raises(self) -> None:
        with self.assertRaises(SystemExit):
            module.parse_args(["-m", "10480", "-t", "180"])

    def test_child_cgroup_path_is_named_memory_pressure_under_the_slice(self) -> None:
        self.assertEqual(
            module.child_cgroup_path("system.slice"),
            "/sys/fs/cgroup/system.slice/memory-pressure",
        )


class JoinCgroupTest(unittest.TestCase):
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
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as caught:
                self._join(tmp, write_memory_current=False)
            self.assertIn("no memory controller", str(caught.exception))


class SetMemoryLimitTest(unittest.TestCase):
    def setUp(self) -> None:
        # The tests must not depend on the memory of the machine that runs them.
        patcher = patch.object(module, "MEMINFO_PATH", "/nonexistent/meminfo")
        patcher.start()
        self.addCleanup(patcher.stop)

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
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max=500)
            self.assertEqual(module._set_memory_limit(child, 1000), 500)

    def test_the_limit_stays_below_the_available_memory_of_the_dut(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max="max")
            meminfo = os.path.join(tmp, "meminfo")
            with open(meminfo, "w") as f:
                f.write("MemTotal: 4194304 kB\nMemAvailable: 2097152 kB\n")
            with patch.object(module, "MEMINFO_PATH", meminfo):
                limit = module._set_memory_limit(child, 10 * 1024**3)
            self.assertEqual(limit, 2 * 1024**3 - module.MEM_AVAILABLE_MARGIN_BYTES)
            self.assertEqual(self._written(child), str(limit))

    def test_swap_is_disabled_so_the_allocation_cannot_be_paged_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max="max")
            open(os.path.join(child, "memory.swap.max"), "w").close()
            module._set_memory_limit(child, 1000)
            self.assertEqual(self._written(child, "memory.swap.max"), "0")

    def test_unwritable_swap_max_is_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            child = self._tree(tmp, parent_max="max")
            os.makedirs(os.path.join(child, "memory.swap.max"))
            self.assertEqual(
                module._set_memory_limit(child, 1000),
                int(1000 * module.OOM_HEADROOM),
            )


class MainLogsBeforeAllocatingTest(unittest.TestCase):
    def test_args_and_limit_are_flushed_before_the_allocation(self) -> None:
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

# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""OOM expectations must be observed in the caller's requested log window."""

import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_check.health_check import types as hc_types
from taac.health_checks.device_health_checks import oomd_kill_health_check as module


class TestOomdKillHealthCheck(unittest.IsolatedAsyncioTestCase):
    async def check_log(
        self, entries, expected=None, window_seconds=120, dut_offset_seconds=None
    ):
        # Execute the production log-filter command against a local fixture;
        # only the remote transport is replaced, so stale-log regressions are real.
        now = int(time.time()) // 60 * 60
        start = now - window_seconds
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fb-oomd.log"
            path.write_text("\n".join(
                f"{time.strftime('%b %e %H:%M:%S', time.localtime(start + offset))} "
                f"Trying to kill /sys/fs/cgroup/{slice_name}/{process}"
                for offset, slice_name, process in entries
            ))

            async def run_command(cmd):
                if dut_offset_seconds is not None and cmd == "date +%z":
                    sign = "-" if dut_offset_seconds < 0 else "+"
                    minutes = abs(dut_offset_seconds) // 60
                    return "%s%02d%02d\n" % (sign, minutes // 60, minutes % 60)
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                self.assertIn(result.returncode, (0, 1), result.stderr)
                return result.stdout

            check = module.OomdKillHealthCheck(logger=MagicMock())
            check.driver = MagicMock()
            check.driver.async_run_cmd_on_shell = AsyncMock(side_effect=run_command)
            with patch.object(module, "FB_OOMD_LOG_PATH", str(path)), patch.object(
                module.time, "time", return_value=now
            ), patch.object(module, "TAAC_OSS", False):
                return await check._run(
                    MagicMock(), hc_types.BaseHealthCheckIn(),
                    {
                        "start_time": start,
                        "end_time": now,
                        "expected_oom_kills": expected if expected is not None else {
                            "system.slice": ["memory-pressure"]
                        },
                    },
                )

    async def test_empty_log_fails(self):
        result = await self.check_log([])
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("memory-pressure", result.message)

    async def test_expected_kill_passes(self):
        result = await self.check_log([(30, "system.slice", "memory-pressure")])
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_missing_one_expected_kill_fails(self):
        result = await self.check_log(
            [(30, "system.slice", "memory-pressure")],
            {"system.slice": ["memory-pressure", "second-allocator"]},
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("second-allocator", result.message)

    async def test_wrong_slice_does_not_satisfy_expectation(self):
        result = await self.check_log([(30, "workload.slice", "memory-pressure")])
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_unexpected_victim_still_fails(self):
        result = await self.check_log([
            (30, "system.slice", "memory-pressure"),
            (40, "system.slice", "fboss_sw_agent.service"),
        ])
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("fboss_sw_agent.service", result.message)

    async def test_old_expected_kill_does_not_satisfy_expectation(self):
        result = await self.check_log([(-3600, "system.slice", "memory-pressure")])
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_old_unexpected_victim_does_not_fail_current_window(self):
        result = await self.check_log([
            (-3600, "system.slice", "fboss_sw_agent.service"),
            (30, "system.slice", "memory-pressure"),
        ])
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_kill_after_end_does_not_satisfy_expectation(self):
        result = await self.check_log([(180, "system.slice", "memory-pressure")])
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_empty_window_fails_without_accepting_old_log(self):
        result = await self.check_log(
            [(-3600, "system.slice", "memory-pressure")], window_seconds=0
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_reversed_window_fails_without_accepting_old_log(self):
        result = await self.check_log(
            [(-3600, "system.slice", "memory-pressure")], window_seconds=-60
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_the_window_follows_the_dut_timezone_not_the_runners(self):
        """The fixture log is stamped in the runner's zone. Telling the check
        the DUT is six hours ahead must move the grep window off it, so the
        kill is no longer found."""
        result = await self.check_log(
            [(30, "system.slice", "memory-pressure")],
            dut_offset_seconds=module.runner_utc_offset_seconds() + 6 * 3600,
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_the_same_dut_timezone_still_matches(self):
        result = await self.check_log(
            [(30, "system.slice", "memory-pressure")],
            dut_offset_seconds=module.runner_utc_offset_seconds(),
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_the_dut_offset_is_read_once_and_reused(self):
        """A retry must not re-read it: one failed `date +%z` would move the
        window by hours and flip the verdict."""
        check = module.OomdKillHealthCheck(logger=MagicMock())
        reads = []

        async def shell(cmd):
            reads.append(cmd)
            return "+0530\n"

        check.driver = MagicMock()
        check.driver.async_run_cmd_on_shell = AsyncMock(side_effect=shell)
        first = await check._async_dut_utc_offset_seconds()
        second = await check._async_dut_utc_offset_seconds()
        self.assertEqual(first, 5 * 3600 + 30 * 60)
        self.assertEqual(second, first)
        self.assertEqual(reads, ["date +%z"])

    async def test_the_offset_is_parsed_by_shape_not_position(self):
        """Transport noise around the value must not change the answer, and a
        signless value must fail rather than parse as garbage."""
        for raw, expected in (
            ("+0530", 5 * 3600 + 30 * 60),
            ("-0800", -(8 * 3600)),
            ("some-motd-line\n+0530", 5 * 3600 + 30 * 60),
            ("0530", None),
            ("", None),
        ):
            with self.subTest(raw=raw):
                check = module.OomdKillHealthCheck(logger=MagicMock())
                check.driver = MagicMock()
                check.driver.async_run_cmd_on_shell = AsyncMock(return_value=raw)
                offset = await check._async_dut_utc_offset_seconds()
                if expected is None:
                    self.assertEqual(offset, module.runner_utc_offset_seconds())
                else:
                    self.assertEqual(offset, expected)

    async def test_a_failed_offset_read_is_not_cached(self):
        """Falling back to the runner's offset is a guess; it must not stick
        and mask a later successful read."""
        check = module.OomdKillHealthCheck(logger=MagicMock())
        answers = [OSError("ssh down"), "+0530\n"]

        async def shell(_cmd):
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        check.driver = MagicMock()
        check.driver.async_run_cmd_on_shell = AsyncMock(side_effect=shell)
        self.assertEqual(
            await check._async_dut_utc_offset_seconds(),
            module.runner_utc_offset_seconds(),
        )
        self.assertEqual(
            await check._async_dut_utc_offset_seconds(), 5 * 3600 + 30 * 60
        )

    async def test_a_kill_in_an_unlisted_slice_is_reported(self):
        """Iterating only the expectations hid every kill in a slice nobody
        listed."""
        result = await self.check_log(
            [
                (30, "system.slice", "memory-pressure"),
                (40, "workload.slice", "fboss_sw_agent.service"),
            ]
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("workload.slice", result.message)
        self.assertIn("fboss_sw_agent.service", result.message)


class OssOomCommandAndPatternTest(unittest.TestCase):
    """OSS has no fb-oomd; these cover the kernel-log command/pattern in
    isolation, without needing a real journalctl on this box."""

    def test_window_uses_epoch_seconds_and_needs_no_dut_timezone(self):
        """journalctl takes @<epoch> directly, so the OSS branch skips
        _async_dut_utc_offset_seconds and its wrong-answer fallback."""
        cmd, _pattern = module._oss_oom_command_and_pattern(
            start_time=1_700_000_000, end_time=1_700_000_120
        )
        self.assertIn("journalctl -k", cmd)
        # A minute of slack each way: the runner's clock sets the window, the
        # DUT's clock stamps the journal, and DUT clocks drift.
        self.assertIn(f"--since @{1_700_000_000 - 60}", cmd)
        self.assertIn(f"--until @{1_700_000_120 + 60}", cmd)
        # -q --no-pager: older systemd prints "-- Logs begin at ... --".
        self.assertIn("-q", cmd)
        self.assertIn("--no-pager", cmd)
        self.assertIn(module._RC_MARKER, cmd)

    def test_the_oss_command_does_not_depend_on_journalctl_grep(self):
        """--grep needs systemd >= 237 with PCRE2; when absent journalctl
        leaves stdout empty and this check would call that a product
        failure."""
        cmd, _pattern = module._oss_oom_command_and_pattern(0, 60)
        self.assertNotIn("-g ", cmd)
        self.assertNotIn("--grep", cmd)

    def test_pattern_extracts_the_oom_memcg_from_a_real_kernel_line(self):
        _cmd, pattern = module._oss_oom_command_and_pattern(0, 60)
        line = (
            "Sep 22 10:15:03 dut1 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,"
            "nodemask=(null),cpuset=/,mems_allowed=0,global_oom,"
            "task_memcg=/system.slice/memory-pressure,task=memory_pressure,"
            "pid=12345,uid=0"
        )
        match = module.re.search(pattern, line)
        self.assertIsNotNone(match)
        self.assertEqual(match.group("cgroup_path"), "/system.slice/memory-pressure")


class TestOomdKillHealthCheckUnderOss(unittest.IsolatedAsyncioTestCase):
    def _check(
        self,
        journal_text,
        allocator_log="allocator log line",
        rc=0,
        allocator_mtime=0,
    ):
        check = module.OomdKillHealthCheck(logger=MagicMock())
        check.driver = MagicMock()
        check.driver.hostname = "dut1"

        async def run_command(cmd):
            if cmd.startswith("cat "):
                return allocator_log
            # The production command stats the pushed allocator first (the
            # marker for "this device ran the step") and appends journalctl's
            # exit status last, because the driver returns stdout only and
            # journalctl's own diagnostics go to stderr.
            prefix = (
                ""
                if allocator_mtime is None
                else f"{module._MTIME_MARKER}{allocator_mtime}\n"
            )
            suffix = "" if rc is None else f"\n{module._RC_MARKER}{rc}"
            return f"{prefix}{journal_text}{suffix}"

        check.driver.async_run_cmd_on_shell = AsyncMock(side_effect=run_command)
        return check

    async def _run_with_journal(
        self, journal_text, expected=None, start_time=0, end_time=60, **kwargs
    ):
        check = self._check(journal_text, **kwargs)
        with patch.object(module, "TAAC_OSS", True):
            return await check._run(
                MagicMock(),
                hc_types.BaseHealthCheckIn(),
                {
                    "start_time": start_time,
                    "end_time": end_time,
                    "expected_oom_kills": expected
                    if expected is not None
                    else {"system.slice": ["memory-pressure"]},
                },
            )

    async def test_kill_of_the_memory_pressure_cgroup_passes(self):
        result = await self._run_with_journal(
            "Sep 22 10:15:03 dut1 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,"
            "task_memcg=/system.slice/memory-pressure,task=memory_pressure,pid=1,uid=0"
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_kill_of_a_different_unit_under_the_slice_fails(self):
        result = await self._run_with_journal(
            "Sep 22 10:15:03 dut1 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,"
            "task_memcg=/system.slice/bgpd,task=bgpd,pid=1,uid=0"
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("bgpd", result.message)

    async def test_a_nonzero_journalctl_exit_is_an_error_not_a_verdict(self):
        """journalctl needs root and -k is current-boot only; both exit
        non-zero, and their diagnostics go to stderr, which the driver
        discards -- so the exit status is the only signal that survives."""
        result = await self._run_with_journal("", rc=1)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.ERROR)
        self.assertIn("tooling failure", result.message)

    async def test_a_missing_exit_marker_is_an_error(self):
        result = await self._run_with_journal("", rc=None)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.ERROR)

    async def test_a_quiet_kernel_is_a_verdict_not_a_tooling_failure(self):
        """The failure this playbook exists to detect -- the platform did not
        OOM-kill under pressure -- looks exactly like an empty window on a
        box whose kernel is otherwise silent. It must FAIL, not ERROR, and
        must collect the allocator log."""
        result = await self._run_with_journal(
            "", rc=0, allocator_log="MemoryError"
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("memory-pressure", result.message)
        self.assertIn("MemoryError", result.message)

    async def test_routine_kernel_text_does_not_discard_a_real_kill(self):
        """Without --grep the whole kernel ring for the window comes back,
        and "failed to" / "not found" are ordinary kernel strings."""
        result = await self._run_with_journal(
            "Sep 22 10:15:01 dut1 kernel: bnxt_en: Failed to load firmware\n"
            "Sep 22 10:15:02 dut1 kernel: ACPI: table not found\n"
            "Sep 22 10:15:03 dut1 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,"
            "task_memcg=/system.slice/memory-pressure,task=memory_pressure,pid=1"
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_a_missing_kill_quotes_the_allocators_own_log(self):
        """The usual reason for a missing kill is that the fire-and-forget
        stand-in died; nothing else in the tree reads its log."""
        result = await self._run_with_journal(
            "Sep 22 10:15:03 dut1 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,"
            "task_memcg=/system.slice/something-else,task=x,pid=1,uid=0",
            allocator_log="PermissionError: /sys/fs/cgroup/...",
            expected={"system.slice": ["memory-pressure"]},
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("PermissionError", result.message)
        self.assertIn(module.OSS_MEMORY_PRESSURE_LOG, result.message)

    async def test_kills_outside_the_expected_slices_are_ignored(self):
        """journalctl -k sees every OOM kill on the box, unlike fb-oomd.log
        which holds only oomd's own."""
        result = await self._run_with_journal(
            "Sep 22 10:15:03 dut1 kernel: oom-kill:"
            "task_memcg=/user.slice/user-0.slice/session-1.scope,task=x,pid=1\n"
            "Sep 22 10:15:04 dut1 kernel: oom-kill:"
            "task_memcg=/system.slice/memory-pressure,task=y,pid=2"
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_a_root_cgroup_victim_is_not_a_phantom_unexpected_kill(self):
        result = await self._run_with_journal(
            "Sep 22 10:15:03 dut1 kernel: oom-kill:constraint=CONSTRAINT_NONE,"
            "task_memcg=/,task=someproc,pid=1,uid=0\n"
            "Sep 22 10:15:04 dut1 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,"
            "task_memcg=/system.slice/memory-pressure,task=memory_pressure,"
            "pid=2,uid=0"
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_a_device_that_never_ran_the_allocator_is_skipped(self):
        """The allocator step runs on one device; the playbook's postchecks
        run on every device in a multi-DUT topology. Those never stressed
        must not report "Oom kills not detected" for a kill nothing asked
        them to produce."""
        result = await self._run_with_journal("", allocator_mtime=None)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.SKIP)
        self.assertIn(module.OSS_MEMORY_PRESSURE_PATH, result.message)
        self.assertIn("absent", result.message)

    async def test_a_device_that_never_ran_the_allocator_skips_even_with_a_broken_journalctl(
        self,
    ) -> None:
        """"Is this expectation even mine?" has to be decided before "can I
        read the journal?" -- in a multi-DUT topology, most devices never ran the
        allocator, and a journalctl that's unusable on all of them (needs root,
        or -k not supported) must not turn their correct SKIP into a
        misleading ERROR."""
        result = await self._run_with_journal("", allocator_mtime=None, rc=1)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.SKIP)

    async def test_an_allocator_left_over_from_an_earlier_run_is_skipped(self):
        """The step rewrites the stand-in every run, so anything stamped
        before this window belongs to a previous one."""
        result = await self._run_with_journal(
            "",
            start_time=1_700_000_000,
            end_time=1_700_000_120,
            allocator_mtime=1_700_000_000 - 10_000,
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.SKIP)
        self.assertIn("stale", result.message)

    async def test_the_stat_cannot_swallow_journalctls_exit_status(self):
        """`stat` runs first precisely so that "$?" still belongs to
        journalctl; a missing file must not read as a clean journal."""
        cmd, _pattern = module._oss_oom_command_and_pattern(0, 60)
        self.assertLess(cmd.index("stat -c"), cmd.index("journalctl"))
        self.assertLess(cmd.index("journalctl"), cmd.index(module._RC_MARKER))
        self.assertIn(module.OSS_MEMORY_PRESSURE_PATH, cmd)

    async def test_a_kill_attributed_to_the_bare_slice_stays_visible(self):
        """What a missing memory controller on the child cgroup looks like:
        the kernel names the slice itself, not a unit under it."""
        result = await self._run_with_journal(
            "Sep 22 10:15:03 dut1 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,"
            "task_memcg=/system.slice,task=memory_pressure,pid=1,uid=0"
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("<slice root>", result.message)


if __name__ == "__main__":
    unittest.main()

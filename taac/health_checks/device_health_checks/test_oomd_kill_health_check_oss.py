# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""A pure OSS DUT has no fb-oomd log: the check reads the kernel OOM record."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_check.health_check import types as hc_types
from taac.health_checks.device_health_checks import oomd_kill_health_check as module

_RC_OK = "__TAAC_JOURNALCTL_RC=0"
_END_TIME = 1_000_000
_EXPECTED = {"system.slice": ["memory-pressure"]}


def _kill(task_memcg: str) -> str:
    return (
        "Jan 01 00:00:00 dut kernel: oom-kill:constraint=CONSTRAINT_MEMCG,"
        "nodemask=(null),cpuset=/,mems_allowed=0,"
        f"oom_memcg={task_memcg},task_memcg={task_memcg},task=python3,pid=7,uid=0"
    )


class OomdKillHealthCheckOssTest(unittest.IsolatedAsyncioTestCase):
    async def _run_check(self, output, pure_oss=True, expected=_EXPECTED):
        check = module.OomdKillHealthCheck(logger=MagicMock())
        check.driver = MagicMock()
        check.driver.async_run_cmd_on_shell = AsyncMock(return_value=output)
        with (
            patch.object(module, "TAAC_OSS", True),
            patch.object(module, "TAAC_OSS_META_INTERNAL", not pure_oss),
        ):
            result = await check._run(
                MagicMock(),
                hc_types.BaseHealthCheckIn(),
                {
                    "start_time": _END_TIME - 600,
                    "end_time": _END_TIME,
                    "expected_oom_kills": expected,
                },
            )
        return result, check.driver.async_run_cmd_on_shell.await_args.args[0]

    async def test_reads_the_kernel_journal_with_a_widened_window(self) -> None:
        _result, cmd = await self._run_check(_RC_OK)

        self.assertIn(
            f"journalctl -k -q --no-pager --since @{_END_TIME - 600 - 60} ", cmd
        )
        self.assertIn(f"--until @{_END_TIME + 60}", cmd)
        self.assertNotIn(module.FB_OOMD_LOG_PATH, cmd)

    async def test_the_expected_kill_passes(self) -> None:
        output = f"{_kill('/system.slice/memory-pressure')}\n{_RC_OK}"
        result, _cmd = await self._run_check(output)

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_an_unexpected_process_in_an_expected_slice_fails(self) -> None:
        output = f"{_kill('/system.slice/stray')}\n{_RC_OK}"
        result, _cmd = await self._run_check(output)

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("stray", result.message)

    async def test_a_kill_in_another_slice_is_ignored(self) -> None:
        output = f"{_kill('/user.slice/other')}\n{_RC_OK}"
        result, _cmd = await self._run_check(output)

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_a_journalctl_failure_is_an_error(self) -> None:
        for output in ("__TAAC_JOURNALCTL_RC=1", ""):
            with self.subTest(output=output):
                result, _cmd = await self._run_check(output)
                self.assertEqual(result.status, hc_types.HealthCheckStatus.ERROR)

    async def test_meta_internal_keeps_the_fb_oomd_log(self) -> None:
        _result, cmd = await self._run_check("", pure_oss=False)

        self.assertIn(module.FB_OOMD_LOG_PATH, cmd)
        self.assertNotIn("journalctl", cmd)


if __name__ == "__main__":
    unittest.main()

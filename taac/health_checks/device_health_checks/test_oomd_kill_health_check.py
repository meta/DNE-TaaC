# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""The OOMD kill check must read the log window that the caller asks for."""

import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_check.health_check import types as hc_types
from taac.health_checks.device_health_checks import oomd_kill_health_check as module

HOUR = 3600


class TestOomdKillHealthCheck(unittest.IsolatedAsyncioTestCase):
    async def _run_check(self, kill_age_s: int, window_start_age_s: int):
        now = int(time.time()) // 60 * 60
        kill_time = now - kill_age_s
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "fb-oomd.log"
            log.write_text(
                f"{time.strftime('%b %e %H:%M:%S', time.localtime(kill_time))} "
                "Trying to kill /sys/fs/cgroup/system.slice/stray-process\n"
            )

            async def run_command(cmd):
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                self.assertIn(result.returncode, (0, 1), result.stderr)
                return result.stdout

            check = module.OomdKillHealthCheck(logger=MagicMock())
            check.driver = MagicMock()
            check.driver.async_run_cmd_on_shell = AsyncMock(side_effect=run_command)
            # These tests cover the fb-oomd log path, so they turn off TAAC_OSS.
            with patch.object(module, "TAAC_OSS", False), patch.object(
                module, "FB_OOMD_LOG_PATH", str(log)
            ), patch.object(module.time, "time", return_value=now):
                return await check._run(
                    MagicMock(),
                    hc_types.BaseHealthCheckIn(),
                    {
                        "start_time": now - window_start_age_s,
                        "expected_oom_kills": {"system.slice": ["expected-process"]},
                    },
                )

    async def test_kill_inside_window_is_reported(self):
        result = await self._run_check(kill_age_s=HOUR, window_start_age_s=2 * HOUR)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_window_start_older_than_24_hours_is_honored(self):
        # The kill is 25 h old. Only a window from start_time (26 h ago) sees it.
        result = await self._run_check(kill_age_s=25 * HOUR, window_start_age_s=26 * HOUR)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_kill_before_window_start_is_ignored(self):
        result = await self._run_check(kill_age_s=3 * HOUR, window_start_age_s=2 * HOUR)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)


if __name__ == "__main__":
    unittest.main()

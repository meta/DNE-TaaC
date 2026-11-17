# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import calendar
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_check.health_check import types as hc_types
from taac.health_checks.device_health_checks.log_parsing_health_check import (
    LogParsingHealthCheck,
)

SPLIT = "/var/facebook/logs/fboss/fboss_sw_agent.log"
LEGACY = "/var/facebook/logs/fboss/wedge_agent.log"
REJECTION = (
    "W0101 12:00:00.000000 1 ResourceAccountant.cpp:578] Invalid route update - "
    "exceeding route or ECMP resource limits."
)


DATE_OFFSET_CMD = "date +%z"


class LogParsingCandidatePathsTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.check = LogParsingHealthCheck(logger=MagicMock())
        self.check.driver = AsyncMock()

    def _shell_answers(self, answer):
        # ResourceAccountant mode asks the device for its UTC offset first.
        self.check.driver.async_run_cmd_on_shell.side_effect = lambda cmd: (
            "+0000\n" if cmd == DATE_OFFSET_CMD else answer
        )

    def _non_offset_shell_cmds(self):
        return [
            c.args[0]
            for c in self.check.driver.async_run_cmd_on_shell.call_args_list
            if c.args[0] != DATE_OFFSET_CMD
        ]

    async def test_a_single_path_is_used_as_given(self):
        self.assertEqual(await self.check._first_readable(SPLIT), SPLIT)
        self.check.driver.async_run_cmd_on_shell.assert_not_called()

    async def test_the_first_readable_candidate_wins(self):
        self.check.driver.async_run_cmd_on_shell.return_value = f"{LEGACY}\n"
        self.assertEqual(await self.check._first_readable([SPLIT, LEGACY]), LEGACY)
        (cmd,) = self.check.driver.async_run_cmd_on_shell.call_args.args
        self.assertLess(cmd.index(SPLIT), cmd.index(LEGACY))

    async def test_no_readable_candidate_raises(self):
        self.check.driver.async_run_cmd_on_shell.return_value = ""
        with self.assertRaisesRegex(RuntimeError, "none of"):
            await self.check._first_readable([SPLIT, LEGACY])

    async def test_resource_accountant_mode_reads_the_resolved_file(self):
        self._shell_answers(f"{LEGACY}\n")
        self.check.driver.async_read_log_file.return_value = REJECTION
        result = await self.check._run(
            MagicMock(),
            hc_types.BaseHealthCheckIn(),
            {"log_file_path": [SPLIT, LEGACY], "resource_accountant_activation": True},
        )
        self.assertEqual(self.check.driver.async_read_log_file.call_args.args[0], LEGACY)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_resource_accountant_mode_reads_archives_rotated_in_the_window(self):
        start = calendar.timegm((2000, 1, 1, 12, 9, 41, 0, 0, 0))
        archive = "/var/facebook/logs/fboss/archive/fboss_sw_agent.log-{}.gz"
        listing = "\n".join(
            [
                "fboss_sw_agent.log-200001011200.gz",
                "fboss_sw_agent.log-200001011300.gz",
                "fboss_sw_agent.log-200001011230.gz",
                "wedge_agent.log-200001011300.gz",
            ]
        )
        self._shell_answers(listing)
        rejection = (
            "E0101 12:56:07.000000 1 ResourceAccountant.cpp:1026] Total NDP entries "
            "in new switchState: 4001 exceeds the limit: 4000"
        )
        self.check.driver.async_read_log_file.side_effect = ["", rejection, ""]
        with patch("time.localtime", time.gmtime):
            result = await self.check._run(
                MagicMock(),
                hc_types.BaseHealthCheckIn(),
                {
                    "log_file_path": SPLIT,
                    "resource_accountant_activation": True,
                    "start_time": start,
                    "end_time": start + 4200,
                },
            )
        read = [c.args[0] for c in self.check.driver.async_read_log_file.call_args_list]
        self.assertEqual(
            read,
            [archive.format("200001011230"), archive.format("200001011300"), SPLIT],
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_no_window_reads_only_the_live_log(self):
        self._shell_answers("")
        self.check.driver.async_read_log_file.return_value = REJECTION
        await self.check._run(
            MagicMock(),
            hc_types.BaseHealthCheckIn(),
            {"log_file_path": SPLIT, "resource_accountant_activation": True},
        )
        self.assertEqual(self._non_offset_shell_cmds(), [])
        self.check.driver.async_read_log_file.assert_awaited_once()

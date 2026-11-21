# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import calendar
import unittest
from unittest.mock import AsyncMock, MagicMock

from taac.health_check.health_check import types as hc_types
from taac.health_checks.device_health_checks.log_parsing_health_check import (
    LogParsingHealthCheck,
)

AGENT_LOG = "/var/facebook/logs/fboss/fboss_sw_agent.log"
ARCHIVE = "/var/facebook/logs/fboss/archive/fboss_sw_agent.log-{}.gz"
REJECTION = (
    "W0101 12:00:00.000000 1 ResourceAccountant.cpp:578] Invalid route update - "
    "exceeding route or ECMP resource limits."
)
DATE_OFFSET_CMD = "date +%z"


class LogParsingRotatedArchivesTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.check = LogParsingHealthCheck(logger=MagicMock())
        self.check.driver = AsyncMock()

    def _shell_answers(self, answer, utc_offset="+0000"):
        # ResourceAccountant mode asks the device for its UTC offset first.
        self.check.driver.async_run_cmd_on_shell.side_effect = lambda cmd: (
            f"{utc_offset}\n" if cmd == DATE_OFFSET_CMD else answer
        )

    def _non_offset_shell_cmds(self):
        return [
            c.args[0]
            for c in self.check.driver.async_run_cmd_on_shell.call_args_list
            if c.args[0] != DATE_OFFSET_CMD
        ]

    async def test_reads_archives_rotated_in_the_window_in_device_time(self):
        # 20:09 UTC is 12:09 on a device at -0800; archive names use device time.
        start = calendar.timegm((2000, 1, 1, 20, 9, 41, 0, 0, 0))
        listing = "\n".join(
            [
                "fboss_sw_agent.log-200001011200.gz",
                "fboss_sw_agent.log-200001011300.gz",
                "fboss_sw_agent.log-200001011230.gz",
                "wedge_agent.log-200001011300.gz",
            ]
        )
        self._shell_answers(listing, utc_offset="-0800")
        rejection = (
            "E0101 12:56:07.000000 1 ResourceAccountant.cpp:1026] Total NDP entries "
            "in new switchState: 4001 exceeds the limit: 4000"
        )
        self.check.driver.async_read_log_file.side_effect = ["", rejection, ""]
        result = await self.check._run(
            MagicMock(),
            hc_types.BaseHealthCheckIn(),
            {
                "log_file_path": AGENT_LOG,
                "resource_accountant_activation": True,
                "start_time": start,
                "end_time": start + 4200,
            },
        )
        read = [c.args[0] for c in self.check.driver.async_read_log_file.call_args_list]
        self.assertEqual(
            read,
            [ARCHIVE.format("200001011230"), ARCHIVE.format("200001011300"), AGENT_LOG],
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_no_window_reads_only_the_live_log(self):
        self._shell_answers("")
        self.check.driver.async_read_log_file.return_value = REJECTION
        await self.check._run(
            MagicMock(),
            hc_types.BaseHealthCheckIn(),
            {"log_file_path": AGENT_LOG, "resource_accountant_activation": True},
        )
        self.assertEqual(self._non_offset_shell_cmds(), [])
        self.check.driver.async_read_log_file.assert_awaited_once()

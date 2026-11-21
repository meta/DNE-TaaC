# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""ECMP_GROUP_AND_MEMBER_COUNT_CHECK reports the counts it measured on PASS."""

import unittest
from unittest.mock import AsyncMock, MagicMock

from taac.constants import TestDevice
from taac.health_checks.device_health_checks.ecmp_group_and_member_count_health_check import (
    EcmpGroupAndMemberCountHealthCheck,
)
from taac.health_check.health_check import types as hc_types

# Two groups: 100 with two members, 200 with one.
_DUMP = """\
NextHopGroupSaiId(100): (Type: 0)
NextHopGroupMemberSaiId(1): (NextHopGroupId: 100, NextHopId: 11, Weight: 1)
NextHopGroupMemberSaiId(2): (NextHopGroupId: 100, NextHopId: 12, Weight: 1)
NextHopGroupSaiId(200): (Type: 0)
NextHopGroupMemberSaiId(3): (NextHopGroupId: 200, NextHopId: 13, Weight: 1)
"""


class TestEcmpGroupCountReport(unittest.IsolatedAsyncioTestCase):
    async def test_pass_message_carries_group_and_member_counts(self):
        check = EcmpGroupAndMemberCountHealthCheck(logger=MagicMock())
        check.driver = AsyncMock()
        check.driver.hostname = "dut1"
        check.driver.async_run_cmd_on_shell = AsyncMock(return_value=_DUMP)
        device = MagicMock(spec=TestDevice)
        device.name = "dut1"

        result = await check._run(
            device,
            hc_types.BaseHealthCheckIn(),
            {"ecmp_group_count": 10**9, "ecmp_member_count": 10**9},
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("2 ECMP groups", result.message)
        self.assertIn("3 members", result.message)

    async def test_empty_dump_warning_shows_the_head_of_the_dump(self):
        check = EcmpGroupAndMemberCountHealthCheck(logger=MagicMock())
        check._EMPTY_DUMP_RETRY_DELAY_S = 0
        check.driver = AsyncMock()
        check.driver.async_run_cmd_on_shell = AsyncMock(return_value="E" * 200 + "TAIL")

        await check._async_dump_next_hop_groups()

        warning = check.logger.warning.call_args.args[0]
        self.assertIn("E" * 200, warning)
        self.assertNotIn("TAIL", warning)

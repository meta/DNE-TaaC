# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import unittest
from unittest.mock import MagicMock

from taac.constants import TestDevice
from taac.health_check.health_check import types as hc_types
from taac.health_checks.constants import Snapshot
from taac.health_checks.snapshot_health_checks.port_speed_health_check import (
    PortSpeedHealtchCheck,
)


class PortSpeedSnapshotTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.device = MagicMock(spec=TestDevice)
        self.device.name = "dut1"
        self.hc = PortSpeedHealtchCheck(
            obj=self.device,
            input=hc_types.BaseHealthCheckIn(),
            pre_snapshot_checkpoint_id="test_case_start",
            post_snapshot_checkpoint_id="test_case_end",
            check_params={},
            logger=MagicMock(),
        )

    async def _compare(self, pre: int, post: int) -> hc_types.HealthCheckResult:
        return await self.hc.compare_snapshots(
            self.device,
            hc_types.BaseHealthCheckIn(),
            {},
            Snapshot(data={"eth1/17/5": pre}, timestamp=1),
            Snapshot(data={"eth1/17/5": post}, timestamp=2),
        )

    async def test_a_speed_of_zero_at_the_end_is_a_speed_change(self) -> None:
        result = await self._compare(400, 0)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("speed has changed", result.message)
        self.assertNotIn("not found", result.message)

    async def test_a_speed_of_zero_at_both_ends_is_unchanged(self) -> None:
        result = await self._compare(0, 0)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

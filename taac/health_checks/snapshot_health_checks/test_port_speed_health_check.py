# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""compare_snapshots reports the Gbps values it compares (speeds arrive in Gbps)."""

import unittest
from unittest.mock import MagicMock

from taac.constants import TestDevice
from taac.health_check.health_check import types as hc_types
from taac.health_checks.constants import Snapshot
from taac.health_checks.snapshot_health_checks.port_speed_health_check import PortSpeedHealtchCheck


class PortSpeedSnapshotMessageTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
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

    async def test_message_names_the_gbps_values(self):
        pre = Snapshot(data={"eth1/17/1": 400}, timestamp=1)
        post = Snapshot(data={"eth1/17/1": 200}, timestamp=2)
        result = await self.hc.compare_snapshots(self.device, hc_types.BaseHealthCheckIn(), {}, pre, post)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("Speed Before Test: 400G and Speed After Test: 200G", result.message)

    async def test_link_down_is_a_speed_change_not_a_missing_port(self):
        pre = Snapshot(data={"eth1/17/5": 400}, timestamp=1)
        post = Snapshot(data={"eth1/17/5": 0}, timestamp=2)
        result = await self.hc.compare_snapshots(self.device, hc_types.BaseHealthCheckIn(), {}, pre, post)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("Speed Before Test: 400G and Speed After Test: 0G", result.message)

    async def test_a_port_down_at_both_ends_is_unchanged(self):
        """Start-vs-end only: liveness is create_port_state_check's job."""
        pre = Snapshot(data={"eth1/17/5": 0}, timestamp=1)
        post = Snapshot(data={"eth1/17/5": 0}, timestamp=2)
        result = await self.hc.compare_snapshots(self.device, hc_types.BaseHealthCheckIn(), {}, pre, post)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""A disabled_interfaces entry that names only one end also covers the far end."""

import unittest
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

from taac.constants import TestDevice
from taac.health_checks.device_health_checks import port_state_health_check
from taac.health_checks.device_health_checks.lldp_health_check import LldpHealthCheck
from taac.health_checks.device_health_checks.port_state_health_check import (
    PortStateHealthCheck,
)
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types

# dut2's eth1/2/1 is cabled to dut1's eth1/1/1; eth1/2/2 to dut1's eth1/1/2.
DUT2_INTERFACES = [
    taac_types.TestInterface(
        interface_name=f"eth1/2/{n}",
        switch_name="dut2",
        neighbor_switch_name="dut1",
        neighbor_interface_name=f"eth1/1/{n}",
    )
    for n in (1, 2)
]
# Only dut1's end is named, as a caller that shut that port would write it.
DISABLED = [{"switch_name": "dut1", "interface_name": "eth1/1/1"}]


def _dut2() -> MagicMock:
    device = MagicMock(spec=TestDevice)
    device.name = "dut2"
    device.interfaces = DUT2_INTERFACES
    return device


class TestOneEndedDisabledLinks(unittest.IsolatedAsyncioTestCase):
    async def _port_state(self, oper_state):
        check = PortStateHealthCheck(logger=MagicMock())
        check.driver = AsyncMock()
        check.driver.async_get_all_interfaces_operational_status.return_value = (
            oper_state
        )
        with mock.patch.object(
            port_state_health_check,
            "async_everpaste_str",
            AsyncMock(return_value="paste"),
        ):
            return await check._run(
                _dut2(),
                hc_types.BaseHealthCheckIn(),
                {"disabled_interfaces": DISABLED},
            )

    async def test_port_state_expects_the_far_end_down(self):
        result = await self._port_state({"eth1/2/1": False, "eth1/2/2": True})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_port_state_fails_when_the_far_end_is_up(self):
        result = await self._port_state({"eth1/2/1": True, "eth1/2/2": True})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("dut2:eth1/2/1 is expected to be DOWN", result.message)

    def test_lldp_skips_the_far_end(self):
        check = LldpHealthCheck(logger=MagicMock())
        enabled, _ = check._get_enabled_and_disabled_interfaces(
            _dut2(), {"disabled_interfaces": DISABLED}
        )
        self.assertEqual([i.interface_name for i in enabled], ["eth1/2/2"])

# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""The LLDP check's built-in retry must outlast a late first LLDP frame.

A port's first LLDP frame can arrive several seconds after link-up. Bare
create_lldp_check() calls have no outer retry, so the built-in retry of
async_validate_lldp_neighbors is the whole window.
"""

import unittest
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

from taac.driver.driver_constants import SwitchLldpData
from taac.health_checks.device_health_checks import lldp_health_check as lldp
from taac.test_as_a_config import types as taac_types
from taac.utils import oss_taac_lib_utils

INTF = taac_types.TestInterface(
    interface_name="eth1/1/1",
    switch_name="dut1",
    neighbor_switch_name="dut2",
    neighbor_interface_name="eth1/2/1",
    neighbor_display_name="dut2:eth1/2/1",
)


class TestLldpPacedRetryWindow(unittest.IsolatedAsyncioTestCase):
    async def _validate(self, neighbors_at):
        """Run the check on a fake clock; neighbors_at(clock) is the LLDP table read at clock[0]."""
        clock = [0.0]

        async def fake_sleep(seconds):
            clock[0] += seconds

        check = lldp.LldpHealthCheck(logger=MagicMock())
        check.driver = AsyncMock()
        check.driver.async_get_lldp_neighbors.side_effect = lambda: neighbors_at(clock)
        self.driver = check.driver
        # These patch the global asyncio.sleep and time.time. That's safe here
        # because the event loop uses time.monotonic and nothing else in this
        # block awaits asyncio.sleep.
        with mock.patch.object(oss_taac_lib_utils.asyncio, "sleep", fake_sleep), mock.patch.object(
            oss_taac_lib_utils.time, "time", lambda: clock[0]
        ), mock.patch.object(
            lldp, "async_everpaste_str", AsyncMock(return_value="paste")
        ), mock.patch.object(lldp, "to_fb_fqdn", lambda name: name):
            try:
                await check.async_validate_lldp_neighbors([INTF], [])
            finally:
                self.elapsed = clock[0]

    async def test_retry_window_is_15_to_24_seconds(self):
        with self.assertRaisesRegex(Exception, "expected to be UP"):
            await self._validate(lambda clock: {})
        self.assertGreaterEqual(self.elapsed, 15)
        self.assertLessEqual(self.elapsed, 24)

    async def test_first_frame_10_seconds_after_link_up_passes(self):
        neighbor = {"eth1/1/1": SwitchLldpData(remote_device_name="dut2", remote_intf_name="eth1/2/1")}
        await self._validate(lambda clock: neighbor if clock[0] >= 10 else {})
        # Reads at t=0, 2, ..., 10: the check waited out the 10 s gap.
        self.assertEqual(self.driver.async_get_lldp_neighbors.call_count, 6)

    async def test_slow_failing_reads_stop_retrying_after_24_seconds(self):
        """A dead agent makes each read fail slowly; retries stop after 24 s: 2 tries, not 9."""

        def slow_failure(clock):
            clock[0] += 15
            raise ConnectionError("agent down")

        with self.assertRaises(ConnectionError):
            await self._validate(slow_failure)
        self.assertEqual(self.driver.async_get_lldp_neighbors.call_count, 2)
        self.assertEqual(self.elapsed, 32)

# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""The loss check waits out its sample window without blocking the event loop."""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_check.health_check import types as hc_types
from taac.health_checks.ixia_health_checks import ixia_packet_loss_health_check as module


class TestLossWaitNonBlocking(unittest.IsolatedAsyncioTestCase):
    async def run_check(self, clear_traffic_stats):
        now = [0.0]
        events = []

        async def async_advance(seconds):
            now[0] += seconds

        def no_blocking_sleep(seconds):
            raise AssertionError("time.sleep(%s) inside an async check" % seconds)

        traffic = MagicMock()
        traffic.get_traffic_items.return_value = ["traffic"]
        traffic.get_traffic_start_time.return_value = 0
        traffic.clear_traffic_stats.side_effect = lambda: events.append(("clear", now[0]))
        traffic.stop_traffic.side_effect = lambda: events.append(("stop", now[0]))
        traffic.get_latest_stats.return_value = [
            {"identifier": "traffic", "packet_loss_duration": 0,
             "packet_loss_percentage": 0, "frame_delta": 0}
        ]
        check = module.IxiaPacketLossHealthCheck(logger=MagicMock())
        # Module-local stand-ins, so the test loop's own clock and sleep are untouched.
        clock = SimpleNamespace(time=lambda: now[0], sleep=no_blocking_sleep)
        with patch.object(module, "time", clock), \
             patch.object(module, "asyncio", SimpleNamespace(sleep=async_advance)), \
             patch.object(module, "async_everpaste_str", new=AsyncMock(return_value="details")):
            result = await check._run(
                traffic,
                hc_types.IxiaPacketLossHealthCheckIn(
                    thresholds=[hc_types.PacketLossThreshold(str_value="0")],
                    clear_traffic_stats=clear_traffic_stats, sleep_time=2,
                ),
                {"skip_clear_stats_at_end": True},
            )
        return result, events

    async def test_sample_window_is_awaited_after_a_clear(self):
        result, events = await self.run_check(clear_traffic_stats=True)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertEqual(events[0], ("clear", 0))
        self.assertEqual(events[1][0], "stop")
        self.assertGreaterEqual(events[1][1], 2)

    async def test_sample_window_is_awaited_without_a_clear(self):
        result, events = await self.run_check(clear_traffic_stats=False)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertEqual(events[0][0], "stop")
        self.assertGreaterEqual(events[0][1], 2)

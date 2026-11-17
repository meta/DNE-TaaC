# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Recovery time must precede the measured forwarding window."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_check.health_check import types as hc_types
from taac.health_checks.ixia_health_checks import ixia_packet_loss_health_check as module


class TestRecoveryWindow(unittest.IsolatedAsyncioTestCase):
    async def run_window(self, recovery_end, params, clear_traffic_stats=True):
        now = [0.0]
        events = []
        window = [0.0, None]

        def advance(seconds):
            now[0] += seconds

        async def async_advance(seconds):
            advance(seconds)

        def clear():
            events.append(("clear", now[0]))
            window[0] = now[0]

        def stop():
            events.append(("stop", now[0]))
            window[1] = now[0]

        def stats(**kwargs):
            loss = max(0, min(recovery_end, window[1]) - window[0]) * 1000
            return [{"identifier": "traffic", "packet_loss_duration": loss,
                     "packet_loss_percentage": 0, "frame_delta": 0}]

        traffic = MagicMock()
        traffic.get_traffic_items.return_value = ["traffic"]
        traffic.get_traffic_start_time.return_value = 0
        traffic.clear_traffic_stats.side_effect = clear
        traffic.stop_traffic.side_effect = stop
        traffic.get_latest_stats.side_effect = stats
        self.logger = MagicMock()
        check = module.IxiaPacketLossHealthCheck(logger=self.logger)
        # time.sleep must never be called: this coroutine shares the loop with
        # the periodic collectors, so a blocking wait stalls their sampling.
        def no_blocking_sleep(seconds):
            raise AssertionError("time.sleep(%s) inside an async check" % seconds)

        with patch.object(module.time, "time", side_effect=lambda: now[0]), \
             patch.object(module.time, "sleep", side_effect=no_blocking_sleep), \
             patch.object(module.asyncio, "sleep", side_effect=async_advance), \
             patch.object(module, "async_everpaste_str", new=AsyncMock(return_value="details")):
            result = await check._run(
                traffic,
                hc_types.IxiaPacketLossHealthCheckIn(
                    thresholds=[hc_types.PacketLossThreshold(str_value="0")],
                    clear_traffic_stats=clear_traffic_stats, sleep_time=2,
                ),
                dict(params, skip_clear_stats_at_end=True),
            )
        return result, events

    async def test_recovery_loss_excluded_before_clear_and_live_sample(self):
        result, events = await self.run_window(5, {"settle_time_seconds": 5})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertEqual(events[0], ("clear", 5))
        self.assertEqual(events[1][0], "stop")
        self.assertGreaterEqual(events[1][1], 7)

    async def test_loss_after_recovery_still_fails(self):
        result, events = await self.run_window(20, {"settle_time_seconds": 5})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertEqual(events[0], ("clear", 5))

    async def test_default_has_no_recovery_allowance(self):
        result, events = await self.run_window(5, {})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertEqual(events[0], ("clear", 0))

    async def test_a_settle_without_a_clear_is_flagged(self):
        """Without clear_traffic_stats the settle only delays the check: the
        losses it was meant to absorb stay inside the measured window."""
        await self.run_window(5, {"settle_time_seconds": 5}, clear_traffic_stats=False)
        warnings = " ".join(
            str(call) for call in self.logger.warning.call_args_list
        )
        self.assertIn("settle_time_seconds", warnings)
        self.assertIn("clear_traffic_stats", warnings)

    async def test_a_settle_with_a_clear_is_not_flagged(self):
        await self.run_window(5, {"settle_time_seconds": 5})
        warnings = " ".join(
            str(call) for call in self.logger.warning.call_args_list
        )
        self.assertNotIn("settle_time_seconds", warnings)

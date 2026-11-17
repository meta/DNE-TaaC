# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""require_frames_items: a loss threshold alone passes on an item that sent nothing."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_check.health_check import types as hc_types
from taac.health_checks.ixia_health_checks import ixia_packet_loss_health_check as module
from taac.ixia.taac_ixia import TaacIxia


def _stat(name, tx, rx):
    return {"identifier": name, "packet_loss_duration": 0, "packet_loss_percentage": 0,
            "frame_delta": 0, "tx_frames": tx, "rx_frames": rx}


class TestFramesFlowed(unittest.IsolatedAsyncioTestCase):
    async def run_check(self, stats, params):
        traffic = MagicMock()
        traffic.get_traffic_items.return_value = ["A", "XF"]
        traffic.get_traffic_start_time.return_value = 0
        traffic.get_latest_stats.return_value = stats
        check = module.IxiaPacketLossHealthCheck(logger=MagicMock())
        with patch.object(module.time, "time", return_value=10.0), \
             patch.object(module.asyncio, "sleep", new=AsyncMock()), \
             patch.object(module, "async_everpaste_str", new=AsyncMock(return_value="details")):
            return await check._run(
                traffic,
                hc_types.IxiaPacketLossHealthCheckIn(
                    thresholds=[hc_types.PacketLossThreshold(str_value="0")], sleep_time=1
                ),
                dict(params, skip_clear_stats_at_end=True),
            )

    async def test_zero_frames_fails_even_with_zero_loss(self):
        result = await self.run_check([_stat("A", 5, 5), _stat("XF", 0, 0)],
                                      {"require_frames_items": ["XF"]})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("no traffic flowed", result.message)

    async def test_frames_sent_and_received_passes(self):
        result = await self.run_check([_stat("A", 5, 5), _stat("XF", 100, 100)],
                                      {"require_frames_items": ["XF"]})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_missing_frame_counts_fail_closed(self):
        stat = _stat("XF", 100, 100)
        del stat["tx_frames"]
        result = await self.run_check([_stat("A", 5, 5), stat], {"require_frames_items": ["XF"]})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_missing_row_fails(self):
        result = await self.run_check([_stat("A", 5, 5)], {"require_frames_items": ["XF"]})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("missing=XF", result.message)

    async def test_skipped_item_is_not_required(self):
        result = await self.run_check([_stat("A", 5, 5), _stat("XF", 0, 0)],
                                      {"require_frames_items": ["XF"], "skip_traffic_items": ["XF"]})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_default_does_not_require_frames(self):
        result = await self.run_check([_stat("A", 0, 0)], {})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)


class TestPacketLossStatCarriesFrames(unittest.TestCase):
    def test_tx_rx_frames_are_read(self):
        cols = {"Traffic Item": "XF", "Loss %": "0", "Tx Frames": "1234", "Rx Frames": "1230"}
        row = MagicMock()
        row.Columns = list(cols)
        row.__getitem__.side_effect = cols.__getitem__
        stat = TaacIxia._packet_loss_stat("Traffic Item Statistics", row)
        self.assertEqual((stat["tx_frames"], stat["rx_frames"]), (1234.0, 1230.0))


if __name__ == "__main__":
    unittest.main()

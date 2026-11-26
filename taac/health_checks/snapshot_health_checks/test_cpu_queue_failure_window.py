# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""OSS-runnable coverage for the CPU queue check's failure evidence and its
pre-snapshot baseline.

``test_cpu_queue_health_check.py`` cannot run in the OSS image (it imports
``neteng.netcastle``), so the assertions that a failure carries the window it
measured, and that the window starts from reported counters, live here, where
``run_tests.sh`` actually executes them.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_checks.constants import Snapshot
from taac.health_checks.snapshot_health_checks.cpu_queue_health_check import (
    CpuQueueHealthCheck,
)
from taac.health_check.health_check import types as hc_types

_HC_MODULE = "neteng.test_infra.dne.taac.health_checks.snapshot_health_checks.cpu_queue_health_check"

# A CPU port's configured queues, as getCpuPortStats names them.
_QUEUE_NAMES = {
    0: "cpuQueue-low",
    1: "cpuQueue-default",
    2: "cpuQueue-mid",
    9: "cpuQueue-high",
}


def _cpu_port_stats(
    out_packets: dict, discards: dict | None = None, names: dict | None = None
) -> MagicMock:
    data = MagicMock()
    data.queueToName_ = dict(names or {})
    data.portStats_.queueOutPackets_ = dict(out_packets)
    data.portStats_.queueOutDiscardPackets_ = dict(discards or {})
    return data


def _snapshot(
    out_packets: dict, discards: dict, timestamp: int, names: dict | None = None
) -> Snapshot:
    return Snapshot(
        data=_cpu_port_stats(out_packets, discards, names), timestamp=timestamp
    )


class TestCpuQueueFailureWindow(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.check = CpuQueueHealthCheck(
            obj=MagicMock(),
            input=hc_types.CpuQueueHealthCheckIn(active_queues=[]),
            pre_snapshot_checkpoint_id="pre",
            post_snapshot_checkpoint_id="post",
            check_params={},
            logger=MagicMock(),
        )
        self.check.driver = AsyncMock()
        # The failure path uploads its full reason list; keep it off the network.
        patcher = patch(
            f"{_HC_MODULE}.async_everpaste_str", new=AsyncMock(return_value="stub_url")
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    async def _compare(self, input_, pre_out, post_out, pre_disc, post_disc):
        return await self.check.compare_snapshots(
            MagicMock(),
            input_,
            {},
            _snapshot(pre_out, pre_disc, timestamp=1000),
            _snapshot(post_out, post_disc, timestamp=1060),
        )

    async def _capture_pre(self, input_, *reads, clock_time=1000):
        """Capture a pre-snapshot at checkpoint 1000, read at ``clock_time``."""
        self.check.driver.async_get_cpu_port_stats.side_effect = list(reads)
        # The pre-snapshot waits between reads of unreported counters. This is
        # the process-wide asyncio.sleep, so the patch covers only this call.
        with (
            patch(f"{_HC_MODULE}.time") as clock,
            patch(f"{_HC_MODULE}.asyncio.sleep", new=AsyncMock()) as sleep,
        ):
            clock.time.return_value = clock_time
            pre = await self.check.capture_pre_snapshot(MagicMock(), input_, {}, 1000)
        self.sleep = sleep
        return pre

    async def _compare_to_post(self, input_, pre, post_out):
        post = _snapshot(post_out, {}, timestamp=1046, names=_QUEUE_NAMES)
        return await self.check.compare_snapshots(MagicMock(), input_, {}, pre, post)

    async def test_active_queue_failures_carry_their_own_counters(self):
        """A failure has to carry the window it measured.

        A flat out_packets with climbing discards is a policer eating the
        punts; flat with flat discards is a punt that never happened; a
        counter that went backwards is an agent restart inside the window.
        All three read as "no increase", and nothing in the message tells
        them apart unless the numbers are in it.
        """
        policed = await self._compare(
            hc_types.CpuQueueHealthCheckIn(
                active_queues=[0], active_min_out_pps_per_queue={0: 10}
            ),
            pre_out={0: 38166},
            post_out={0: 38166},
            pre_disc={0: 1000000},
            post_disc={0: 6665827},
        )
        self.assertEqual(policed.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("out_packets 38166 -> 38166 in 60s", policed.message)
        self.assertIn("discards 1000000 -> 6665827", policed.message)

        below_threshold = await self._compare(
            hc_types.CpuQueueHealthCheckIn(
                active_queues=[0], active_min_out_pps_per_queue={0: 100}
            ),
            pre_out={0: 0},
            post_out={0: 600},  # 10 pps, below the 100 pps floor
            pre_disc={0: 0},
            post_disc={0: 42},
        )
        self.assertEqual(below_threshold.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("out_packets 0 -> 600 in 60s", below_threshold.message)
        self.assertIn("discards 0 -> 42", below_threshold.message)

    async def test_counters_reported_after_a_restart_are_the_baseline(self):
        """Lifetime totals that appear after a restart are not new traffic.

        Right after an agent restart getCpuPortStats reports no queue yet, then
        only some of them. Taken as sparse zeros, the inactive queues' lifetime
        totals would read as a high packet rate over the window and fail the
        inactive-queue check.
        """
        input_ = hc_types.CpuQueueHealthCheckIn(
            active_queues=[0], inactive_queues=[2, 9]
        )
        pre = await self._capture_pre(
            input_,
            _cpu_port_stats({}, names=_QUEUE_NAMES),
            _cpu_port_stats({0: 100}, names=_QUEUE_NAMES),
            _cpu_port_stats(
                {0: 100, 1: 0, 2: 9000000, 9: 3000000}, names=_QUEUE_NAMES
            ),
        )
        self.assertEqual(pre.data.portStats_.queueOutPackets_[2], 9000000)
        result = await self._compare_to_post(
            input_, pre, {0: 9000, 1: 0, 2: 9000200, 9: 3000050}
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_complete_counters_with_an_idle_queue_are_read_once(self):
        """A queue that never carried a packet is reported as 0, not left out,
        so a complete read is taken as is and costs the check no time.
        """
        pre = await self._capture_pre(
            hc_types.CpuQueueHealthCheckIn(active_queues=[0], inactive_queues=[2, 9]),
            _cpu_port_stats(
                {0: 100, 1: 0, 2: 25000, 9: 80000}, names=_QUEUE_NAMES
            ),
        )
        self.assertEqual(pre.timestamp, 1000)
        self.check.driver.async_get_cpu_port_stats.assert_awaited_once()

    async def test_snapshots_are_stamped_at_the_read(self):
        """Both snapshots carry the time of their read, not the checkpoint's."""
        input_ = hc_types.CpuQueueHealthCheckIn(active_queues=[0])
        complete = {0: 100, 1: 0, 2: 0, 9: 0}
        pre = await self._capture_pre(
            input_, _cpu_port_stats(complete, names=_QUEUE_NAMES), clock_time=1037
        )
        self.assertEqual(pre.timestamp, 1037)

        self.check.driver.async_get_cpu_port_stats.side_effect = [
            _cpu_port_stats(complete, names=_QUEUE_NAMES)
        ]
        with patch(f"{_HC_MODULE}.time") as clock:
            clock.time.return_value = 1037
            post = await self.check.capture_post_snapshot(
                MagicMock(), input_, {}, 1000
            )
        self.assertEqual(post.timestamp, 1037)

    async def test_unreported_queue_falls_back_to_a_sparse_zero(self):
        """A queue that never shows up is scored from a zero baseline.

        After the settle timeout the check stops waiting, and traffic that
        reaches the missing queue still fails it rather than being hidden.
        """
        input_ = hc_types.CpuQueueHealthCheckIn(
            active_queues=[0], inactive_queues=[2, 9]
        )
        reads = [
            _cpu_port_stats({0: 100, 1: 0, 9: 50}, names=_QUEUE_NAMES)
            for _ in range(16)
        ]
        pre = await self._capture_pre(input_, *reads)
        self.assertEqual(self.sleep.await_count, 15)
        result = await self._compare_to_post(
            input_, pre, {0: 9000, 1: 0, 2: 500000, 9: 50}
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("inactive queue 2", result.message)

    async def test_without_queue_names_any_reported_counter_is_the_baseline(self):
        """With no configured queue names to wait for, a non-empty read is
        complete; the check must not stall for the whole settle timeout.
        """
        pre = await self._capture_pre(
            hc_types.CpuQueueHealthCheckIn(active_queues=[0]),
            _cpu_port_stats({0: 100}),
        )
        self.assertEqual(pre.timestamp, 1000)
        self.check.driver.async_get_cpu_port_stats.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()

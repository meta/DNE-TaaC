# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""The BGP peer route pre-snapshot waits for the BGP summary to stop changing."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.health_checks.snapshot_health_checks.bgp_peers_health_check import (
    _PRE_SNAPSHOT_SETTLE_INTERVAL_SECONDS,
    _PRE_SNAPSHOT_SETTLE_TIMEOUT_SECONDS,
    BgpPeerData,
    BgpPeersHealthCheck,
    BgpSummaryData,
)
from taac.health_check.health_check import types as hc_types

# ShipIt rewrites imports but not string literals; derive the patch target.
_HC_MODULE = BgpPeersHealthCheck.__module__


def _summary(sent_per_peer: int, peers: int = 2) -> BgpSummaryData:
    peer_data = {
        f"2001:db8::{i}": BgpPeerData(prefixes_sent=sent_per_peer, prefixes_received=5)
        for i in range(peers)
    }
    return BgpSummaryData(
        total_paths_received=5 * peers,
        total_paths_sent=sent_per_peer * peers,
        peer_data=peer_data,
    )


class _Clock:
    """Stands in for the module's ``time``: advances only when told to."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


def _check() -> BgpPeersHealthCheck:
    return BgpPeersHealthCheck(
        obj=MagicMock(),
        input=hc_types.BaseHealthCheckIn(),
        pre_snapshot_checkpoint_id="pre",
        post_snapshot_checkpoint_id="post",
        check_params={},
        logger=MagicMock(),
    )


class TestBgpPeersPreSnapshotSettle(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.check = _check()
        self.clock = _Clock()

    async def _capture_pre(self, check_params, *reads, read_s: float = 0.0):
        """Capture with ``reads`` as successive summary reads.

        A read that is an exception raises instead; each read takes ``read_s`` on
        the fake clock, and each settle sleep advances it by the slept interval.
        """
        pending = list(reads)

        async def read(*args, **kwargs):
            self.clock.now += read_s
            result = pending.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        async def sleep(seconds):
            self.clock.now += seconds

        self.check.get_bgp_summary_data = AsyncMock(side_effect=read)
        # Patch the module's names only: asyncio.sleep and time are process-wide.
        with patch(
            f"{_HC_MODULE}.asyncio.sleep", new=AsyncMock(side_effect=sleep)
        ) as sleep_mock, patch(f"{_HC_MODULE}.time", new=self.clock):
            pre = await self.check.capture_pre_snapshot(
                MagicMock(), MagicMock(), check_params, 1000
            )
        self.sleep = sleep_mock
        self.unread = pending
        return pre

    async def test_waits_until_advertisement_finishes(self):
        """Partial sent counts right after peers come up are not the baseline."""
        pre = await self._capture_pre(
            {}, _summary(1), _summary(500), _summary(900), _summary(900)
        )
        self.assertEqual(pre.data, _summary(900))
        self.assertEqual(self.check.get_bgp_summary_data.await_count, 4)
        self.assertEqual(self.sleep.await_count, 3)
        self.sleep.assert_awaited_with(_PRE_SNAPSHOT_SETTLE_INTERVAL_SECONDS)

    async def test_gives_up_after_timeout_with_last_read(self):
        reads = (
            _PRE_SNAPSHOT_SETTLE_TIMEOUT_SECONDS
            // _PRE_SNAPSHOT_SETTLE_INTERVAL_SECONDS
        )
        pre = await self._capture_pre({}, *[_summary(n) for n in range(reads + 1)])
        self.assertEqual(pre.data, _summary(reads))
        self.assertEqual(self.sleep.await_count, reads)
        self.check.logger.warning.assert_called_once()

    async def test_read_time_counts_toward_the_timeout(self):
        """Slow reads (RIB dumps with ignore lists) do not stretch the wait."""
        pre = await self._capture_pre(
            {"pre_snapshot_settle_timeout_s": 60},
            *[_summary(n) for n in range(10)],
            read_s=20,
        )
        # Reads end at 20, 50 and 80; the deadline is 60, so the third is the last.
        self.assertEqual(pre.data, _summary(2))
        self.assertEqual(self.check.get_bgp_summary_data.await_count, 3)
        self.assertEqual(self.sleep.await_count, 2)
        warning = self.check.logger.warning.call_args.args[0]
        self.assertIn("within 80s", warning)

    async def test_failed_re_read_keeps_waiting_without_restarting(self):
        """A re-read that raises is "not settled"; it never reaches the retry wrapper."""
        pre = await self._capture_pre(
            {},
            _summary(900),
            TimeoutError("thrift read timed out"),
            _summary(900),
        )
        self.assertEqual(pre.data, _summary(900))
        self.assertEqual(self.check.get_bgp_summary_data.await_count, 3)
        self.assertEqual(self.check.logger.warning.call_count, 1)

    async def test_no_successful_read_takes_one_more_read(self):
        pre = await self._capture_pre(
            {"pre_snapshot_settle_timeout_s": 10},
            TimeoutError("thrift read timed out"),
            TimeoutError("thrift read timed out"),
            _summary(1),
        )
        self.assertEqual(pre.data, _summary(1))
        self.assertEqual(self.unread, [])

    async def test_interval_is_configurable(self):
        await self._capture_pre(
            {"pre_snapshot_settle_interval_s": 3}, _summary(1), _summary(1)
        )
        self.sleep.assert_awaited_once_with(3)

    async def test_zero_timeout_takes_a_single_read(self):
        pre = await self._capture_pre({"pre_snapshot_settle_timeout_s": 0}, _summary(1))
        self.assertEqual(pre.data, _summary(1))
        self.sleep.assert_not_awaited()

    async def test_peer_level_change_is_not_settled(self):
        """Equal totals can hide counts moving between peers."""
        shifted = _summary(900)._replace(
            peer_data={
                "2001:db8::0": BgpPeerData(prefixes_sent=800, prefixes_received=5),
                "2001:db8::1": BgpPeerData(prefixes_sent=1000, prefixes_received=5),
            }
        )
        pre = await self._capture_pre({}, shifted, _summary(900), _summary(900))
        self.assertEqual(pre.data, _summary(900))
        self.assertEqual(self.check.get_bgp_summary_data.await_count, 3)


if __name__ == "__main__":
    unittest.main()

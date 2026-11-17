# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""WaitForBgpFibSyncTask returns only on a loaded, consistent, settled FIB."""

import itertools
import json
import unittest
from unittest import mock

from taac.task_definitions import create_wait_for_bgp_fib_sync_task
from taac.tasks import wait_for_bgp_fib_sync_task as mod
from taac.tasks.registry import TASK_NAME_TO_CLASS


def _poll(rib, fib_bgp=None, nh=None, miss_fib=0, miss_rib=0, rib_all=None, fib_all=None):
    fib_bgp = rib if fib_bgp is None else fib_bgp
    rib_all = rib if rib_all is None else rib_all
    return mod._Poll(
        rib_all,
        rib_all if fib_all is None else fib_all,
        rib,
        fib_bgp,
        fib_bgp * 2 if nh is None else nh,
        miss_fib,
        miss_rib,
    )


class TestWaitForBgpFibSync(unittest.IsolatedAsyncioTestCase):
    async def _run(self, polls, **params):
        polls = iter(polls)

        async def fake_poll(_driver, _ignore=()):
            item = next(polls)
            if isinstance(item, Exception):
                raise item
            return item

        task = mod.WaitForBgpFibSyncTask(logger=mock.MagicMock())
        with mock.patch.object(
            mod, "async_get_device_driver", mock.AsyncMock()
        ), mock.patch.object(mod, "async_poll_bgp_fib_sync", fake_poll), mock.patch.object(
            mod.asyncio, "sleep", mock.AsyncMock()
        ):
            await task.run({"hostnames": "dut", "interval": 0, **params})
        return polls

    async def test_waits_out_programming_then_settles(self):
        rest = await self._run(
            [
                _poll(1000),  # baseline: consistent but under the floor
                _poll(80000, fib_bgp=20000, miss_fib=60000),  # FIB filling
                _poll(80000, nh=100),  # consistent, ECMP still widening
                _poll(80000, nh=140),
                _poll(80000, nh=140),
                _poll(80000, nh=140),
                _poll(1),  # never read
            ],
            min_rib_prefixes=70000,
            stable_polls=3,
            timeout=3600,
        )
        self.assertEqual(next(rest), _poll(1))

    async def test_floor_counts_ignored_prefixes(self):
        # One whole pool sits under an ignored parent prefix.
        loaded = _poll(50000, rib_all=80000)
        rest = await self._run(
            [loaded, loaded, loaded, _poll(1)],
            min_rib_prefixes=70000,
            stable_polls=3,
            timeout=3600,
        )
        self.assertEqual(next(rest), _poll(1))

    async def test_fib_missing_an_ignored_pool_holds_the_task(self):
        rest = await self._run(
            [
                _poll(50000, rib_all=80000, fib_all=50500),
                _poll(50000, rib_all=80000, fib_all=50500),
                _poll(50000, rib_all=80000, fib_all=50500),
                _poll(50000, rib_all=80000, fib_all=80500),
                _poll(50000, rib_all=80000, fib_all=80500),
                _poll(50000, rib_all=80000, fib_all=80500),
                _poll(1),
            ],
            min_rib_prefixes=70000,
            stable_polls=3,
            timeout=3600,
        )
        self.assertEqual(next(rest), _poll(1))

    async def test_churning_ignored_pool_does_not_hold_the_task(self):
        # A pool under an ignored prefix is re-advertised periodically,
        # moving the unfiltered counts between polls.
        rest = await self._run(
            [
                _poll(50000, rib_all=80000, fib_all=80500),
                _poll(50000, rib_all=79000, fib_all=79500),
                _poll(50000, rib_all=79500, fib_all=80000),
                _poll(1),
            ],
            min_rib_prefixes=70000,
            stable_polls=3,
            timeout=3600,
        )
        self.assertEqual(next(rest), _poll(1))

    async def test_read_error_resets_the_streak(self):
        rest = await self._run(
            [
                _poll(80000),
                _poll(80000),
                RuntimeError("thrift timeout"),
                _poll(80000),
                _poll(80000),
                _poll(80000),
                _poll(1),
            ],
            min_rib_prefixes=70000,
            stable_polls=3,
            timeout=3600,
        )
        self.assertEqual(next(rest), _poll(1))

    async def test_times_out_naming_the_last_poll(self):
        with mock.patch.object(mod.time, "monotonic", side_effect=itertools.count(0, 100)):
            with self.assertRaisesRegex(TimeoutError, "missing_in_fib=5"):
                await self._run(
                    [_poll(80000, miss_fib=5)] * 5,
                    min_rib_prefixes=1,
                    timeout=10,
                )

    def test_factory_runs_post_ixia_and_is_registered(self):
        task = create_wait_for_bgp_fib_sync_task("dut", min_rib_prefixes=5)
        self.assertTrue(task.ixia_needed)
        self.assertIs(TASK_NAME_TO_CLASS[task.task_name], mod.WaitForBgpFibSyncTask)
        self.assertEqual(json.loads(task.params.json_params)["hostnames"], ["dut"])


class TestPollBgpFibSync(unittest.IsolatedAsyncioTestCase):
    async def test_counts_bgp_routes_and_their_next_hops(self):
        def rib_entry(addr):
            e = mock.MagicMock()
            e.prefix.prefix_bin = addr
            e.prefix.num_bits = 128
            e.best_path.next_hop.prefix_bin = b"\x20" + b"\x00" * 15
            return e

        def fib_route(addr, client, nhops):
            r = mock.MagicMock()
            r.dest.ip.addr = addr
            r.dest.prefixLength = 128
            r.nextHopMulti = [mock.MagicMock(clientId=client)]
            r.nextHops = [object()] * nhops
            return r

        a, b, c = (bytes([0x20, 0x01] + [0] * 13 + [i]) for i in (1, 2, 3))
        bgpd = int(mod.fib_bgp_prefixes.__globals__["_BGPD"])
        driver = mock.MagicMock()
        driver.async_get_bgp_rib_entries = mock.AsyncMock(return_value=[rib_entry(a), rib_entry(b)])
        driver.async_get_route_table_details = mock.AsyncMock(
            return_value=[fib_route(a, bgpd, 8), fib_route(c, bgpd + 1, 1)]
        )
        driver.async_get_bgp_originated_routes = mock.AsyncMock(return_value=[])
        poll = await mod.async_poll_bgp_fib_sync(driver)
        self.assertEqual(
            poll,
            mod._Poll(rib_all=2, fib_all=2, rib=2, fib_bgp=1, fib_bgp_next_hops=8, missing_in_fib=1, missing_in_rib=0),
        )
        self.assertFalse(mod.is_synced(poll, 1))
        # Ignoring the unprogrammed prefix clears the drift but not the floor count.
        poll = await mod.async_poll_bgp_fib_sync(driver, ["2001::2/128"])
        self.assertEqual((poll.rib_all, poll.rib, poll.missing_in_fib), (2, 1, 0))
        self.assertTrue(mod.is_synced(poll, 2))


if __name__ == "__main__":
    unittest.main()

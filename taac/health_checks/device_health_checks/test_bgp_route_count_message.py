# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""BGP_ROUTE_COUNT_VERIFICATION_CHECK result messages carry the counts.

test_bgp_route_count_verification_health_check.py imports neteng.netcastle and
so never runs under OSS; these cases live here.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from neteng.fboss.bgp_thrift.types import TBgpPeerState
from taac.constants import TestDevice
from taac.health_checks.device_health_checks import (
    bgp_route_count_verification_health_check as route_count_module,
)
from taac.health_checks.device_health_checks.bgp_route_count_verification_health_check import (
    BgpRouteCountVerificationHealthCheck,
)
from taac.health_check.health_check import types as hc_types


def _session(peer_addr):
    session = MagicMock()
    session.peer_addr = peer_addr
    session.description = ""
    session.peer.peer_state = TBgpPeerState.ESTABLISHED
    return session


class _RouteCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.check = BgpRouteCountVerificationHealthCheck(logger=MagicMock())
        self.check.driver = AsyncMock()
        self.device = MagicMock(spec=TestDevice)
        self.device.name = "dut1"

    async def _run(self, routes_by_peer, params):
        self.check.driver.async_get_bgp_sessions = AsyncMock(
            return_value=[_session(p) for p in routes_by_peer]
        )
        self.check.driver.async_get_postfilter_received_networks = AsyncMock(
            side_effect=lambda peer: [object()] * routes_by_peer[peer]
        )
        return await self.check._run(
            self.device,
            hc_types.BaseHealthCheckIn(),
            {"policy_type": "post_policy", **params},
        )


class TestRouteCountMessage(_RouteCase):
    async def test_pass_message_carries_per_peer_and_total_counts(self):
        result = await self._run({"2001:db8::11": 4500, "2001:db8::13": 0}, {})

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("2 peers, 4500 routes", result.message)
        self.assertIn("2001:db8::11=4500", result.message)
        self.assertIn("2001:db8::13=0", result.message)

    async def test_pass_against_a_minimum_still_reports_the_counts(self):
        result = await self._run(
            {"2001:db8::11": 5000, "2001:db8::13": 5001}, {"min_count": 5000}
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("min=5000", result.message)
        self.assertIn("2 peers, 10001 routes", result.message)

    async def test_fail_message_carries_the_counts(self):
        result = await self._run(
            {"2001:db8::11": 4500, "2001:db8::13": 0}, {"min_count": 1}
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("2 peers, 4500 routes", result.message)
        self.assertIn("2001:db8::13=0", result.message)

    async def test_selected_peers_only(self):
        result = await self._run(
            {"2001:db8::11": 4500, "2001:db8::13": 4500, "fd00::fab1": 5000},
            {"peer_addresses_to_check": ["2001:db8::11", "2001:db8::13"]},
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("2 peers, 9000 routes", result.message)
        self.assertNotIn("fd00::fab1", result.message)

    async def test_histogram_mismatch_fails_without_per_peer_counts(self):
        # The histogram path has no per-peer counts; the summary must not break it.
        self.check.driver.bgp = AsyncMock()
        with patch.object(
            route_count_module,
            "get_route_count_histogram_by_afi_for_peers",
            AsyncMock(return_value={"ipv6": {4500: 1}}),
        ):
            result = await self._run(
                {"2001:db8::11": 4500},
                {"expected_count_histogram_by_afi": {"ipv6": {5000: 1}}},
            )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("Expected route-count histogram", result.message)
        self.assertNotIn("per peer", result.message)

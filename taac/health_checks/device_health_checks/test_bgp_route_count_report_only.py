# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""BGP_ROUTE_COUNT_VERIFICATION_CHECK in report-only mode.

test_bgp_route_count_verification_health_check.py imports neteng.netcastle and
so never runs under OSS; these cases live here.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock

from neteng.fboss.bgp_thrift.types import TBgpPeerState
from taac.constants import TestDevice
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


class TestRouteCountReportOnly(_RouteCase):
    async def test_pass_message_carries_per_peer_and_total_counts(self):
        result = await self._run({"2001:db8::11": 4500, "2001:db8::13": 0}, {"min_total_count": 1})

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("2 peers, 4500 routes", result.message)
        self.assertIn("2001:db8::11=4500", result.message)
        self.assertIn("2001:db8::13=0", result.message)

    async def test_pass_against_a_minimum_still_reports_the_counts(self):
        # A fabric-scale gate passes on min_count; its PASS row is the
        # only post-health record of how many fabric routes came back.
        result = await self._run(
            {"2001:db8::11": 5000, "2001:db8::13": 5001}, {"min_count": 5000}
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("min=5000", result.message)
        self.assertIn("2 peers, 10001 routes", result.message)

    async def test_zero_routes_from_every_peer_fails(self):
        result = await self._run({"2001:db8::11": 0, "2001:db8::13": 0}, {"min_total_count": 1})

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("0 routes", result.message)

    async def test_no_established_peer_fails_the_floor(self):
        result = await self._run({}, {"min_total_count": 1})

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)


class TestRouteCountPeerAddresses(_RouteCase):
    """The floor counts only the named peers, so fabric routes cannot mask them."""

    IXIA = ["2001:db8::11", "2001:db8::13"]

    async def test_routes_from_other_peers_do_not_count(self):
        result = await self._run(
            {"2001:db8::11": 0, "2001:db8::13": 0, "fd00::fab1": 5000},
            {"min_total_count": 1, "peer_addresses": self.IXIA},
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("2 peers, 0 routes", result.message)
        self.assertNotIn("fd00::fab1", result.message)

    async def test_named_peers_with_routes_pass(self):
        result = await self._run(
            {"2001:db8::11": 4500, "2001:db8::13": 4500, "fd00::fab1": 5000},
            {"min_total_count": 1, "peer_addresses": self.IXIA},
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("2 peers, 9000 routes", result.message)

    async def test_no_named_peer_established_fails(self):
        result = await self._run(
            {"fd00::fab1": 5000}, {"min_total_count": 1, "peer_addresses": self.IXIA}
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

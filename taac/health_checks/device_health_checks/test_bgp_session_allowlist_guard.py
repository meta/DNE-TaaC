# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""BGP_SESSION_ESTABLISH_CHECK must not PASS when its allowlist matches nothing.

test_bgp_session_health_check.py imports neteng.netcastle and so never runs
under OSS; these cases live here so the guard is exercised in this repo.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock

from neteng.fboss.bgp_thrift.types import TBgpPeerState
from taac.constants import TestDevice
from taac.health_checks.device_health_checks.bgp_session_health_check import (
    BgpSessionEstablishedHealthCheck,
)
from taac.health_check.health_check import types as hc_types


def _session(peer_addr, state=TBgpPeerState.ESTABLISHED):
    session = MagicMock()
    session.peer_addr = peer_addr
    session.my_addr = "2001:db8::10"
    session.uptime = 1000
    session.peer.peer_state = state
    session.peer.remote_as = 65000
    return session


class _CheckCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.check = BgpSessionEstablishedHealthCheck(logger=MagicMock())
        self.check.driver = AsyncMock()
        self.device = MagicMock(spec=TestDevice)
        self.device.name = "dut1"

    async def _run(self, sessions, params):
        self.check.driver.async_get_bgp_sessions = AsyncMock(return_value=sessions)
        return await self.check._run(self.device, hc_types.BaseHealthCheckIn(), params)


class TestAllowlistGuard(_CheckCase):
    async def test_allowlist_matching_no_session_fails(self):
        # The default IXIA addressing against a DUT peered on other networks.
        result = await self._run(
            [_session("2001:db8:0:1b00::11")],
            {"ignore_all_prefixes_except": ["2401:db00:e50d:11:8::11"]},
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("None of the 1 allowlisted", result.message)

    async def test_allowlist_matching_a_session_still_passes(self):
        result = await self._run(
            [_session("2001:db8:0:1b00::11"), _session("fe80::1", TBgpPeerState.IDLE)],
            {"ignore_all_prefixes_except": ["2001:db8:0:1b00::11"]},
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_allowlist_expecting_zero_sessions_is_not_guarded(self):
        # An explicit expectation of 0 is the caller saying "none" on purpose.
        result = await self._run(
            [_session("2001:db8:0:1b00::11")],
            {
                "ignore_all_prefixes_except": ["2401:db00:e50d:11:8::11"],
                "expected_established_session_count": 0,
            },
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)


class TestMinEstablishedSessionCount(_CheckCase):
    """Report-only mode: down sessions are reported, only too few established fails."""

    PEERS = ["2001:db8::11", "2001:db8::13"]

    async def test_one_established_of_two_passes_and_reports_both(self):
        result = await self._run(
            [_session("2001:db8::11"), _session("2001:db8::13", TBgpPeerState.ACTIVE)],
            {"ignore_all_prefixes_except": self.PEERS, "min_established_session_count": 1},
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("1/2", result.message)
        self.assertIn("2001:db8::13", result.message)

    async def test_none_established_fails(self):
        result = await self._run(
            [
                _session("2001:db8::11", TBgpPeerState.ACTIVE),
                _session("2001:db8::13", TBgpPeerState.IDLE),
            ],
            {"ignore_all_prefixes_except": self.PEERS, "min_established_session_count": 1},
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("0/2", result.message)

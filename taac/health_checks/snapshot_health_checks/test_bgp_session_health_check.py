# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Unit tests for BgpSessionHealthCheck flap / reset detection.

Focus: the uptime handling in ``compare_snapshots``. A slow post-snapshot device
read makes the device-reported uptime arrive several seconds "newer" than the
snapshot timestamp; the old absolute ``abs(actual - expected) > UPTIME_TOLERANCE``
check turned that pure measurement skew into a spurious FAIL. These tests assert
that skew no longer fails the check while genuine resets are still caught.
"""

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import later.unittest
from neteng.fboss.bgp_thrift.types import TBgpPeer, TBgpPeerState, TBgpSession
from neteng.netcastle.logger import ConsoleFileLogger
from taac.constants import TestDevice
from taac.health_checks.constants import Snapshot
from taac.health_checks.snapshot_health_checks.bgp_session_health_check import (
    BgpSessionHealthCheck,
    BgpSessionId,
    RuntimeBgpSnapshot,
)
from taac.health_check.health_check import types as hc_types


_KEY = BgpSessionId(my_addr="10.0.0.1", peer_addr="10.0.0.2")


def _session(uptime_seconds: int, num_of_flaps: int = 0, has_details: bool = True):
    """Minimal stand-in for TBgpSession.

    ``compare_snapshots`` only reads ``.uptime`` (in milliseconds) and, when
    present, ``.details.num_of_flaps``. When ``has_details=False`` the flap check
    falls back to the uptime-decrease path instead of the flap-counter path.
    """
    details = SimpleNamespace(num_of_flaps=num_of_flaps) if has_details else None
    return SimpleNamespace(uptime=uptime_seconds * 1000, details=details)


def _make_check() -> BgpSessionHealthCheck:
    return BgpSessionHealthCheck(
        obj=MagicMock(spec=TestDevice),
        input=hc_types.BaseHealthCheckIn(),
        pre_snapshot_checkpoint_id="pre",
        post_snapshot_checkpoint_id="post",
        check_params={},
        logger=MagicMock(spec=ConsoleFileLogger),
    )


class TestBgpSessionUptimeCheck(unittest.IsolatedAsyncioTestCase):
    async def _compare(self, pre_data, post_data, pre_ts, post_ts, **check_params):
        check = _make_check()
        return await check.compare_snapshots(
            obj=MagicMock(spec=TestDevice),
            input=hc_types.BaseHealthCheckIn(),
            check_params=check_params,
            pre_snapshot=Snapshot(timestamp=pre_ts, data=pre_data),
            post_snapshot=Snapshot(timestamp=post_ts, data=post_data),
        )

    async def test_slow_post_capture_does_not_false_fail(self):
        """Healthy session whose post-snapshot uptime is HIGHER than the naive
        ``pre_uptime + elapsed`` — the signature of a slow post-snapshot device
        read. The removed abs()/UPTIME_TOLERANCE check failed this; must PASS."""
        pre = {_KEY: _session(uptime_seconds=6000, num_of_flaps=1)}
        # elapsed = 80s, but uptime grew by 92s -> +12s skew over "expected".
        post = {_KEY: _session(uptime_seconds=6092, num_of_flaps=1)}
        result = await self._compare(pre, post, pre_ts=1000, post_ts=1080)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS, result.message)

    async def test_healthy_session_passes(self):
        """Session stayed up: uptime grew by ~elapsed, no flaps -> PASS."""
        pre = {_KEY: _session(uptime_seconds=6000, num_of_flaps=0)}
        post = {_KEY: _session(uptime_seconds=6080, num_of_flaps=0)}
        result = await self._compare(pre, post, pre_ts=1000, post_ts=1080)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS, result.message)

    async def test_num_of_flaps_increase_detects_flap(self):
        """Flap counter advanced across the window -> FAIL."""
        pre = {_KEY: _session(uptime_seconds=6000, num_of_flaps=1)}
        post = {_KEY: _session(uptime_seconds=6080, num_of_flaps=2)}
        result = await self._compare(pre, post, pre_ts=1000, post_ts=1080)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("Flapped", result.message)

    async def test_uptime_decrease_detects_flap(self):
        """No flap-counter details available -> uptime going backwards is the
        flap signal -> FAIL."""
        pre = {_KEY: _session(uptime_seconds=6000, has_details=False)}
        post = {_KEY: _session(uptime_seconds=10, has_details=False)}
        result = await self._compare(pre, post, pre_ts=1000, post_ts=1001)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("Flapped", result.message)

    async def test_intentional_restart_requires_both_snapshot_skips(self):
        pre = {_KEY: _session(uptime_seconds=6000, has_details=False)}
        post = {_KEY: _session(uptime_seconds=10, has_details=False)}

        uptime_only = await self._compare(
            pre,
            post,
            pre_ts=1000,
            post_ts=1001,
            skip_uptime_check=True,
        )
        both_skipped = await self._compare(
            pre,
            post,
            pre_ts=1000,
            post_ts=1001,
            skip_flap_check=True,
            skip_uptime_check=True,
        )

        self.assertEqual(uptime_only.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("Flapped", uptime_only.message)
        self.assertEqual(both_skipped.status, hc_types.HealthCheckStatus.PASS)

    async def test_restart_backstop_uptime_less_than_interval(self):
        """Flap counter unchanged and uptime did not decrease, but post uptime
        (50s) is less than the inter-snapshot interval (200s) -> the session
        could not have stayed up the whole window, so it reset -> FAIL."""
        pre = {_KEY: _session(uptime_seconds=10, num_of_flaps=0)}
        post = {_KEY: _session(uptime_seconds=50, num_of_flaps=0)}
        result = await self._compare(pre, post, pre_ts=1000, post_ts=1200)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("restarted", result.message)


_KEY2 = BgpSessionId(my_addr="10.0.0.1", peer_addr="10.0.0.3")


class TestBgpReconvergenceAssertion(unittest.IsolatedAsyncioTestCase):
    """The opt-in reconvergence-timing assertion (assert_reconvergence).

    convergence_sec = (post_ts - uptime) - restart_epoch; ALL pre-Established
    peers must be within max_convergence_sec. Anchored on the disrupted service's
    systemd ActiveEnterTimestamp, scoped to the disrupted device.
    """

    async def _compare(
        self,
        pre_data,
        post_data,
        post_ts,
        restart_epoch="1000",
        obj_name="gtsw001",
        **check_params,
    ):
        check = _make_check()
        check.driver = SimpleNamespace(
            async_run_cmd_on_shell=AsyncMock(return_value=restart_epoch),
            async_get_systemctl_service_name=AsyncMock(
                side_effect=lambda service: service
            ),
        )
        return await check.compare_snapshots(
            obj=SimpleNamespace(name=obj_name),
            input=hc_types.BaseHealthCheckIn(),
            check_params={"assert_reconvergence": True, **check_params},
            pre_snapshot=Snapshot(timestamp=0, data=pre_data),
            post_snapshot=Snapshot(timestamp=post_ts, data=post_data),
        )

    async def test_all_peers_within_sla_pass(self):
        # restart_epoch=1000, post_ts=1080; uptime 30s -> established_at=1050 ->
        # convergence=50s <= 60s SLA for both peers -> PASS.
        pre = {_KEY: _session(6000), _KEY2: _session(6000)}
        post = {_KEY: _session(30), _KEY2: _session(30)}
        result = await self._compare(pre, post, post_ts=1080, max_convergence_sec=60.0)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS, result.message)

    async def test_one_peer_exceeds_sla_fail(self):
        # _KEY2 uptime 10s -> established_at=1070 -> convergence=70s > 60s -> FAIL.
        pre = {_KEY: _session(6000), _KEY2: _session(6000)}
        post = {_KEY: _session(30), _KEY2: _session(10)}
        result = await self._compare(pre, post, post_ts=1080, max_convergence_sec=60.0)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL, result.message)
        self.assertIn("reconvergence SLA", result.message)

    async def test_scoped_out_device_skipped(self):
        # Even with a peer that would violate, a non-DUT device returns PASS.
        pre = {_KEY: _session(6000)}
        post = {_KEY: _session(10)}
        result = await self._compare(
            pre,
            post,
            post_ts=1080,
            obj_name="gtsw002",
            max_convergence_sec=60.0,
            reconvergence_hosts=["gtsw001"],
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS, result.message)
        self.assertIn("not the disrupted device", result.message)

    async def test_deleted_peer_still_fails_before_timing(self):
        # A pre-Established peer absent post -> the deleted-session check fires
        # (peer never re-established) regardless of timing.
        pre = {_KEY: _session(6000), _KEY2: _session(6000)}
        post = {_KEY: _session(30)}
        result = await self._compare(pre, post, post_ts=1080, max_convergence_sec=60.0)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL, result.message)
        self.assertIn("not present in post snapshot", result.message)

    async def test_restart_epoch_unknown_skips(self):
        pre = {_KEY: _session(6000)}
        post = {_KEY: _session(10)}
        result = await self._compare(
            pre, post, post_ts=1080, restart_epoch="", max_convergence_sec=60.0
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS, result.message)
        self.assertIn("skipping reconvergence", result.message)

    async def test_no_pre_peers_passes(self):
        # Only NEW peers post (none in pre) -> nothing in scope -> PASS.
        pre = {}
        post = {_KEY: _session(10)}
        result = await self._compare(pre, post, post_ts=1080, max_convergence_sec=60.0)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS, result.message)


class TestQuietRuntimeBgpBaseline(later.unittest.TestCase):
    def _data(self, *, peer="10.0.0.2", local="10.0.0.1", idle=True):
        key = BgpSessionId(local, peer, TBgpPeerState.ESTABLISHED)
        keys = {key}
        if idle:
            keys.add(BgpSessionId(local, "10.0.0.9", TBgpPeerState.IDLE))
        return RuntimeBgpSnapshot({key: TBgpSession(uptime=10000)}, frozenset(keys))

    async def _capture(self, samples, *, recovery=False, pre=None):
        check = _make_check()
        if pre is not None:
            check._pre_snapshot = pre
        now = [0.0]

        async def sleep(seconds):
            now[0] += seconds

        iterator = iter(samples)
        last = samples[-1]

        async def read():
            nonlocal last
            last = next(iterator, last)
            if isinstance(last, BaseException):
                raise last
            return last

        with (
            patch(
                "neteng.test_infra.dne.taac.health_checks.snapshot_health_checks.bgp_session_health_check.time.monotonic",
                side_effect=lambda: now[0],
            ),
            patch(
                "neteng.test_infra.dne.taac.health_checks.snapshot_health_checks.bgp_session_health_check.asyncio.sleep",
                side_effect=sleep,
            ),
            patch.object(check, "_read_runtime_sessions", side_effect=read),
        ):
            snapshot = await check._capture_runtime_snapshot(
                {
                    "stable_window_sec": 2,
                    "poll_interval_sec": 1,
                    "baseline_timeout_sec": 6,
                    "recovery_timeout_sec": 6,
                },
                recovery=recovery,
            )
        return check, snapshot, now[0]

    async def test_nonempty_baseline_requires_stability_and_audits_idle(self):
        _, snapshot, elapsed = await self._capture([self._data()])
        self.assertEqual(elapsed, 2)
        self.assertEqual(
            snapshot.capture_result.status, hc_types.HealthCheckStatus.PASS
        )
        self.assertIn("IDLE", snapshot.capture_result.message)
        self.assertIn("1/2", snapshot.capture_result.message)

    async def test_empty_pre_times_out_without_passing(self):
        _, snapshot, elapsed = await self._capture(
            [RuntimeBgpSnapshot({}, frozenset())]
        )
        self.assertEqual(elapsed, 6)
        self.assertEqual(
            snapshot.capture_result.status, hc_types.HealthCheckStatus.FAIL
        )
        self.assertIn("timed out", snapshot.capture_result.message)

    async def test_churn_resets_stable_window(self):
        _, snapshot, elapsed = await self._capture(
            [self._data(), self._data(peer="10.0.0.3"), self._data()]
        )
        self.assertEqual(elapsed, 4)
        self.assertEqual(
            snapshot.capture_result.status, hc_types.HealthCheckStatus.PASS
        )

    async def test_missing_pre_returns_failure_without_query_or_polling(self):
        check = _make_check()
        with (
            patch.object(check, "_read_runtime_sessions", new=AsyncMock()) as read,
            patch(
                "neteng.test_infra.dne.taac.health_checks.snapshot_health_checks.bgp_session_health_check.asyncio.sleep",
                new=AsyncMock(),
            ) as sleep,
        ):
            post = await check._capture_runtime_snapshot({}, recovery=True)
        read.assert_not_awaited()
        sleep.assert_not_awaited()
        self.assertEqual(post.capture_result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("Runtime PRE missing", post.capture_result.message)
        result = check._compare_runtime_snapshots(check._pre_snapshot, post)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertEqual(result.message, "Runtime PRE missing")

    async def test_failed_pre_skips_recovery_and_preserves_original_failure(self):
        for data in (RuntimeBgpSnapshot({}, frozenset()), self._data()):
            with self.subTest(data=data):
                check = _make_check()
                failure = hc_types.HealthCheckResult(
                    status=hc_types.HealthCheckStatus.FAIL,
                    message="PRE qualification timed out",
                )
                pre = Snapshot(timestamp=0, data=data, capture_result=failure)
                check._pre_snapshot = pre
                with (
                    patch.object(
                        check, "_read_runtime_sessions", new=AsyncMock()
                    ) as read,
                    patch(
                        "neteng.test_infra.dne.taac.health_checks.snapshot_health_checks.bgp_session_health_check.asyncio.sleep",
                        new=AsyncMock(),
                    ) as sleep,
                ):
                    post = await check._capture_runtime_snapshot({}, recovery=True)
                read.assert_not_awaited()
                sleep.assert_not_awaited()
                self.assertEqual(
                    post.capture_result.status, hc_types.HealthCheckStatus.FAIL
                )
                self.assertIs(check._compare_runtime_snapshots(pre, post), failure)

    async def test_unqualified_pre_skips_recovery(self):
        check = _make_check()
        check._pre_snapshot = Snapshot(timestamp=0, data=self._data())
        with patch.object(check, "_read_runtime_sessions", new=AsyncMock()) as read:
            post = await check._capture_runtime_snapshot({}, recovery=True)
        read.assert_not_awaited()
        self.assertEqual(post.capture_result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("recovery skipped", post.capture_result.message)

    async def test_recovery_waits_for_exact_pre_identities_and_states(self):
        _, pre, _ = await self._capture([self._data()])
        for changed in [
            self._data(peer="10.0.0.3"),
            self._data(local="10.0.0.4"),
            self._data(idle=False),
        ]:
            with self.subTest(changed=changed):
                check, post, elapsed = await self._capture(
                    [changed], recovery=True, pre=pre
                )
                self.assertEqual(elapsed, 6)
                self.assertEqual(
                    check._compare_runtime_snapshots(pre, post).status,
                    hc_types.HealthCheckStatus.FAIL,
                )
        check, post, elapsed = await self._capture(
            [self._data(peer="10.0.0.3"), self._data()], recovery=True, pre=pre
        )
        self.assertEqual(elapsed, 3)
        self.assertEqual(
            check._compare_runtime_snapshots(pre, post).status,
            hc_types.HealthCheckStatus.PASS,
        )

    async def test_driver_capture_keeps_all_configured_states(self):
        check = _make_check()
        check.driver = SimpleNamespace(
            async_get_bgp_sessions=AsyncMock(
                return_value=[
                    TBgpSession(
                        my_addr="a",
                        peer_addr="b",
                        peer=TBgpPeer(peer_state=TBgpPeerState.ESTABLISHED),
                    ),
                    TBgpSession(
                        my_addr="a",
                        peer_addr="c",
                        peer=TBgpPeer(peer_state=TBgpPeerState.IDLE),
                    ),
                ]
            )
        )
        data = await check._read_runtime_sessions()
        self.assertEqual(len(data.established), 1)
        self.assertEqual(len(data.configured), 2)

    async def test_capture_error_is_a_bounded_failed_snapshot(self):
        _, snapshot, elapsed = await self._capture(
            [TimeoutError("device read timed out")]
        )
        self.assertEqual(elapsed, 6)
        self.assertEqual(
            snapshot.capture_result.status, hc_types.HealthCheckStatus.FAIL
        )
        self.assertIn("device read timed out", snapshot.capture_result.message)

    async def test_transient_capture_error_requires_a_new_stable_window(self):
        _, snapshot, elapsed = await self._capture(
            [self._data(), TimeoutError("temporary"), self._data()]
        )
        self.assertEqual(elapsed, 4)
        self.assertEqual(
            snapshot.capture_result.status, hc_types.HealthCheckStatus.PASS
        )

    async def test_capture_cancellation_propagates(self):
        with self.assertRaises(asyncio.CancelledError):
            await self._capture([asyncio.CancelledError()])

    async def test_legacy_capture_still_uses_single_filtered_read(self):
        check = _make_check()
        with patch.object(
            check,
            "async_get_bgp_sessions",
            new=AsyncMock(return_value={_KEY: _session(10)}),
        ) as read:
            snapshot = await check.capture_pre_snapshot(
                MagicMock(), hc_types.BaseHealthCheckIn(), {}, 0
            )
        read.assert_awaited_once_with([])
        self.assertIsNone(snapshot.capture_result)


if __name__ == "__main__":
    unittest.main()

# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh

from taac.health_check.health_check import types as hc_types
from taac.tasks.periodic_tasks import ThriftStressPeriodicTask
from taac.tasks.thrift_stress_payloads import (
    fboss_qsfp_flaps_only,
    READ_ONLY_FBOSS_APIS,
)


def _make_fboss_driver(extra_apis=()) -> MagicMock:
    names = [c.method for c in READ_ONLY_FBOSS_APIS] + list(extra_apis)
    driver = MagicMock(spec=names)
    for name in names:
        setattr(driver, name, AsyncMock(return_value=42))
    return driver


async def _hang(*args, **kwargs):
    await asyncio.sleep(3600)


async def _run(driver) -> dict:
    task = ThriftStressPeriodicTask(hostname="dut", logger=MagicMock())
    with patch(
        "taac.tasks.periodic_tasks.async_get_device_driver",
        AsyncMock(return_value=driver),
    ):
        await task.run({"hostname": "dut", "requests_per_api": 2, "burst_timeout_s": 1.0})
    burst = next(iter(task._data.values()))
    return {k: burst[k] for k in ("total", "success", "failures", "timed_out")}


class ThriftStressBurstTimeoutTest(unittest.IsolatedAsyncioTestCase):
    """A burst that times out keeps the results of the calls that finished."""

    async def test_one_hung_call_does_not_erase_the_others(self) -> None:
        driver = _make_fboss_driver()
        driver.get_bgp_table_length = AsyncMock(side_effect=_hang)
        driver.get_bgp_sessions_count = AsyncMock(side_effect=RuntimeError("rate limited"))
        # 7 APIs * 2 = 14: 2 hang, 2 raise, 10 return.
        self.assertEqual(
            await _run(driver), {"total": 14, "success": 10, "failures": 2, "timed_out": 2}
        )

    async def test_fully_hung_burst_is_all_timed_out(self) -> None:
        driver = _make_fboss_driver()
        for call in READ_ONLY_FBOSS_APIS:
            setattr(driver, call.method, AsyncMock(side_effect=_hang))
        self.assertEqual(
            await _run(driver), {"total": 14, "success": 0, "failures": 0, "timed_out": 14}
        )

    async def test_a_call_that_cancels_itself_counts_as_a_failure(self) -> None:
        driver = _make_fboss_driver()
        driver.get_bgp_sessions_count = AsyncMock(side_effect=asyncio.CancelledError())
        self.assertEqual(
            await _run(driver), {"total": 14, "success": 12, "failures": 2, "timed_out": 0}
        )

    async def test_cancelling_the_burst_cancels_its_calls(self) -> None:
        driver = _make_fboss_driver()
        for call in READ_ONLY_FBOSS_APIS:
            setattr(driver, call.method, AsyncMock(side_effect=_hang))
        task = ThriftStressPeriodicTask(hostname="dut", logger=MagicMock())
        with patch(
            "taac.tasks.periodic_tasks.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            burst = asyncio.ensure_future(
                task.run({"hostname": "dut", "requests_per_api": 2, "burst_timeout_s": 60.0})
            )
            await asyncio.sleep(0.1)
            burst.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await burst
        await asyncio.sleep(0)
        current = asyncio.current_task()
        self.assertFalse([t for t in asyncio.all_tasks() if t is not current and not t.done()])


class ThriftStressFlapRetryTest(unittest.IsolatedAsyncioTestCase):
    """A dynamic flap is retried only when its SSH transport failed."""

    def setUp(self) -> None:
        self.logger = MagicMock()
        self.task = ThriftStressPeriodicTask(hostname="dut", logger=self.logger)

    async def _run(self, driver: MagicMock, params: dict) -> dict:
        with patch(
            "taac.tasks.periodic_tasks.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await self.task.run({"hostname": "dut", **params})
        return next(iter(self.task._data.values()))

    async def _run_dynamic_flap(
        self, flap_side_effect, total_flaps: int = 1, **params
    ) -> dict:
        driver = _make_fboss_driver(
            ["async_get_lldp_neighbors", "async_do_rapid_interface_flaps"]
        )
        driver.async_get_lldp_neighbors.return_value = {
            "eth1/3/1": MagicMock(remote_device_name="peer001")
        }
        driver.async_do_rapid_interface_flaps.side_effect = flap_side_effect
        self.flap = driver.async_do_rapid_interface_flaps
        payload = fboss_qsfp_flaps_only([], total_flaps=total_flaps)
        return await self._run(
            driver,
            {
                "calls": [c.to_dict() for c in payload],
                "resolve_flap_interfaces_from_lldp": True,
                **params,
            },
        )

    async def test_transport_error_is_retried_and_completes(self) -> None:
        # A command hang never raises, so a TimeoutError comes from connecting.
        for error in (
            ConnectionResetError("reset"),
            asyncssh.ConnectionLost("connection lost"),
            TimeoutError("connect"),
        ):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                burst = await self._run_dynamic_flap([error, None])

                self.assertEqual(self.flap.await_count, 2)
                self.assertEqual(
                    (burst["success"], burst["failures"], burst["timed_out"]),
                    (1, 0, 0),
                )
                self.assertEqual(burst["flap_retries"], 1)
                self.assertIn(
                    type(error).__name__, str(self.logger.warning.call_args_list)
                )

    async def test_non_transport_error_is_not_retried(self) -> None:
        for error in (
            RuntimeError("qsfp_service down"),
            asyncssh.PermissionDenied("bad password"),
        ):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                burst = await self._run_dynamic_flap(error)

                self.flap.assert_awaited_once()
                self.assertEqual((burst["failures"], burst["flap_retries"]), (1, 0))

    async def test_multi_flap_call_is_not_retried(self) -> None:
        # The retry re-runs the whole driver call, which for a call carrying
        # several flaps is not the cycle that failed and would be cut mid-flap
        # by the burst deadline.
        burst = await self._run_dynamic_flap(
            [TimeoutError("connect"), None], total_flaps=2
        )
        self.flap.assert_awaited_once()
        self.assertEqual((burst["failures"], burst["flap_retries"]), (1, 0))
        self.assertIn(
            "more than one flap; not retried", str(self.logger.error.call_args_list)
        )

    async def test_timed_out_flap_is_not_retried(self) -> None:
        """A flap that hangs past the burst deadline is a switch-side signal."""
        calls = []

        async def _hang_once(*args, **kwargs):
            calls.append(args)
            if len(calls) == 1:
                await _hang()

        burst = await self._run_dynamic_flap(_hang_once, burst_timeout_s=0.1)

        self.flap.assert_awaited_once()
        self.assertEqual(
            (burst["success"], burst["timed_out"], burst["flap_retries"]), (0, 1, 0)
        )
        self.logger.error.assert_called_once()

    async def test_retry_that_hangs_stops_retrying(self) -> None:
        calls = []

        async def _reset_then_hang(*args, **kwargs):
            calls.append(args)
            if len(calls) == 1:
                raise ConnectionResetError("reset")
            await _hang()

        burst = await self._run_dynamic_flap(_reset_then_hang, burst_timeout_s=0.05)

        self.assertEqual(len(calls), 2)
        self.assertEqual((burst["success"], burst["failures"]), (0, 1))
        self.assertIn("retry hung past", str(self.logger.error.call_args_list))

    async def test_flap_failing_every_retry_still_counts_as_failure(self) -> None:
        burst = await self._run_dynamic_flap(ConnectionResetError("reset"))

        attempts = ThriftStressPeriodicTask.DEFAULT_FLAP_RETRY_ATTEMPTS
        self.assertEqual(self.flap.await_count, 1 + attempts)
        self.assertEqual((burst["success"], burst["failures"]), (0, 1))
        self.assertEqual(burst["flap_retries"], attempts)
        self.logger.error.assert_called_once()
        result = await self.task.run_final_check()
        assert result is not None
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("flap RPC", result.message or "")

    async def test_flap_retry_can_be_disabled(self) -> None:
        burst = await self._run_dynamic_flap(
            ConnectionResetError("reset"), flap_retry_attempts=0
        )

        self.flap.assert_awaited_once()
        self.assertEqual((burst["failures"], burst["flap_retries"]), (1, 0))

    async def test_read_only_call_failures_are_not_retried(self) -> None:
        driver = _make_fboss_driver()
        failing = getattr(driver, READ_ONLY_FBOSS_APIS[0].method)
        failing.side_effect = RuntimeError("LOADSHEDDING")

        burst = await self._run(driver, {"requests_per_api": 2})

        self.assertEqual(failing.await_count, 2)
        self.assertEqual((burst["failures"], burst["flap_retries"]), (2, 0))

    async def test_final_check_reports_flaps_completed_on_retry(self) -> None:
        driver = _make_fboss_driver(["async_get_all_interfaces_operational_status"])
        driver.async_get_all_interfaces_operational_status.return_value = {
            "eth1/3/1": True
        }
        self.task.add_data(
            {
                "hostname": "dut",
                "flap_interfaces": ["eth1/3/1"],
                "total": 1,
                "success": 1,
                "failures": 0,
                "timed_out": 0,
                "flap_retries": 1,
                "elapsed_s": 1.0,
            }
        )
        with patch(
            "taac.tasks.periodic_tasks.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            result = await self.task.run_final_check()

        assert result is not None
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn(
            "1 flap retries after an SSH transport error", result.message or ""
        )


if __name__ == "__main__":
    unittest.main()

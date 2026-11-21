# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""A port-state poll that never returns must not hold a longevity soak open.

The hold's end is only checked between polls, so one getAllPortInfo reply lost
on a half-open connection would otherwise park the step on a single await until
the run-level timeout kills it, losing the postchecks and the poll data.
"""

import asyncio
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import taac.steps.step_definitions as step_definitions
from taac.constants import (  # oss-rewrite (force ShipIt re-export to taac.* root)
    TestDevice,
    TestTopology,
)
from taac.libs.parameter_evaluator import ParameterEvaluator
from taac.steps.step_definitions import LongevityStep
from taac.test_as_a_config import types as taac_types


class _FakeClock:
    """Virtual wall time for the hold; poll deadlines still run on the real loop clock."""

    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


def _build_longevity_step() -> LongevityStep:
    device = MagicMock(spec=TestDevice)
    device.name = "test_device.p001.f01.snc1"
    attributes = MagicMock()
    attributes.operating_system = "FBOSS"
    attributes.role = ""
    attributes.device_name = "test_device"
    attributes.hardware = ""
    attributes.ai_zone = ""
    device.attributes = attributes

    step = LongevityStep(
        name="test_longevity",
        device=device,
        topology=MagicMock(spec=TestTopology),
        test_case_results=[],
        test_config=MagicMock(spec=taac_types.TestConfig),
        test_case_name="test_case",
        test_case_start_time=time.time(),
        parameter_evaluator=MagicMock(spec=ParameterEvaluator),
        step=MagicMock(spec=taac_types.Step),
    )
    step.driver = AsyncMock()
    step.logger = MagicMock()
    return step


class TestLongevityPollTimeout(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.longevity_step = _build_longevity_step()
        self.clock = _FakeClock()
        self._patches = [
            patch.object(step_definitions.time, "time", self.clock.time),
            patch.object(step_definitions.asyncio, "sleep", self.clock.sleep),
            # The collector everpastes its JSONL; keep the unit test offline.
            patch.object(
                step_definitions, "async_everpaste_str", AsyncMock(return_value="h")
            ),
            patch.object(
                step_definitions, "async_get_fburl", AsyncMock(return_value="url")
            ),
        ]
        for patcher in self._patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _warnings(self) -> str:
        return "\n".join(
            str(c.args[0]) for c in self.longevity_step.logger.warning.call_args_list
        )

    def _infos(self) -> str:
        return "\n".join(
            str(c.args[0]) for c in self.longevity_step.logger.info.call_args_list
        )

    async def test_hung_poll_is_abandoned_at_the_hold_deadline(self):
        async def _hang():
            await asyncio.Event().wait()

        self.longevity_step.driver.async_get_all_interfaces_operational_status = _hang

        # Real-time bound: without the deadline this await never returns.
        await asyncio.wait_for(
            self.longevity_step.run(
                taac_types.BaseInput(),
                {"duration": 0.2, "collect_port_state": True, "poll_interval": 5},
            ),
            timeout=5,
        )

        self.assertIn("poll error: TimeoutError", self._warnings())
        self.assertIn("complete: 0 polls", self._infos())

    async def test_hung_poll_is_abandoned_and_polling_resumes(self):
        all_up = {"eth1/1/1": True, "eth1/2/1": True}
        calls = []

        async def _hang_once():
            calls.append(None)
            if len(calls) == 1:
                await asyncio.Event().wait()
            return dict(all_up)

        self.longevity_step.driver.async_get_all_interfaces_operational_status = (
            _hang_once
        )

        with patch.object(LongevityStep, "PORT_STATE_POLL_TIMEOUT_S", 0.05):
            await asyncio.wait_for(
                self.longevity_step.run(
                    taac_types.BaseInput(),
                    {"duration": 60, "collect_port_state": True, "poll_interval": 5},
                ),
                timeout=5,
            )

        # One abandoned poll (+5s backoff), then a clean poll every 5s to the 60s mark.
        self.assertEqual(len(calls), 12)
        self.assertEqual(self.clock.now, 60)
        self.assertIn("1 poll errors", self._infos())


if __name__ == "__main__":
    unittest.main()

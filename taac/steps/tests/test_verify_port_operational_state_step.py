# Copyright (c) Meta Platforms, Inc. and affiliates.

import json
from unittest.mock import AsyncMock, MagicMock, patch

from later.unittest import TestCase
from taac.constants import (
    TestCaseFailure,
    TestDevice,
    TestTopology,
)
from taac.driver.abstract_switch import AbstractSwitch
from taac.libs.parameter_evaluator import ParameterEvaluator
from taac.steps.step_definitions import (
    create_verify_port_operational_state_step,
    VerifyPortOperationalStateStep,
)
from taac.test_as_a_config import types as taac_types

PORTS: list[str] = ["eth1/14/1", "eth1/15/1"]
STEP_MODULE: str = "neteng.test_infra.dne.taac.steps.step_definitions"
BASE_MODULE: str = "neteng.test_infra.dne.taac.steps.step"


class VerifyPortOperationalStateStepTest(TestCase):
    def setUp(self) -> None:
        self.definition = create_verify_port_operational_state_step(
            interfaces=PORTS, operational_state=True, start_traffic=False
        )
        assert self.definition.step_params is not None
        self.params = json.loads(self.definition.step_params.json_params or "{}")
        device = TestDevice(
            name="dut.example.com", attributes=taac_types.SwitchAttributes()
        )
        self.ixia = MagicMock()
        self.driver = AsyncMock(spec=AbstractSwitch)
        self.step = VerifyPortOperationalStateStep(
            name="verify_ports",
            device=device,
            topology=TestTopology(devices=[device]),
            test_case_results=[],
            test_config=taac_types.TestConfig(),
            test_case_name="CPU_039",
            test_case_start_time=0,
            parameter_evaluator=MagicMock(spec=ParameterEvaluator),
            step=self.definition,
            ixia=self.ixia,
            logger=MagicMock(),
        )

    async def _run_step(self) -> None:
        with (
            patch(
                f"{BASE_MODULE}.async_get_device_driver",
                new=AsyncMock(return_value=self.driver),
            ),
            patch(
                f"{BASE_MODULE}.async_everpaste_if_needed",
                new=AsyncMock(return_value="step parameters"),
            ),
            patch(f"{STEP_MODULE}.asyncio.sleep", new=AsyncMock()),
        ):
            await self.step._run(taac_types.BaseInput(), self.params)

    async def test_explicit_up_ports_pass_without_starting_traffic(self) -> None:
        self.driver.async_get_interfaces_status.return_value = dict.fromkeys(
            PORTS, True
        )

        await self._run_step()

        self.driver.async_get_interfaces_status.assert_awaited_once_with(PORTS)
        self.ixia.start_traffic.assert_not_called()

    async def test_missing_port_fails_in_single_endpoint_topology(self) -> None:
        self.driver.async_get_interfaces_status.return_value = {PORTS[0]: True}

        with self.assertRaisesRegex(TestCaseFailure, "not found.*eth1/15/1"):
            await self._run_step()

        self.ixia.start_traffic.assert_not_called()

    async def test_disabled_down_port_fails(self) -> None:
        self.driver.async_get_interfaces_status.return_value = {
            PORTS[0]: True,
            PORTS[1]: False,
        }

        with self.assertRaisesRegex(TestCaseFailure, "mismatch.*eth1/15/1"):
            await self._run_step()

        self.ixia.start_traffic.assert_not_called()

    async def test_retries_until_every_explicit_port_is_up(self) -> None:
        self.driver.async_get_interfaces_status.side_effect = [
            {PORTS[0]: True, PORTS[1]: False},
            dict.fromkeys(PORTS, True),
        ]

        await self._run_step()

        self.assertEqual(2, self.driver.async_get_interfaces_status.await_count)
        self.ixia.start_traffic.assert_not_called()

    async def test_factory_preserves_default_traffic_behavior(self) -> None:
        self.definition = create_verify_port_operational_state_step(PORTS, True)
        self.step.step = self.definition
        assert self.definition.step_params is not None
        self.params = json.loads(self.definition.step_params.json_params or "{}")
        self.driver.async_get_interfaces_status.return_value = dict.fromkeys(
            PORTS, True
        )

        await self._run_step()

        self.ixia.start_traffic.assert_called_once_with()
        self.driver.async_get_interfaces_status.assert_awaited_once_with(PORTS)

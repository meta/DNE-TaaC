# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""RegisterSpeedFlipPatcherStep: profile resolution and the change_speed patcher."""

import json
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from neteng.fboss.switch_config.thrift_mutable_types import PortSpeed

from taac.constants import (  # oss-rewrite (force ShipIt re-export to taac.* root)
    TestDevice,
    TestTopology,
)
from taac.libs.parameter_evaluator import ParameterEvaluator
from taac.steps.speed_flip_profiles import (
    default_profile_id,
    PLATFORM_SPEED_PROFILE_MAPPING,
)
from taac.steps.step_definitions import (
    _SpeedFlipDeviceInfo,
    AGENT_CONFIG,
    create_register_speed_flip_patcher_step,
    RegisterSpeedFlipPatcherStep,
)
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.thrift_types import Step


class RegisterSpeedFlipPatcherStepTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.device = MagicMock(spec=TestDevice)
        self.device.name = "test_device"
        attributes_mock = MagicMock()
        attributes_mock.operating_system = "FBOSS"
        attributes_mock.role = ""
        attributes_mock.device_name = "test_device"
        attributes_mock.hardware = "MONTBLANC"
        attributes_mock.ai_zone = ""
        self.device.attributes = attributes_mock

        self.step = RegisterSpeedFlipPatcherStep(
            name="test_register_speed_flip_patcher",
            device=self.device,
            topology=MagicMock(spec=TestTopology),
            test_case_results=[],
            test_config=MagicMock(),
            test_case_name="test_case",
            test_case_start_time=time.time(),
            parameter_evaluator=MagicMock(spec=ParameterEvaluator),
            step=MagicMock(spec=Step),
        )
        self.driver_mock = AsyncMock()
        self.device_info = _SpeedFlipDeviceInfo(
            ports=["eth1/17/1", "eth1/21/1"],
            driver=self.driver_mock,
            hostname="test_device",
            hardware_type="MONTBLANC",
        )

    async def test_registers_through_the_change_speed_patcher(self):
        await self.step._register_speed_flip_patchers(
            device_infos=[self.device_info],
            speed_in_gbps=800,
            patcher_name="speed_flip",
        )
        self.driver_mock.async_change_speed_patcher.assert_awaited_once()
        call = self.driver_mock.async_change_speed_patcher.await_args
        self.assertEqual(call.kwargs["patcher_name"], "speed_flip")
        self.assertEqual(call.kwargs["intf_names"], ["eth1/17/1", "eth1/21/1"])
        self.assertEqual(call.kwargs["desired_speed"], "EIGHTHUNDREDG")
        self.assertEqual(
            call.kwargs["profile_id"], default_profile_id("MONTBLANC", 800000)
        )

    def test_the_table_needs_a_portspeed_not_raw_mbps(self):
        """Raw Mbps must not reach the table: PortSpeed is an Enum, not an int.

        Indexing the table with raw ``speed_in_mbps`` never matches;
        ``default_profile_id`` converts first.
        """
        by_speed = PLATFORM_SPEED_PROFILE_MAPPING["MONTBLANC"]
        self.assertEqual(
            default_profile_id("MONTBLANC", 800000),
            by_speed[PortSpeed.EIGHTHUNDREDG],
        )

    @unittest.skipIf(
        isinstance(PortSpeed.EIGHTHUNDREDG, int),
        "PortSpeed is int-backed here, so a raw-Mbps lookup hits",
    )
    def test_raw_mbps_misses_the_table(self):
        """Only assertable where PortSpeed is not int-backed (the Meta tree)."""
        self.assertIsNone(PLATFORM_SPEED_PROFILE_MAPPING["MONTBLANC"].get(800000))

    async def test_a_platform_without_a_profile_table_raises(self):
        device_info = _SpeedFlipDeviceInfo(
            ports=["eth1/17/1"],
            driver=self.driver_mock,
            hostname="test_device",
            hardware_type="NOT_A_PLATFORM",
        )
        with self.assertRaises(KeyError) as ctx:
            await self.step._register_speed_flip_patchers(
                device_infos=[device_info],
                speed_in_gbps=800,
                patcher_name="speed_flip",
            )
        self.assertIn("NOT_A_PLATFORM", str(ctx.exception))
        self.driver_mock.async_change_speed_patcher.assert_not_awaited()

    async def test_a_speed_the_platform_has_no_profile_for_raises(self):
        with self.assertRaises(KeyError) as ctx:
            await self.step._register_speed_flip_patchers(
                device_infos=[
                    _SpeedFlipDeviceInfo(
                        ports=["eth1/17/1"],
                        driver=self.driver_mock,
                        hostname="test_device",
                        hardware_type="MINIPACK",
                    )
                ],
                speed_in_gbps=800,
                patcher_name="speed_flip",
            )
        self.assertIn("EIGHTHUNDREDG", str(ctx.exception))

    def test_step_params_are_unchanged_for_callers_that_pass_neither(self):
        step = create_register_speed_flip_patcher_step(
            register_patcher=True,
            port_state_change=False,
            patcher_name="speed_flip",
            endpoints={"test_device": ["eth1/17/1"]},
            speed_in_gbps=800,
        )
        params = json.loads(step.step_params.json_params)
        self.assertEqual(
            params,
            {
                "register_patcher": True,
                "port_state_change": False,
                "patcher_name": "speed_flip",
                "endpoints": {"test_device": ["eth1/17/1"]},
                "speed_in_gbps": 800,
                "target_port_cage_count": 4,
            },
        )

    async def _run_step(self, **extra_params):
        with patch.object(
            self.step, "_gather_device_infos", return_value=[self.device_info]
        ):
            await self.step.run(
                input=MagicMock(),
                params={
                    "register_patcher": False,
                    "port_state_change": False,
                    "endpoints": {
                        "test_device": [
                            "eth1/17/1",
                            "eth1/21/1",
                            "eth1/25/1",
                            "eth1/29/1",
                        ]
                    },
                    **extra_params,
                },
            )

    async def test_run_defaults_to_a_warm_boot(self):
        await self._run_step(patcher_name="speed_flip")
        self.driver_mock.async_coop_unregister_patchers.assert_awaited_once_with(
            "speed_flip", config_name=AGENT_CONFIG
        )
        self.driver_mock.async_apply_patchers.assert_awaited_once_with(
            taac_types.ApplyPatcherMethod.AGENT_WARMBOOT
        )

    async def test_run_forwards_the_requested_method_from_params(self):
        for method in (
            taac_types.ApplyPatcherMethod.AGENT_RELOAD,
            taac_types.ApplyPatcherMethod.AGENT_RELOAD_AND_WARMBOOT,
        ):
            with self.subTest(method=method.name):
                self.driver_mock.reset_mock()
                await self._run_step(apply_patcher_method=method.value)
                self.driver_mock.async_apply_patchers.assert_awaited_once_with(
                    method
                )

    async def test_run_refuses_a_method_that_leaves_the_agent_alone(self):
        """BGP_RESTART never activates the agent config, so the ports would keep
        their old speed while the test carries on."""
        with self.assertRaisesRegex(ValueError, "BGP_RESTART"):
            await self._run_step(
                apply_patcher_method=taac_types.ApplyPatcherMethod.BGP_RESTART.value
            )
        self.driver_mock.async_coop_unregister_patchers.assert_not_awaited()
        self.driver_mock.async_apply_patchers.assert_not_awaited()

    async def test_refused_method_leaves_the_ports_up(self):
        with patch.object(self.step, "_disable_device_ports") as disable:
            with self.assertRaises(ValueError):
                await self._run_step(
                    port_state_change=True,
                    apply_patcher_method=(
                        taac_types.ApplyPatcherMethod.BGP_RESTART.value
                    ),
                )
        disable.assert_not_called()

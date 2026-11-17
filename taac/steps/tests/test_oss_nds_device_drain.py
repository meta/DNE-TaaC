# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""OSS has no NDS drainer; a whole-device NDS drain/undrain uses the on-box drain."""

import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestDevice, TestTopology
from taac.libs.parameter_evaluator import ParameterEvaluator
from taac.steps import step_definitions
from taac.steps.step_definitions import DrainUndrainStep
from taac.test_as_a_config import types as taac_types


class OssNdsDeviceDrainTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        device = MagicMock(spec=TestDevice)
        device.name = "test_device"
        self.step = DrainUndrainStep(
            name="drain",
            device=device,
            topology=MagicMock(spec=TestTopology),
            test_case_results=[],
            test_config=MagicMock(spec=taac_types.TestConfig),
            test_case_name="case",
            test_case_start_time=time.time(),
            parameter_evaluator=MagicMock(spec=ParameterEvaluator),
            step=MagicMock(spec=taac_types.Step),
        )
        self.step.driver = AsyncMock()

    async def test_reboot_undrain_uses_the_onbox_undrain(self):
        with patch.object(step_definitions, "TAAC_OSS", True), patch.object(
            step_definitions, "async_nds_drain", AsyncMock()
        ) as nds:
            await self.step.run(taac_types.DrainUndrainInput(drain=False), {})
            await self.step.run(taac_types.DrainUndrainInput(drain=True), {})
        nds.assert_not_awaited()
        self.step.driver.async_onbox_undrain_device.assert_awaited_once()
        self.step.driver.async_onbox_drain_device.assert_awaited_once()

    async def test_interface_nds_drain_still_uses_nds_in_oss(self):
        resolved = taac_types.TestInterface(interface_name="eth1/1/1")
        self.step.device.get_interface_by_name.return_value = resolved
        with patch.object(step_definitions, "TAAC_OSS", True), patch.object(
            step_definitions, "async_nds_drain", AsyncMock()
        ) as nds:
            await self.step.run(
                taac_types.DrainUndrainInput(drain=True), {"interfaces": '["eth1/1/1"]'}
            )
        nds.assert_awaited_once()
        self.step.driver.async_onbox_drain_device.assert_not_awaited()

    async def test_non_oss_whole_device_drain_still_uses_nds(self):
        with patch.object(step_definitions, "TAAC_OSS", False), patch.object(
            step_definitions, "async_nds_drain", AsyncMock()
        ) as nds:
            await self.step.run(taac_types.DrainUndrainInput(drain=False), {})
        nds.assert_awaited_once()
        self.step.driver.async_onbox_undrain_device.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()

# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

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

    async def _run(self, drain, params, pure_oss):
        with patch.object(
            step_definitions, "oss_config_patcher_enabled", return_value=pure_oss
        ), patch.object(step_definitions, "async_nds_drain", AsyncMock()) as nds:
            await self.step.run(taac_types.DrainUndrainInput(drain=drain), params)
        return nds

    async def test_whole_device_drain_and_undrain_use_the_onbox_drain(self):
        nds = await self._run(False, {}, pure_oss=True)
        self.step.driver.async_onbox_undrain_device.assert_awaited_once()
        nds.assert_not_awaited()
        nds = await self._run(True, {}, pure_oss=True)
        self.step.driver.async_onbox_drain_device.assert_awaited_once()
        nds.assert_not_awaited()

    async def test_interface_drain_still_uses_nds_in_pure_oss(self):
        resolved = taac_types.TestInterface(interface_name="eth1/1/1")
        self.step.device.get_interface_by_name.return_value = resolved
        nds = await self._run(True, {"interfaces": '["eth1/1/1"]'}, pure_oss=True)
        nds.assert_awaited_once()
        self.step.driver.async_onbox_drain_device.assert_not_awaited()

    async def test_other_modes_still_use_nds_for_the_whole_device(self):
        nds = await self._run(False, {}, pure_oss=False)
        nds.assert_awaited_once()
        self.step.driver.async_onbox_undrain_device.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()

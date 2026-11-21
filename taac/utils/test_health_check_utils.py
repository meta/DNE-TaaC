# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""The fb303 counter port must survive an agent that cannot answer."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.utils.health_check_utils import (
    _resolve_fb303_port,
    FBOSS_FB303_PORT,
    FBOSS_MNPU_FB303_PORT,
)


class TestResolveFb303Port(unittest.IsolatedAsyncioTestCase):
    async def _resolve(self, topology, pure_oss=True) -> int:
        driver = MagicMock()
        driver.async_is_multi_switch = AsyncMock()
        if isinstance(topology, BaseException):
            driver.async_is_multi_switch.side_effect = topology
        else:
            driver.async_is_multi_switch.return_value = topology
        with patch(
            "taac.utils.health_check_utils.async_get_device_driver",
            AsyncMock(return_value=driver),
        ), patch(
            "taac.utils.health_check_utils.oss_agent_restart_paths_enabled",
            return_value=pure_oss,
        ):
            return await _resolve_fb303_port("dut")

    async def test_known_topology_picks_its_own_port(self):
        self.assertEqual(await self._resolve(True), FBOSS_MNPU_FB303_PORT)
        self.assertEqual(await self._resolve(False), FBOSS_FB303_PORT)

    async def test_pure_oss_unknown_topology_uses_the_monolithic_port(self):
        error = RuntimeError("no topology")
        self.assertEqual(await self._resolve(error), FBOSS_FB303_PORT)

    async def test_other_modes_let_the_error_propagate(self):
        with self.assertRaises(NotImplementedError):
            await self._resolve(NotImplementedError("not OSS"), pure_oss=False)


if __name__ == "__main__":
    unittest.main()

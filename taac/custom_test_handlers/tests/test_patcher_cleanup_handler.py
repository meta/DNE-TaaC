# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""PatcherCleanupHelper lists the patchers and removes those that a test case added."""

import collections
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.custom_test_handlers import patcher_cleanup_handler
from taac.custom_test_handlers.patcher_cleanup_handler import PatcherCleanupHelper
from taac.driver.fboss_switch import FbossSwitch
from taac.driver.oss_coop_patcher import OssPatcher

HOST = "dut1"
# A COOP patcher is hashable. The old cleanup relies on that.
_CoopPatcher = collections.namedtuple("_CoopPatcher", "name")


def _patcher(name: str, config: str = "agent") -> OssPatcher:
    return OssPatcher(name=name, config_name=config, py_func_name="fn")


class PatcherCleanupHelperTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.driver = AsyncMock(spec=FbossSwitch)
        self.lists = {}
        self.driver.async_coop_list_patchers.side_effect = lambda config: list(
            self.lists.get(config, [])
        )
        for name, value in (
            ("async_get_device_driver", AsyncMock(return_value=self.driver)),
            ("TAAC_OSS", True),
            ("oss_config_patcher_enabled", MagicMock(return_value=True)),
        ):
            mock = patch.object(patcher_cleanup_handler, name, value)
            mock.start()
            self.addCleanup(mock.stop)
        self.helper = PatcherCleanupHelper([HOST], MagicMock())

    async def test_lists_the_registered_patchers(self) -> None:
        self.lists = {"agent": [_patcher("a")], "bgpcpp": [_patcher("b", "bgpcpp")]}
        await self.helper.set_current_registered_patchers()
        current = self.helper.current_patchers[HOST]
        self.assertEqual([p.name for p in current["agent"]], ["a"])
        self.assertEqual([p.name for p in current["bgpcpp"]], ["b"])
        self.assertEqual(current["bgpcpp_drain"], [])

    async def test_unregisters_only_patchers_added_after_setup(self) -> None:
        self.lists = {"agent": [_patcher("old")]}
        await self.helper.set_initial_registered_patchers()
        self.lists = {
            "agent": [_patcher("old"), _patcher("new1"), _patcher("new2")],
            "bgpcpp": [_patcher("new3", "bgpcpp")],
        }
        await self.helper.set_current_registered_patchers()

        await self.helper.initiate_cleanup()

        removed = self.driver.async_coop_unregister_patchers.await_args_list
        self.assertEqual(
            sorted(c.args for c in removed),
            [("new1", "agent"), ("new2", "agent"), ("new3", "bgpcpp")],
        )
        self.driver.async_apply_patchers.assert_awaited_once()
        self.driver.async_restart_service.assert_not_awaited()
        self.driver.async_wait_for_agent_configured.assert_awaited_once()

    async def test_coop_path_removes_and_restarts_the_agent(self) -> None:
        patcher_cleanup_handler.oss_config_patcher_enabled.return_value = False
        with patch.object(patcher_cleanup_handler, "TAAC_OSS", False):
            await self.helper.set_initial_registered_patchers()
            self.lists = {
                "agent": [_CoopPatcher("new1"), _CoopPatcher("new2")],
                "bgpcpp": [_CoopPatcher("new3")],
            }
            await self.helper.set_current_registered_patchers()
            await self.helper.initiate_cleanup()

        removed = self.driver.async_coop_unregister_patchers.await_args_list
        self.assertEqual(
            sorted(c.args for c in removed),
            [("new1", "agent"), ("new2", "agent"), ("new3", "bgpcpp")],
        )
        self.driver.async_restart_service.assert_awaited_once()
        self.driver.async_apply_patchers.assert_not_awaited()

    async def test_oss_with_meta_internal_never_calls_the_driver(self) -> None:
        patcher_cleanup_handler.oss_config_patcher_enabled.return_value = False
        self.lists = {"agent": [_patcher("new")]}

        await self.helper.set_initial_registered_patchers()
        await self.helper.set_current_registered_patchers()
        await self.helper.initiate_cleanup()

        self.driver.async_coop_list_patchers.assert_not_awaited()
        self.driver.async_coop_unregister_patchers.assert_not_awaited()
        self.driver.async_apply_patchers.assert_not_awaited()
        self.driver.async_restart_service.assert_not_awaited()

    async def test_no_new_patcher_means_no_restart(self) -> None:
        self.lists = {"agent": [_patcher("old")]}
        await self.helper.set_initial_registered_patchers()
        await self.helper.set_current_registered_patchers()

        await self.helper.initiate_cleanup()

        self.driver.async_coop_unregister_patchers.assert_not_awaited()
        self.driver.async_apply_patchers.assert_not_awaited()
        self.driver.async_restart_service.assert_not_awaited()

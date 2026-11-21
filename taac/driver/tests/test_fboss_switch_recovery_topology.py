# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Agent topology when the sw agent RPC fails."""

import json
import logging
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, PropertyMock, patch

from taac.driver.fboss_switch import FbossSwitch, FbossSystemctlServiceName

_MODE_FLAG = "taac.driver.fboss_switch.oss_agent_restart_paths_enabled"


class _TopologyTestBase(unittest.IsolatedAsyncioTestCase):
    pure_oss = True

    def setUp(self):
        self.switch = FbossSwitch("dut", logging.getLogger(__name__))
        self.rpc_error = ConnectionError("SW agent unavailable")
        self.client = AsyncMock()
        self.client.__aenter__.return_value = self.client
        self.client.getMultiSwitchRunState.side_effect = self.rpc_error
        self.config = {
            "defaultCommandLineArgs": {"multi_switch": "true"},
            "sw": {
                "switchSettings": {"switchIdToSwitchInfo": {"0": {"switchIndex": 0}}}
            },
        }
        self.raw_config = None
        self.commands = []

        async def shell(_switch, command, *args, **kwargs):
            self.commands.append(command)
            if self.raw_config is not None:
                return self.raw_config
            return json.dumps(self.config)

        for p in [
            patch(_MODE_FLAG, return_value=self.pure_oss),
            patch.object(
                FbossSwitch,
                "async_agent_client",
                new_callable=PropertyMock,
                return_value=self.client,
            ),
            patch.object(FbossSwitch, "async_run_cmd_on_shell", shell),
        ]:
            p.start()
            self.addCleanup(p.stop)


class PureOssTopologyTest(_TopologyTestBase):
    async def test_rpc_down_recovers_explicit_split_topology(self):
        self.assertTrue(await self.switch.async_is_multi_switch())
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0])

    async def test_two_configured_npus_give_both_indices(self):
        infos = self.config["sw"]["switchSettings"]["switchIdToSwitchInfo"]
        infos["42"] = {"switchIndex": 1}
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0, 1])

    async def test_explicit_monolithic_config(self):
        self.config["defaultCommandLineArgs"]["multi_switch"] = "false"
        self.assertFalse(await self.switch.async_is_multi_switch())
        with self.assertRaises(RuntimeError):
            await self.switch.async_get_hw_agent_switch_indices()

    async def test_unclear_config_raises_with_the_rpc_error_as_cause(self):
        for case in ("bad_flag", "bad_json", "bad_index"):
            with self.subTest(case=case):
                self.raw_config = None
                if case == "bad_flag":
                    self.config["defaultCommandLineArgs"]["multi_switch"] = "maybe"
                elif case == "bad_json":
                    self.raw_config = "not json"
                else:
                    infos = self.config["sw"]["switchSettings"]["switchIdToSwitchInfo"]
                    infos["0"]["switchIndex"] = 7
                for operation in (
                    self.switch.async_is_multi_switch,
                    self.switch.async_get_hw_agent_switch_indices,
                ):
                    with self.assertRaises(RuntimeError) as raised:
                        await operation()
                    self.assertIs(raised.exception.__cause__, self.rpc_error)

    async def test_missing_flag_means_the_gflag_default_and_crash_runs_pkill(self):
        self.config["defaultCommandLineArgs"] = {}
        self.assertFalse(await self.switch.async_is_multi_switch())
        self.commands.clear()
        await self.switch.async_crash_service(FbossSystemctlServiceName.AGENT)
        self.assertEqual(self.commands[-1], "pkill -9 wedge_agent")

    async def test_switch_info_rpc_failure_uses_the_config_fallback(self):
        self.client.getMultiSwitchRunState.side_effect = None
        self.client.getMultiSwitchRunState.return_value = SimpleNamespace(
            multiSwitchEnabled=True, hwIndexToRunState={0: 1}
        )
        self.client.getSwitchIdToSwitchInfo.side_effect = TimeoutError("busy")
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0])

    async def test_working_rpc_is_used_without_shell_reads(self):
        self.client.getMultiSwitchRunState.side_effect = None
        self.client.getMultiSwitchRunState.return_value = SimpleNamespace(
            multiSwitchEnabled=True, hwIndexToRunState={1: 1, 0: 1}
        )
        self.client.getSwitchIdToSwitchInfo.return_value = {
            0: SimpleNamespace(switchIndex=0),
            1: SimpleNamespace(switchIndex=1),
        }
        self.assertTrue(await self.switch.async_is_multi_switch())
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0, 1])
        self.assertEqual(self.commands, [])


class NotPureOssTopologyTest(_TopologyTestBase):
    pure_oss = False

    async def test_rpc_down_means_not_multi_switch_and_reads_no_config(self):
        self.assertFalse(await self.switch.async_is_multi_switch())
        self.assertEqual(self.commands, [])

    async def test_rpc_down_raises_the_rpc_error_for_the_indices(self):
        with self.assertRaises(ConnectionError):
            await self.switch.async_get_hw_agent_switch_indices()
        self.assertEqual(self.commands, [])

    async def test_crash_service_still_runs_pkill(self):
        await self.switch.async_crash_service(FbossSystemctlServiceName.AGENT)
        self.assertEqual(self.commands, ["pkill -9 wedge_agent"])


if __name__ == "__main__":
    unittest.main()

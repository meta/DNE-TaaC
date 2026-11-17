# Copyright (c) Meta Platforms, Inc. and affiliates.

import json
import logging
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, PropertyMock, patch

from taac.driver.fboss_switch import FbossSwitch

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_PACKAGE = "taac" if TAAC_OSS else "neteng.test_infra.dne.taac"

_FBOSS_SWITCH_MODULE = f"{_PACKAGE}.driver.fboss_switch"


class RecoveryTopologyTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.switch = FbossSwitch("dut", logging.getLogger(__name__))
        self.rpc_error = ConnectionError("SW agent unavailable")
        self.client = AsyncMock()
        self.client.__aenter__.return_value = self.client
        self.client.getMultiSwitchRunState.side_effect = self.rpc_error
        self.config = {
            "defaultCommandLineArgs": {"multi_switch": "true"},
            "sw": {"switchSettings": {"switchIdToSwitchInfo": {
                "0": {"switchIndex": 0},
            }}},
        }
        self.loaded = {"fboss_sw_agent.service", "fboss_hw_agent@0.service"}
        self.raw_config = None
        self.raw_units = None
        self.commands = []

        async def shell(_switch, command, *args, **kwargs):
            self.commands.append(command)
            if command in ("cat /etc/coop/agent.conf", "cat -- /etc/coop/agent.conf"):
                return self.raw_config if self.raw_config is not None else json.dumps(self.config)
            if self.raw_units is not None:
                return self.raw_units
            units = ["wedge_agent.service", "fboss_sw_agent.service",
                     "fboss_hw_agent@0.service", "fboss_hw_agent@1.service"]
            return "\n\n".join(
                f"Id={unit}\nLoadState={'loaded' if unit in self.loaded else 'not-found'}"
                for unit in units
            )

        for p in [
            patch.object(FbossSwitch, "async_agent_client", new_callable=PropertyMock,
                         return_value=self.client),
            patch.object(FbossSwitch, "async_run_cmd_on_shell", shell),
        ]:
            p.start()
            self.addCleanup(p.stop)

    async def test_rpc_down_recovers_explicit_split_topology(self):
        self.assertTrue(await self.switch.async_is_multi_switch())
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0])
        self.assertTrue(any("systemctl show" in command for command in self.commands))

    async def test_explicit_monolithic_requires_loaded_monolithic_unit(self):
        self.config["defaultCommandLineArgs"]["multi_switch"] = "false"
        self.loaded = {"wedge_agent.service"}
        self.assertFalse(await self.switch.async_is_multi_switch())

    async def test_two_configured_npus_require_both_loaded_units(self):
        self.config["sw"]["switchSettings"]["switchIdToSwitchInfo"]["42"] = {"switchIndex": 1}
        self.loaded.add("fboss_hw_agent@1.service")
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0, 1])

    async def test_template_loadability_does_not_add_unconfigured_hw_indices(self):
        self.loaded.add("fboss_hw_agent@1.service")
        self.assertTrue(await self.switch.async_is_multi_switch())
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0])
        self.assertFalse(any("fboss_hw_agent@1.service" in cmd for cmd in self.commands))

    async def test_installed_split_units_do_not_override_explicit_monolithic_config(self):
        self.config["defaultCommandLineArgs"]["multi_switch"] = "false"
        self.loaded.add("wedge_agent.service")
        self.assertFalse(await self.switch.async_is_multi_switch())

    async def test_monolithic_requires_loaded_wedge_unit(self):
        self.config["defaultCommandLineArgs"]["multi_switch"] = "false"
        with self.assertRaises(RuntimeError) as raised:
            await self.switch.async_is_multi_switch()
        self.assertIs(raised.exception.__cause__, self.rpc_error)

    async def test_non_agent_restart_does_not_require_agent_topology(self):
        from taac.driver.fboss_switch import FbossSystemctlServiceName
        self.raw_config = "missing"
        with patch.object(FbossSwitch, "_async_restart_single_service", new_callable=AsyncMock) as restart:
            await self.switch.async_restart_service(FbossSystemctlServiceName.BGP)
        restart.assert_awaited_once_with(FbossSystemctlServiceName.BGP)
        self.assertEqual(self.commands, [])

    async def test_unknown_config_and_units_fail_closed_with_rpc_cause(self):
        for case in ("missing_flag", "malformed_json", "missing_unit", "unsafe_index",
                     "duplicate_index", "unsupported_index", "missing_units_output"):
            with self.subTest(case=case):
                saved = json.loads(json.dumps(self.config))
                if case == "missing_flag":
                    self.config["defaultCommandLineArgs"] = {}
                elif case == "malformed_json":
                    self.raw_config = "not json"
                elif case == "missing_unit":
                    self.loaded.remove("fboss_hw_agent@0.service")
                elif case == "unsafe_index":
                    self.config["sw"]["switchSettings"]["switchIdToSwitchInfo"]["0"]["switchIndex"] = "0; reboot"
                elif case == "duplicate_index":
                    self.config["sw"]["switchSettings"]["switchIdToSwitchInfo"]["1"] = {"switchIndex": 0}
                elif case == "unsupported_index":
                    self.config["sw"]["switchSettings"]["switchIdToSwitchInfo"]["0"]["switchIndex"] = 2
                else:
                    self.raw_units = ""
                for operation in (self.switch.async_is_multi_switch,
                                  self.switch.async_get_hw_agent_switch_indices):
                    with self.assertRaises(RuntimeError) as raised:
                        await operation()
                    self.assertIs(raised.exception.__cause__, self.rpc_error)
                self.config = saved
                self.raw_config = None
                self.raw_units = None
                self.loaded = {"fboss_sw_agent.service", "fboss_hw_agent@0.service"}

    async def test_non_oss_platform_keeps_the_degradable_callers_working(self):
        """A platform without the OSS evidence must not fail closed everywhere.

        The fallback reads an OSS agent config and OSS systemd units, so
        elsewhere it is unimplemented, not a topology answer -- and callers
        that already coded for that (``except NotImplementedError``) have to
        keep degrading instead of inheriting the restart path's strictness.
        """
        from taac.driver.fboss_switch import FbossSystemctlServiceName

        with patch(f"{_FBOSS_SWITCH_MODULE}.TAAC_OSS", False):
            with self.assertRaises(NotImplementedError) as raised:
                await self.switch.async_is_multi_switch()
            self.assertIs(raised.exception.__cause__, self.rpc_error)
            self.assertEqual(self.commands, [])
            await self.switch.async_crash_service(FbossSystemctlServiceName.AGENT)
        self.assertEqual(self.commands, ["pkill -9 wedge_agent"])

    async def test_non_oss_agent_restart_still_takes_the_monolithic_path(self):
        """The same degradation as async_crash_service: off OSS the fallback
        raises NotImplementedError, and without the guard a monolithic
        Service.AGENT restart fails instead of running systemctl."""
        from taac.driver.fboss_switch import FbossSystemctlServiceName

        with (
            patch(f"{_FBOSS_SWITCH_MODULE}.TAAC_OSS", False),
            patch(
                f"{_FBOSS_SWITCH_MODULE}.oss_agent_restart_paths_enabled",
                return_value=False,
            ),
        ):
            with patch.object(
                FbossSwitch, "_async_restart_single_service", new_callable=AsyncMock
            ) as restart:
                await self.switch.async_restart_service(
                    FbossSystemctlServiceName.AGENT
                )
        restart.assert_awaited_once_with(FbossSystemctlServiceName.AGENT)

    async def test_switch_info_rpc_failure_takes_the_config_fallback(self):
        self.client.getMultiSwitchRunState.side_effect = None
        self.client.getMultiSwitchRunState.return_value = SimpleNamespace(
            multiSwitchEnabled=True, hwIndexToRunState={0: 1},
        )
        self.client.getSwitchIdToSwitchInfo.side_effect = TimeoutError("storm")
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0])
        self.assertTrue(any("systemctl show" in command for command in self.commands))

    async def test_successful_rpc_is_authoritative_without_shell_reads(self):
        self.client.getMultiSwitchRunState.side_effect = None
        self.client.getMultiSwitchRunState.return_value = SimpleNamespace(
            multiSwitchEnabled=True, hwIndexToRunState={1: 1, 0: 1},
        )
        self.client.getSwitchIdToSwitchInfo.return_value = {
            0: SimpleNamespace(switchIndex=0),
            1: SimpleNamespace(switchIndex=1),
        }
        self.assertTrue(await self.switch.async_is_multi_switch())
        self.assertEqual(await self.switch.async_get_hw_agent_switch_indices(), [0, 1])
        self.assertEqual(self.commands, [])
        self.client.getMultiSwitchRunState.return_value.multiSwitchEnabled = False
        self.assertFalse(await self.switch.async_is_multi_switch())
        self.assertEqual(self.commands, [])

#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""bgpd brackets the split-agent warm boot: stopped first, started last.

Stopping bgpd after the sw agent cannot reach the peers (the TUN interfaces
are already gone), and starting it before CONFIGURED cannot reach them either,
so the ordering is the whole point.
"""

import os
import shutil
import subprocess
import tempfile
import typing as t
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.driver import fboss_switch
from taac.driver.fboss_switch import FbossSwitch

_CLEARING_STOP_PREFIX = "t=$(date +%s); systemctl stop bgpd; "


class SplitAgentWarmbootBgpdTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.switch = FbossSwitch("dut1", logger=MagicMock())
        self.run_cmd = AsyncMock(return_value="")
        self.switch.async_run_cmd_on_shell = self.run_cmd
        self.switch.async_get_hw_agent_switch_indices = AsyncMock(return_value=[0])
        self.switch._async_present_cold_boot_flags = AsyncMock(return_value=set())
        self.switch.async_get_service_monotonic_start_time = AsyncMock(
            side_effect=[100, 200]
        )
        self.switch.async_wait_for_service_exit = AsyncMock()
        self.switch.async_wait_for_hw_agent_ready = AsyncMock(return_value=4242)
        self.switch.async_assert_hw_agent_stable = AsyncMock()
        self.switch._async_assert_warm_booted = AsyncMock()
        self.configured = AsyncMock()
        self.switch.async_wait_for_agent_state_configured = self.configured
        sleep_patcher = patch.object(
            fboss_switch.asyncio, "sleep", new_callable=AsyncMock
        )
        self.sleep = sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)

    def _systemctl(self) -> t.List[str]:
        return [
            call.args[0]
            for call in self.run_cmd.await_args_list
            if call.args[0].startswith("systemctl")
        ]

    async def test_default_brackets_the_warm_boot_with_bgpd(self) -> None:
        await self.switch.async_restart_split_agents()
        self.assertEqual(
            self._systemctl(),
            [
                "systemctl stop bgpd",
                "systemctl stop fboss_sw_agent",
                "systemctl stop fboss_hw_agent@0",
                "systemctl start fboss_hw_agent@0",
                "systemctl start fboss_sw_agent",
                "systemctl start bgpd",
            ],
        )

    async def test_bgpd_exit_is_awaited_then_settles_before_the_sw_agent_stops(
        self,
    ) -> None:
        await self.switch.async_restart_split_agents(exit_timeout=7)
        first_exit = self.switch.async_wait_for_service_exit.await_args_list[0]
        self.assertEqual(first_exit.args[0].value, "bgpd")
        self.assertEqual(first_exit.kwargs["timeout"], 7)
        self.sleep.assert_any_await(FbossSwitch.BGPD_STOP_SETTLE_S)

    async def test_bgpd_starts_only_once_the_sw_agent_is_configured(self) -> None:
        order: t.List[str] = []
        self.configured.side_effect = lambda: order.append("configured")
        self.run_cmd.side_effect = lambda cmd: order.append(cmd) or ""
        await self.switch.async_restart_split_agents()
        self.assertEqual(order[-2:], ["configured", "systemctl start bgpd"])

    async def test_stop_bgpd_false_leaves_bgpd_alone(self) -> None:
        await self.switch.async_restart_split_agents(stop_bgpd=False)
        self.assertFalse([c for c in self._systemctl() if "bgpd" in c])
        self.configured.assert_not_awaited()

    async def test_cold_boot_through_this_path_still_brackets_bgpd(self) -> None:
        """bgpd left running across a cold boot is what wedged it."""
        self.switch._async_present_cold_boot_flags = AsyncMock(
            return_value={"/dev/shm/fboss/warm_boot/sw_cold_boot_once"}
        )
        await self.switch.async_restart_split_agents()
        cmds = self._systemctl()
        self.assertEqual(cmds[0], "systemctl stop bgpd")
        self.assertEqual(cmds[-1], "systemctl start bgpd")

    def _bgpd_stop_prints(self, output: str) -> None:
        """What the on-box stop-and-clear command prints for bgpd."""

        def run(cmd: str) -> str:
            return output if cmd.startswith(_CLEARING_STOP_PREFIX) else ""

        self.run_cmd.side_effect = run

    def _stop_cmd(self) -> str:
        return next(
            c.args[0]
            for c in self.run_cmd.await_args_list
            if c.args[0].startswith(_CLEARING_STOP_PREFIX)
        )

    async def test_opted_in_bgpd_stop_clears_a_drain_deadline_exit_on_the_box(
        self,
    ) -> None:
        # The command's logic is covered by ClearingStopShellTest; this checks
        # that the opt-in uses it in place of the plain stop.
        self._bgpd_stop_prints(FbossSwitch.THRIFT_DRAIN_CLEARED_MARKER + "\n")
        await self.switch.async_restart_split_agents(clear_thrift_drain_exit=True)
        self.assertEqual(
            self._stop_cmd(),
            self.switch._stop_clearing_thrift_drain_exit_cmd(
                fboss_switch.FbossSystemctlServiceName.BGP
            ),
        )
        self.assertEqual(self._systemctl()[0], "systemctl stop fboss_sw_agent")
        self.assertIn(
            "missed its thrift drain deadline",
            str(self.switch.logger.warning.call_args_list),
        )

    async def test_opted_in_stop_that_prints_nothing_is_not_treated_as_cleared(
        self,
    ) -> None:
        self._bgpd_stop_prints("")
        await self.switch.async_restart_split_agents(clear_thrift_drain_exit=True)
        self.switch.logger.warning.assert_not_called()
        self.assertEqual(self._systemctl()[-1], "systemctl start bgpd")

    async def test_restart_service_forwards_the_opt_in_to_the_split_agents(
        self,
    ) -> None:
        self.switch.async_restart_split_agents = AsyncMock()
        with patch.object(
            fboss_switch, "oss_agent_restart_paths_enabled", return_value=True
        ):
            await self.switch.async_restart_service(
                fboss_switch.FbossSystemctlServiceName.AGENT,
                clear_thrift_drain_exit=True,
            )
        self.switch.async_restart_split_agents.assert_awaited_once_with(
            clear_thrift_drain_exit=True
        )

    async def test_opt_in_is_ignored_with_a_warning_off_the_split_path(
        self,
    ) -> None:
        self.switch.async_restart_split_agents = AsyncMock()
        self.switch._async_restart_single_service = AsyncMock()
        with patch.object(
            fboss_switch, "oss_agent_restart_paths_enabled", return_value=False
        ):
            await self.switch.async_restart_service(
                fboss_switch.FbossSystemctlServiceName.AGENT,
                clear_thrift_drain_exit=True,
            )
        self.switch.async_restart_split_agents.assert_not_awaited()
        self.switch._async_restart_single_service.assert_awaited_once()
        self.assertIn(
            "clear_thrift_drain_exit has no effect",
            self.switch.logger.warning.call_args.args[0],
        )


_STUB_SYSTEMCTL = """#!/bin/sh
case "$*" in
  "show -p Result --value bgpd") echo "$STUB_RESULT" ;;
  "show -p ExecMainStatus --value bgpd") echo "$STUB_STATUS" ;;
  "reset-failed bgpd") echo reset-failed >> "$STUB_LOG" ;;
esac
"""
_STUB_JOURNALCTL = """#!/bin/sh
printf '%s\\n' "$STUB_JOURNAL"
"""


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class ClearingStopShellTest(unittest.TestCase):
    """Runs the generated on-box command against stub systemctl/journalctl."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        for name, body in (
            ("systemctl", _STUB_SYSTEMCTL),
            ("journalctl", _STUB_JOURNALCTL),
        ):
            path = os.path.join(self.tmp, name)
            with open(path, "w") as f:
                f.write(body)
            os.chmod(path, 0o755)
        self.log = os.path.join(self.tmp, "calls")
        self.cmd = FbossSwitch("dut1", logger=MagicMock())._stop_clearing_thrift_drain_exit_cmd(
            fboss_switch.FbossSystemctlServiceName.BGP
        )

    def _run(self, result: str, status: str, journal: str) -> t.Tuple[bool, bool]:
        env = dict(
            os.environ,
            PATH=f"{self.tmp}:{os.environ.get('PATH', '')}",
            STUB_RESULT=result,
            STUB_STATUS=status,
            STUB_JOURNAL=journal,
            STUB_LOG=self.log,
        )
        out = subprocess.run(
            ["bash", "-c", self.cmd], env=env, capture_output=True, text=True
        ).stdout
        reset = os.path.exists(self.log)
        if reset:
            os.remove(self.log)
        return FbossSwitch.THRIFT_DRAIN_CLEARED_MARKER in out, reset

    def test_clears_only_a_124_exit_with_the_drain_line(self) -> None:
        drain = f"E0101 bgpd: {FbossSwitch.THRIFT_DRAIN_JOURNAL_MARKER}"
        self.assertEqual(self._run("exit-code", "124", drain), (True, True))
        for result, status, journal in (
            ("exit-code", "124", "some other line"),
            ("signal", "0", drain),
            ("exit-code", "1", drain),
            ("core-dump", "124", drain),
            ("success", "0", ""),
        ):
            with self.subTest(result=result, status=status, journal=journal):
                self.assertEqual(self._run(result, status, journal), (False, False))


if __name__ == "__main__":
    unittest.main()

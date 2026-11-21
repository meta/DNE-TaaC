# Copyright (c) Meta Platforms, Inc. and affiliates.

import logging
import re
import unittest
from unittest.mock import AsyncMock, patch

from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.driver.fboss_switch import CrashServiceNoMatchError, FbossSwitch

HW_AGENT_0_PATTERN = r"^/opt/fboss/bin/fboss_hw_agent[^ ]* .*--switchIndex 0( |$)"


class CrashServicePatternTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.switch = FbossSwitch("dut", logging.getLogger(__name__))

    def test_hw_agent_pattern_matches_the_sai_suffixed_binary_only(self):
        command = FbossSwitch._kill_matching_command([HW_AGENT_0_PATTERN])
        match = re.search(r"pgrep -f '([^']+)'", command)
        assert match is not None
        pattern = match.group(1)
        hw0 = (
            "/opt/fboss/bin/fboss_hw_agent-sai_impl --flagfile=/run/fboss/variant_flags"
            " --switchIndex 0 --thrift_ssl_policy=disabled"
        )
        self.assertRegex(hw0, pattern)
        self.assertNotRegex(hw0.replace("--switchIndex 0", "--switchIndex 10"), pattern)
        # pgrep -f also sees the shell running the command.
        self.assertNotRegex(f"bash -c {command}", pattern)

    async def test_crash_that_kills_nothing_raises(self):
        with (
            patch.object(
                self.switch, "async_is_multi_switch", new_callable=AsyncMock, return_value=True
            ),
            patch.object(
                self.switch,
                "async_run_cmd_on_shell",
                new_callable=AsyncMock,
                return_value=f"TAAC_CRASH_NO_MATCH {HW_AGENT_0_PATTERN}",
            ) as run,
            patch(
                "taac.utils.oss_taac_lib_utils.asyncio.sleep", new_callable=AsyncMock
            ) as sleep,
        ):
            with self.assertRaisesRegex(CrashServiceNoMatchError, "killed nothing"):
                await self.switch.async_crash_service(
                    FbossSystemctlServiceName.FBOSS_HW_AGENT_0
                )
        # A missing process won't appear on a retry, so the crash runs only once.
        self.assertEqual(run.await_count, 1)
        sleep.assert_not_awaited()
        assert run.await_args is not None
        self.assertIn(HW_AGENT_0_PATTERN, run.await_args.args[0])

    async def test_agent_crash_kills_sw_and_hw_agent_binaries(self):
        with (
            patch.object(
                self.switch, "async_is_multi_switch", new_callable=AsyncMock, return_value=True
            ),
            patch.object(
                self.switch, "async_run_cmd_on_shell", new_callable=AsyncMock, return_value=""
            ) as run,
        ):
            await self.switch.async_crash_service(FbossSystemctlServiceName.AGENT)
        assert run.await_args is not None
        command = run.await_args.args[0]
        self.assertIn("pgrep -f '^/opt/fboss/bin/fboss_sw_agent( |$)'", command)
        self.assertIn("pgrep -f '^/opt/fboss/bin/fboss_hw_agent[^ ]*( |$)'", command)

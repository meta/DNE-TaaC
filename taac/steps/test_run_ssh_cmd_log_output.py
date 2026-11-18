# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-ignore-all-errors
"""A step's ``log_output`` reaches the console even while console logs are
suppressed around the step."""

import io
import logging
import unittest
from unittest.mock import AsyncMock, MagicMock

from taac.test_as_a_config import types as taac_types


class LogOutputReachesConsoleTest(unittest.IsolatedAsyncioTestCase):
    async def test_log_output_shows_through_run_steps_suppression(self) -> None:
        """run_step wraps every step in suppress_console_logs (console at
        WARNING), so a log_output step must lift that for its own INFO
        "Command output" line and restore it afterwards."""
        from taac.steps.step_definitions import RunSSHCmdStep
        from taac.utils.taac_log_formatter import suppress_console_logs

        logger = logging.getLogger(f"{__name__}.{id(self)}")
        logger.setLevel(logging.DEBUG)
        stream = io.StringIO()
        console = logging.StreamHandler(stream)
        console.setLevel(logging.INFO)
        logger.addHandler(console)
        logger._console_handler = console
        self.addCleanup(logger.removeHandler, console)

        step = RunSSHCmdStep.__new__(RunSSHCmdStep)
        step.logger = logger
        step.driver = MagicMock(
            async_run_cmd_on_shell=AsyncMock(return_value="EXAMPLE_REPORT value=42")
        )
        with suppress_console_logs(logger):
            await step.run(taac_types.BaseInput(), {"cmd": "report", "log_output": True})
            # The enclosing suppression is back in force for whatever follows.
            self.assertEqual(console.level, logging.WARNING)
            await step.run(taac_types.BaseInput(), {"cmd": "quiet"})
        self.assertIn("EXAMPLE_REPORT value=42", stream.getvalue())
        self.assertEqual(stream.getvalue().count("Command output"), 1)


if __name__ == "__main__":
    unittest.main()

# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-ignore-all-errors
"""Playbook cleanup steps log to the console like the playbook's own stages.

Some playbooks end with an informational cleanup step whose whole purpose is
its INFO-level output. Run with the console raised to WARNING, that output
only reaches the log file.
"""

import io
import logging
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from taac.libs.taac_runner import TaacRunner
from taac.steps.step_definitions import create_run_ssh_command_step
from taac.test_as_a_config import types as taac_types
from taac.utils.taac_test_summary import TaacTestSummary


class CleanupStepsConsoleTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.logger = logging.getLogger(f"{__name__}.{id(self)}")
        # What suppress_console_logs raises and restores.
        self.console = logging.StreamHandler(io.StringIO())
        self.console.setLevel(logging.INFO)
        self.logger._console_handler = self.console
        self.summary = TaacTestSummary(self.logger)
        self.addCleanup(self.summary.cleanup)

    def _runner(self, cleanup_steps) -> AsyncMock:
        """A TaacRunner stand-in with everything ``run_test_case`` touches;
        records the console level whenever the cleanup steps run."""
        runner = AsyncMock()
        runner.logger = self.logger
        runner.test_summary = self.summary
        runner.jq_vars = {}
        runner.playbook_results = []
        runner._current_playbook_section = None
        runner._pending_stage_error = None
        runner.continue_on_precheck_failure = False
        runner._get_test_case_iteration_count = MagicMock(return_value=1)
        runner.inject_validation_stages = MagicMock(
            return_value=[taac_types.Stage(iteration=1, steps=[])]
        )
        runner.initialize_and_setup_snapshot_checks = AsyncMock(return_value=[])
        runner._record_playbook_result = MagicMock()
        runner._record_npi_iteration_error = MagicMock()
        runner._raise_test_case_cleanup_errors = MagicMock()
        # Passes the run's own exception (None here) through unchanged.
        runner._run_test_case_fallback_cleanup = AsyncMock(
            side_effect=lambda *a, **k: a[4]
        )
        runner.cleanup_console_levels = []

        async def _run_steps(steps, **kwargs):
            # The Playbook struct holds its own copy of the list.
            if list(steps) == list(cleanup_steps):
                runner.cleanup_console_levels.append(self.console.level)

        runner.initialize_and_run_steps = AsyncMock(side_effect=_run_steps)
        return runner

    async def test_cleanup_steps_run_at_the_normal_console_level(self) -> None:
        cleanup_steps = [create_run_ssh_command_step("true", log_output=True)]
        runner = self._runner(cleanup_steps)
        playbook = taac_types.Playbook(
            name="pb", stages=[], cleanup_steps=cleanup_steps
        )

        await TaacRunner.run_test_case(runner, playbook, SimpleNamespace(name="dut0"))

        self.assertEqual(runner.cleanup_console_levels, [logging.INFO])


if __name__ == "__main__":
    unittest.main()

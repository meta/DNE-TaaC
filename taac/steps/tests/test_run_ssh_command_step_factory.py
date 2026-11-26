# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Unit tests for create_run_ssh_command_step."""

import asyncio
import json
import unittest
from unittest import mock

from taac.steps.step_definitions import (
    create_run_ssh_command_step,
    RunSSHCmdStep,
)
from taac.test_as_a_config.types import StepName


class CreateRunSshCommandStepTest(unittest.TestCase):
    def test_default_omits_log_output(self):
        step = create_run_ssh_command_step(cmd="hostname")
        self.assertEqual(step.name, StepName.RUN_SSH_COMMAND_STEP)
        self.assertEqual(json.loads(step.step_params.json_params), {"cmd": "hostname"})

    def test_log_output_true_is_encoded(self):
        step = create_run_ssh_command_step(
            cmd="hostname", log_output=True, description="d", step_id="s1"
        )
        self.assertEqual(
            json.loads(step.step_params.json_params),
            {"cmd": "hostname", "log_output": True},
        )
        self.assertEqual(step.description, "d")
        self.assertEqual(step.id, "s1")

    def test_expect_and_timeout_are_encoded(self):
        step = create_run_ssh_command_step(cmd="c", expect_in_output="OK", timeout=60)
        self.assertEqual(
            json.loads(step.step_params.json_params),
            {"cmd": "c", "expect_in_output": "OK", "timeout": 60},
        )


class RunSshCmdStepTest(unittest.TestCase):
    def _run(self, output, params):
        step = RunSSHCmdStep.__new__(RunSSHCmdStep)
        step.driver = mock.Mock(async_run_cmd_on_shell=mock.AsyncMock(return_value=output))
        step.logger = mock.Mock()
        asyncio.run(step.run(None, params))
        return step.driver.async_run_cmd_on_shell

    def test_without_expect_any_output_passes(self):
        self._run("", {"cmd": "c"}).assert_awaited_once_with("c")

    def test_expected_marker_passes_and_timeout_is_forwarded(self):
        self._run(
            "x OK y", {"cmd": "c", "expect_in_output": "OK", "timeout": 60}
        ).assert_awaited_once_with("c", timeout=60)

    def test_missing_marker_fails(self):
        with self.assertRaisesRegex(RuntimeError, "TIMEOUT"):
            self._run("TIMEOUT", {"cmd": "c", "expect_in_output": "OK"})

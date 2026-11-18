# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-ignore-all-errors
"""A stage cancelled by the runner's --timeout must not be reported PASS.

`--timeout` is enforced with `asyncio.wait_for(_run_lifecycle(), ...)` in
`taac/runner/oss_entry_point.py`, so the deadline reaches the stage loop as
`asyncio.CancelledError` -- a BaseException. These tests drive the same code
paths with a step that never returns and a sub-second `wait_for`, no hardware.
"""

import asyncio
import logging
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from taac.libs.taac_runner import TaacRunner
from taac.test_as_a_config import types as taac_types
from taac.utils.taac_test_summary import SectionStatus, TaacTestSummary


class TimeoutSectionVerdictTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.summary = TaacTestSummary(logging.getLogger(__name__))
        self.addCleanup(self.summary.cleanup)

    async def _never_returns(self, *args, **kwargs) -> None:
        await asyncio.Event().wait()

    def _fake_runner(self) -> SimpleNamespace:
        """The attributes async_run_stage / _finalize_playbook_section touch."""
        return SimpleNamespace(
            logger=logging.getLogger(__name__),
            test_summary=self.summary,
            _get_stage_display_name=lambda stage: "long_stage",
            initialize_and_run_steps=self._never_returns,
            initialize_and_run_concurrent_steps=self._never_returns,
            _current_playbook_section=None,
            _last_completed_playbook_section=None,
            _pending_stage_error=None,
        )

    async def test_cancelled_stage_is_not_pass(self) -> None:
        runner = self._fake_runner()
        stage = taac_types.Stage(iteration=5, steps=[])

        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(
                TaacRunner.async_run_stage(
                    runner,
                    stage,
                    SimpleNamespace(name="dut0"),
                    "Full_Utilization_ECMP_Group_Coldboot",
                    0,
                    [],
                ),
                timeout=0.05,
            )

        (section,) = self.summary.sections
        self.assertNotEqual(section.status, SectionStatus.PASS)
        self.assertEqual(section.status, SectionStatus.FAIL)
        self.assertIn("cancelled", section.error_message)
        self.assertNotIn("ALL SECTIONS PASSED", self.summary.render_summary())

    async def test_cancelled_stage_marks_the_playbook_section(self) -> None:
        """The playbook row is finalized by the teardown, which sees no error
        of its own -- the in-flight stage's cancellation has to reach it."""
        runner = self._fake_runner()
        runner._current_playbook_section = self.summary.start_section(
            "Playbook: Full_Utilization_ECMP_Group_Coldboot | dut0"
        )
        runner._pending_stage_error = asyncio.CancelledError()

        # exceptions=[] is what a clean teardown after a cancelled stage passes.
        TaacRunner._finalize_playbook_section(runner, [], [])

        (section,) = self.summary.sections
        self.assertEqual(section.status, SectionStatus.FAIL)
        self.assertIn("cancelled", section.error_message)
        self.assertNotIn("ALL SECTIONS PASSED", self.summary.render_summary())

    def _run_test_case_runner(self, stage_error: BaseException) -> SimpleNamespace:
        """A TaacRunner stand-in with everything ``run_test_case`` touches.

        ``async_run_stage`` raises ``stage_error``; the teardown records what
        ``_pending_stage_error`` held when it ran, which is what
        ``_finalize_playbook_section`` would have consumed.
        """
        runner = AsyncMock()
        runner.logger = logging.getLogger(__name__)
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
        runner.async_run_stage = AsyncMock(side_effect=stage_error)
        runner._record_playbook_result = MagicMock()
        runner._record_npi_iteration_error = MagicMock()
        runner._raise_test_case_cleanup_errors = MagicMock()
        runner._run_test_case_fallback_cleanup = AsyncMock(
            side_effect=lambda *a, **k: a[4]
        )
        runner.seen_pending_error = "unset"

        async def _teardown(*args, **kwargs):
            runner.seen_pending_error = runner._pending_stage_error

        runner.async_test_case_tearDown = AsyncMock(side_effect=_teardown)
        return runner

    async def test_a_failed_stage_hands_its_error_to_the_teardown(self) -> None:
        # Producer side: deleting `self._pending_stage_error = error` from the
        # stage loop's `except BaseException` fails this.
        runner = self._run_test_case_runner(asyncio.CancelledError())
        playbook = taac_types.Playbook(name="pb", stages=[])

        with self.assertRaises(asyncio.CancelledError):
            await TaacRunner.run_test_case(
                runner, playbook, SimpleNamespace(name="dut0")
            )

        self.assertIsInstance(runner.seen_pending_error, asyncio.CancelledError)

    async def test_a_playbook_does_not_inherit_the_previous_error(self) -> None:
        # A playbook whose teardown raised before _finalize_playbook_section
        # leaves _pending_stage_error set; the next playbook must not be
        # stamped with it when it fails before the stage loop.
        runner = self._run_test_case_runner(RuntimeError("never reached"))
        stale = RuntimeError("previous playbook")
        runner._pending_stage_error = stale
        runner.async_test_case_setUp = AsyncMock(side_effect=RuntimeError("setup"))
        playbook = taac_types.Playbook(name="pb", stages=[])

        with self.assertRaises(RuntimeError):
            await TaacRunner.run_test_case(
                runner, playbook, SimpleNamespace(name="dut0")
            )

        # setUp raises before the stage loop, so only a reset taken with the
        # section clears it; _finalize_playbook_section would otherwise prepend
        # the previous playbook's error to this one's REASON.
        self.assertIsNot(runner._pending_stage_error, stale)
        self.assertIsNone(runner._pending_stage_error)


class TrackedSectionTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.summary = TaacTestSummary(logging.getLogger(__name__))
        self.addCleanup(self.summary.cleanup)

    async def test_a_cancelled_tracked_section_is_fail(self) -> None:
        # The setup sections ("OSS setup tasks", "Pre-IXIA setup tasks", ...)
        # are wrapped in tracked_section; a run cut short by --timeout raises
        # CancelledError into whichever one is open.
        with self.assertRaises(asyncio.CancelledError):
            with self.summary.tracked_section("OSS setup tasks"):
                raise asyncio.CancelledError()

        (section,) = self.summary.sections
        self.assertEqual(section.status, SectionStatus.FAIL)
        self.assertEqual(section.error_message, "cancelled (run timeout)")
        self.assertNotIn("ALL SECTIONS PASSED", self.summary.render_summary())

    async def test_a_failed_tracked_section_keeps_its_reason(self) -> None:
        with self.assertRaises(RuntimeError):
            with self.summary.tracked_section("Pre-IXIA setup tasks"):
                raise RuntimeError("chassis unreachable")

        (section,) = self.summary.sections
        self.assertEqual(section.status, SectionStatus.FAIL)
        self.assertEqual(section.error_message, "chassis unreachable")


if __name__ == "__main__":
    unittest.main()

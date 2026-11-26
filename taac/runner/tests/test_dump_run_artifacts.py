#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

"""Tests for the end-of-run artifact dump.

Producers write these files to a bare file handle outside the logging
framework, so the runner has to read them back and re-emit them or they never
reach the run's stream.
"""

import logging
import os
import tempfile
import unittest

from taac.runner.oss_entry_point import dump_run_artifacts
from taac.utils.run_artifacts import (
    ArtifactKind,
    clear_artifacts,
    declare_artifact,
)


class TestDumpRunArtifacts(unittest.TestCase):
    def setUp(self) -> None:
        clear_artifacts()
        self.logger = logging.getLogger("taac.oss.test_dump")
        self.logger.setLevel(logging.INFO)

    def tearDown(self) -> None:
        clear_artifacts()

    def _write_artifact(self, contents: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w") as f:
            f.write(contents)
        self.addCleanup(os.unlink, path)
        return path

    def test_file_contents_are_emitted_inline(self) -> None:
        path = self._write_artifact("timestamp  bgpd  notes\nT1  12.5  \n")
        declare_artifact(path, label="cpu_utilization")

        with self.assertLogs(self.logger, level="INFO") as captured:
            dump_run_artifacts(self.logger, "text")

        blob = "\n".join(captured.output)
        self.assertIn("timestamp  bgpd  notes", blob)
        self.assertIn("T1  12.5", blob)
        self.assertIn("cpu_utilization", blob)

    def test_selector_narrows_what_is_dumped(self) -> None:
        cpu = self._write_artifact("cpu rows\n")
        mem = self._write_artifact("mem rows\n")
        declare_artifact(cpu, label="cpu_utilization")
        declare_artifact(mem, label="memory_utilization")

        with self.assertLogs(self.logger, level="INFO") as captured:
            dump_run_artifacts(self.logger, "cpu_utilization")

        blob = "\n".join(captured.output)
        self.assertIn("cpu rows", blob)
        self.assertNotIn("mem rows", blob)

    def test_binary_artifact_is_reported_by_path_not_inlined(self) -> None:
        path = self._write_artifact("\x89PNG binary junk\n")
        declare_artifact(path, label="buffer_watermark", kind=ArtifactKind.BINARY)

        with self.assertLogs(self.logger, level="INFO") as captured:
            dump_run_artifacts(self.logger, "all")

        blob = "\n".join(captured.output)
        self.assertIn("binary, not inlined", blob)
        self.assertIn(path, blob)
        self.assertNotIn("PNG binary junk", blob)

    def test_truncation_is_announced_rather_than_silent(self) -> None:
        path = self._write_artifact("\n".join(str(i) for i in range(10)) + "\n")
        declare_artifact(path, label="cpu_utilization", max_lines=3)

        with self.assertLogs(self.logger, level="INFO") as captured:
            dump_run_artifacts(self.logger, "text")

        blob = "\n".join(captured.output)
        self.assertIn("showing last 3 of 10 lines", blob)

    def test_unreadable_file_warns_and_continues(self) -> None:
        """A vanished artifact is diagnostic noise, not a run failure — the
        remaining artifacts must still be dumped."""
        declare_artifact("/tmp/definitely-not-here.log", label="gone")
        good = self._write_artifact("still here\n")
        declare_artifact(good, label="cpu_utilization")

        with self.assertLogs(self.logger, level="INFO") as captured:
            dump_run_artifacts(self.logger, "text")

        blob = "\n".join(captured.output)
        self.assertIn("Could not read artifact", blob)
        self.assertIn("still here", blob)

    def test_unmatched_selector_warns_and_lists_what_was_available(self) -> None:
        declare_artifact(self._write_artifact("rows\n"), label="cpu_utilization")

        with self.assertLogs(self.logger, level="WARNING") as captured:
            dump_run_artifacts(self.logger, "typo_*")

        blob = "\n".join(captured.output)
        self.assertIn("matched no artifacts", blob)
        self.assertIn("cpu_utilization", blob)

    def test_explicit_none_is_silent(self) -> None:
        """An explicit 'none' is a deliberate choice, not a typo, so it must
        not produce the unmatched-selector warning."""
        declare_artifact(self._write_artifact("rows\n"), label="cpu_utilization")

        with self.assertNoLogs(self.logger, level="INFO"):
            dump_run_artifacts(self.logger, "none")


if __name__ == "__main__":
    unittest.main()

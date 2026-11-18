#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Tests for run-artifact declaration and selection."""

import os
import tempfile
import unittest

from taac.utils.run_artifacts import (
    ArtifactKind,
    clear_artifacts,
    declare_artifact,
    get_artifacts,
    is_dump_disabled,
    read_artifact_lines,
    select_artifacts,
)


class TestDeclareArtifact(unittest.TestCase):
    def setUp(self) -> None:
        clear_artifacts()

    def tearDown(self) -> None:
        clear_artifacts()

    def test_declaration_order_is_preserved(self) -> None:
        declare_artifact("/tmp/a.log", label="cpu_utilization")
        declare_artifact("/tmp/b.log", label="memory_utilization")

        self.assertEqual(
            [a.label for a in get_artifacts()],
            ["cpu_utilization", "memory_utilization"],
        )

    def test_re_declaring_a_path_returns_the_original_unchanged(self) -> None:
        """Back-to-back test configs in one runner process re-create their
        producers; the second declaration must not duplicate or retitle."""
        first = declare_artifact("/tmp/a.log", label="cpu_utilization")
        second = declare_artifact("/tmp/a.log", label="something_else")

        self.assertIs(first, second)
        self.assertEqual(len(get_artifacts()), 1)
        self.assertEqual(get_artifacts()[0].label, "cpu_utilization")

    def test_get_artifacts_filters_by_kind(self) -> None:
        declare_artifact("/tmp/a.log", label="cpu_utilization")
        declare_artifact("/tmp/b.png", label="buffer_watermark", kind=ArtifactKind.BINARY)

        self.assertEqual(
            [a.label for a in get_artifacts(kind=ArtifactKind.BINARY)],
            ["buffer_watermark"],
        )

    def test_returned_list_is_a_copy(self) -> None:
        declare_artifact("/tmp/a.log", label="cpu_utilization")

        get_artifacts().append("bogus")

        self.assertEqual(len(get_artifacts()), 1)


class TestSelectArtifacts(unittest.TestCase):
    def setUp(self) -> None:
        clear_artifacts()
        declare_artifact("/tmp/cpu.log", label="cpu_utilization")
        declare_artifact("/tmp/mem.log", label="memory_utilization")
        declare_artifact("/tmp/hrt_bulk.log", label="hrt_bulk")
        declare_artifact("/tmp/hrt_rf.log", label="hrt_remote_failure")
        declare_artifact(
            "/tmp/wm.png", label="buffer_watermark", kind=ArtifactKind.BINARY
        )

    def tearDown(self) -> None:
        clear_artifacts()

    def _labels(self, selector: str):
        return [a.label for a in select_artifacts(selector)]

    def test_text_selects_every_text_artifact_but_not_binary(self) -> None:
        self.assertEqual(
            self._labels("text"),
            [
                "cpu_utilization",
                "memory_utilization",
                "hrt_bulk",
                "hrt_remote_failure",
            ],
        )

    def test_all_includes_binary(self) -> None:
        self.assertIn("buffer_watermark", self._labels("all"))

    def test_glob_selects_a_family(self) -> None:
        self.assertEqual(
            self._labels("hrt_*"), ["hrt_bulk", "hrt_remote_failure"]
        )

    def test_terms_are_a_union_in_declaration_order(self) -> None:
        self.assertEqual(
            self._labels("memory_utilization,cpu_utilization"),
            ["cpu_utilization", "memory_utilization"],
        )

    def test_overlapping_terms_do_not_duplicate(self) -> None:
        self.assertEqual(self._labels("hrt_*,hrt_bulk").count("hrt_bulk"), 1)

    def test_selector_is_case_insensitive(self) -> None:
        self.assertEqual(self._labels("CPU_Utilization"), ["cpu_utilization"])

    def test_unmatched_selector_returns_empty_rather_than_raising(self) -> None:
        self.assertEqual(self._labels("nope_*"), [])

    def test_none_wins_over_other_terms(self) -> None:
        """A wrapper switching dumping off must not have to rewrite the rest
        of an inherited selector."""
        self.assertEqual(self._labels("text,none"), [])

    def test_is_dump_disabled_distinguishes_none_from_no_match(self) -> None:
        self.assertTrue(is_dump_disabled("none"))
        self.assertTrue(is_dump_disabled(""))
        self.assertFalse(is_dump_disabled("nope_*"))


class TestReadArtifactLines(unittest.TestCase):
    def setUp(self) -> None:
        clear_artifacts()

    def tearDown(self) -> None:
        clear_artifacts()

    def _write(self, contents: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w") as f:
            f.write(contents)
        self.addCleanup(os.unlink, path)
        return path

    def test_uncapped_read_returns_every_line(self) -> None:
        path = self._write("a\nb\nc\n")
        artifact = declare_artifact(path, label="cpu_utilization")

        lines, omitted = read_artifact_lines(artifact)

        self.assertEqual(lines, ["a", "b", "c"])
        self.assertEqual(omitted, 0)

    def test_cap_keeps_the_tail_and_reports_the_omitted_count(self) -> None:
        """Poll logs are read for their most recent samples, and a caller that
        cannot tell truncation happened would present a partial file as whole."""
        path = self._write("\n".join(str(i) for i in range(10)) + "\n")
        artifact = declare_artifact(path, label="cpu_utilization", max_lines=3)

        lines, omitted = read_artifact_lines(artifact)

        self.assertEqual(lines, ["7", "8", "9"])
        self.assertEqual(omitted, 7)

    def test_explicit_max_lines_overrides_the_artifacts_own(self) -> None:
        path = self._write("\n".join(str(i) for i in range(10)) + "\n")
        artifact = declare_artifact(path, label="cpu_utilization", max_lines=3)

        lines, omitted = read_artifact_lines(artifact, max_lines=5)

        self.assertEqual(lines, ["5", "6", "7", "8", "9"])
        self.assertEqual(omitted, 5)

    def test_missing_file_raises_for_the_caller_to_decide(self) -> None:
        artifact = declare_artifact("/tmp/definitely-not-here.log", label="gone")

        with self.assertRaises(OSError):
            read_artifact_lines(artifact)


if __name__ == "__main__":
    unittest.main()

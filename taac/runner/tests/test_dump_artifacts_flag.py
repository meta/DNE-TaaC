#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

"""Tests for --dump-artifacts argument parsing.

The flag is tri-state via nargs="?" — absent, bare, or with a selector — which
is subtle enough to pin down.
"""

import unittest

from taac.runner.cli_parser import parse_args


BASE_ARGV = ["--test-configs", "cfg.py", "--dut", "switch1"]


class TestDumpArtifactsFlag(unittest.TestCase):
    def test_absent_means_no_dump(self) -> None:
        args = parse_args(BASE_ARGV)
        self.assertIsNone(args.dump_artifacts)

    def test_bare_flag_defaults_to_every_text_artifact(self) -> None:
        args = parse_args(BASE_ARGV + ["--dump-artifacts"])
        self.assertEqual(args.dump_artifacts, "text")

    def test_selector_is_passed_through_verbatim(self) -> None:
        args = parse_args(
            BASE_ARGV + ["--dump-artifacts", "cpu_utilization,hrt_*"]
        )
        self.assertEqual(args.dump_artifacts, "cpu_utilization,hrt_*")

    def test_bare_flag_before_another_option_does_not_swallow_it(self) -> None:
        """nargs='?' greedily takes the next token if it isn't option-like;
        --debug is, so the bare form has to survive here."""
        args = parse_args(BASE_ARGV + ["--dump-artifacts", "--debug"])
        self.assertEqual(args.dump_artifacts, "text")
        self.assertTrue(args.debug)


if __name__ == "__main__":
    unittest.main()

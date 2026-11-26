#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Tests for ``collector_window_start``.

Two per-iteration anchors exist and disagree by the duration of test-case
setUp — the ``start_time`` jq var is stamped before it, the collector
registry's timestamp after it. The later one wins.
"""

import unittest

from taac.libs.collectors.registry import (
    clear_collectors,
    set_test_case_start_time,
)
from taac.utils.health_check_utils import (
    collector_window_start,
    floor_collector_window,
    MIN_WINDOW_POLL_INTERVALS,
)


class TestFloorCollectorWindow(unittest.TestCase):
    """The floor exists because a precheck's default window is near-zero-width:
    the runner stamps the test-case start immediately before prechecks run.
    Windows below are floored against the default 5s collector poll interval.
    """

    def test_zero_width_window_is_widened(self) -> None:
        self.assertEqual(floor_collector_window(3000.0, 3000.0, 5.0), 2990.0)

    def test_one_second_window_is_widened(self) -> None:
        """A one-second precheck window."""
        self.assertEqual(floor_collector_window(2999.0, 3000.0, 5.0), 2990.0)

    def test_window_at_the_floor_is_untouched(self) -> None:
        self.assertEqual(floor_collector_window(2990.0, 3000.0, 5.0), 2990.0)

    def test_wider_window_is_untouched(self) -> None:
        """A postcheck spanning the playbook must keep its own start."""
        self.assertEqual(floor_collector_window(1000.0, 3000.0, 5.0), 1000.0)

    def test_floor_scales_with_the_poll_interval(self) -> None:
        """One interval can miss every sample once a poll runs long or times
        out, and a CPU sample is a delta needing the poll before it."""
        for interval in (1.0, 5.0, 30.0):
            start = floor_collector_window(3000.0, 3000.0, interval)
            self.assertEqual(
                3000.0 - start, MIN_WINDOW_POLL_INTERVALS * interval
            )


if __name__ == "__main__":
    unittest.main()

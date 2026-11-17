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


class TestCollectorWindowStart(unittest.TestCase):
    def tearDown(self) -> None:
        clear_collectors()

    def test_registry_anchor_wins_over_earlier_jq_start(self) -> None:
        """The usual caller shape: start_time_jq_var="test_case_start_time",
        stamped before setUp, so the registry's post-setUp anchor is later and
        the tighter window is preserved."""
        set_test_case_start_time(2000.0)
        self.assertEqual(
            collector_window_start({"start_time": 1000}, window_end=3000.0), 2000.0
        )

    def test_later_jq_start_wins(self) -> None:
        """A future call site anchoring to a mid-playbook moment (daemon
        restart, config push) measures the interval it asked for instead of
        silently widening to the whole iteration."""
        set_test_case_start_time(2000.0)
        self.assertEqual(
            collector_window_start({"start_time": 2500}, window_end=3000.0), 2500.0
        )

    def test_jq_start_used_when_registry_anchor_unset(self) -> None:
        self.assertEqual(
            collector_window_start({"start_time": 2500}, window_end=3000.0), 2500.0
        )

    def test_falls_back_to_lookback_when_both_unset(self) -> None:
        self.assertEqual(
            collector_window_start({}, window_end=3000.0, lookback_sec=900), 2100.0
        )

    def test_registry_anchor_used_when_no_jq_start(self) -> None:
        set_test_case_start_time(2000.0)
        self.assertEqual(collector_window_start({}, window_end=3000.0), 2000.0)


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

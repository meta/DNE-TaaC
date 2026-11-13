# Copyright (c) Meta Platforms, Inc. and affiliates.

import unittest

from taac.health_checks.device_health_checks.dlb_resource_analysis import (
    format_snapshot_comparison,
)


class SnapshotComparisonTest(unittest.TestCase):
    def test_accepts_explicit_preexisting_ars_group_offset(self) -> None:
        rendered, matched = format_snapshot_comparison(
            snapshot_count=190,
            matrix_dlb_prefix_total=189,
            expected_extra_groups=1,
        )
        self.assertTrue(matched)
        self.assertIn("Expected extra groups: 1", rendered)
        self.assertIn("MATCH", rendered)

    def test_rejects_negative_extra_group_offset(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected_extra_groups"):
            format_snapshot_comparison(
                snapshot_count=189,
                matrix_dlb_prefix_total=189,
                expected_extra_groups=-1,
            )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Tests for collector artifact declaration and label derivation.

Labels are user-facing — they are what ``--dump-artifacts`` selectors match —
so the derived values are pinned here. Renaming one is a breaking change for
anyone with a selector in a CI invocation.
"""

import unittest

from taac.libs.collectors.base_collector import BaseCollector
from taac.libs.collectors.cpu_utilization_collector import (
    CpuUtilizationCollector,
)
from taac.libs.collectors.memory_utilization_collector import (
    MemoryUtilizationCollector,
)
from taac.libs.collectors.systemd_state_collector import SystemdStateCollector
from taac.utils.run_artifacts import clear_artifacts, get_artifacts


class TestDefaultArtifactLabel(unittest.TestCase):
    def test_oss_collector_labels_match_the_registry_keys(self) -> None:
        """One vocabulary, not two: these are also the names the collector
        registry uses and the names health checks look up."""
        self.assertEqual(
            CpuUtilizationCollector._default_artifact_label(), "cpu_utilization"
        )
        self.assertEqual(
            MemoryUtilizationCollector._default_artifact_label(),
            "memory_utilization",
        )
        self.assertEqual(
            SystemdStateCollector._default_artifact_label(), "systemd_state"
        )

    def test_fpf_collector_names_derive_to_globbable_families(self) -> None:
        """The FPF collectors share an ``hrt_`` prefix, which is what makes
        ``--dump-artifacts 'hrt_*'`` a usable selector."""
        cases = {
            "HrtBulkCollector": "hrt_bulk",
            "HrtRemoteFailureCollector": "hrt_remote_failure",
            "HrtPlaneStatusCollector": "hrt_plane_status",
            "HrtFsdbSessionCollector": "hrt_fsdb_session",
            "ProdHrtPrefixCollector": "prod_hrt_prefix",
            "FsdbRibmapCollector": "fsdb_ribmap",
            "BgpRibCollector": "bgp_rib",
        }
        for class_name, expected in cases.items():
            with self.subTest(class_name=class_name):
                cls = type(class_name, (BaseCollector,), {})
                self.assertEqual(cls._default_artifact_label(), expected)

    def test_class_without_the_collector_suffix_still_derives(self) -> None:
        cls = type("SomeProducer", (BaseCollector,), {})
        self.assertEqual(cls._default_artifact_label(), "some_producer")


class TestCollectorDeclaresItsArtifact(unittest.TestCase):
    def setUp(self) -> None:
        clear_artifacts()

    def tearDown(self) -> None:
        clear_artifacts()

    def test_construction_declares_the_log_path(self) -> None:
        """Declared in __init__, not at registry registration: the file is
        written whether or not anything registers the collector."""
        BaseCollector(tmp_path="/tmp/some_collector.1.log")

        artifacts = get_artifacts()
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].path, "/tmp/some_collector.1.log")
        self.assertEqual(artifacts[0].label, "base")
        self.assertIsNotNone(artifacts[0].max_lines)

    def test_explicit_label_overrides_the_derived_one(self) -> None:
        BaseCollector(tmp_path="/tmp/x.log", artifact_label="custom_name")

        self.assertEqual(get_artifacts()[0].label, "custom_name")


if __name__ == "__main__":
    unittest.main()

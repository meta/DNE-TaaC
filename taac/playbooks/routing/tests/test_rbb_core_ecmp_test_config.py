# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Integration tests for the standalone RBB core ECMP TestConfig."""

import runpy
import unittest
from pathlib import Path
from unittest import mock

from taac.testconfigs.routing.factories.qual_rbb.rbb_core_ecmp_test_config import (
    create_rbb_core_ecmp_test_config,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology(path_count=2):
    paths = tuple(
        CorePortChannel(f"port-channel{index}", (f"eth1/{index}",))
        for index in range(1, path_count + 1)
    )
    return RbbTopology(
        r1=NodeTopology(
            "r1",
            "r1.example",
            paths,
            (IxiaEdge("eth1/10", "1/1"),),
        ),
        r2=NodeTopology(
            "r2",
            "r2.example",
            paths,
            (IxiaEdge("eth1/10", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbCoreEcmpTestConfigTest(unittest.TestCase):
    def test_default_config_exposes_two_independent_playbooks(self) -> None:
        config = create_rbb_core_ecmp_test_config(_topology())

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p1_tc02_openr_path_selection",
                "rbb_p1_tc03_openr_ecmp",
            ],
        )
        self.assertTrue(all(not endpoint.ixia_needed for endpoint in config.endpoints))
        self.assertTrue(config.skip_ixia_protocol_verification)
        self.assertIsNone(config.basic_traffic_item_configs)
        self.assertIsNone(config.basic_port_configs)

    def test_explicit_selection_is_dependency_ordered(self) -> None:
        config = create_rbb_core_ecmp_test_config(
            _topology(), testplan_ids=["phase1:TC-03", "phase1:TC-02"]
        )
        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p1_tc02_openr_path_selection",
                "rbb_p1_tc03_openr_ecmp",
            ],
        )

    def test_rejects_topology_without_parallel_core_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least two"):
            create_rbb_core_ecmp_test_config(_topology(path_count=1))

    def test_example_wrapper_exports_factory_result(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[4] / "examples" / "rbb_core_ecmp_config.py"
        )
        sentinel = object()
        target = (
            "taac.testconfigs.routing.factories.qual_rbb."
            "rbb_core_ecmp_test_config.create_rbb_core_ecmp_test_config"
        )
        with mock.patch(target, return_value=sentinel):
            result = runpy.run_path(str(wrapper))
        self.assertIs(result["test_config"], sentinel)


if __name__ == "__main__":
    unittest.main()

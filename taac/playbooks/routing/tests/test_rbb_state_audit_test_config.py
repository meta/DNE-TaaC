# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for the RBB state-audit TestConfig integration."""

import os
import runpy
import unittest
from pathlib import Path
from unittest import mock

from taac.testconfigs.routing.factories.qual_rbb.rbb_state_audit_test_config import (
    create_rbb_state_audit_test_config,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    RbbAuditCoverage,
    build_rbb_state_audit_profiles,
    select_rbb_state_audit_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology() -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="audit-r1.example",
            core_pcs=(CorePortChannel("port-channel1", ("eth1/1",)),),
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="audit-r2.example",
            core_pcs=(CorePortChannel("port-channel1", ("eth1/1",)),),
            ixia_edges=(IxiaEdge("eth1/5", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbStateAuditTestConfigTest(unittest.TestCase):
    def test_default_selection_is_one_playbook_per_full_profile(self) -> None:
        topology = _topology()
        expected = select_rbb_state_audit_profiles(
            build_rbb_state_audit_profiles(topology)
        )
        config = create_rbb_state_audit_test_config(topology)

        self.assertTrue(expected)
        self.assertTrue(
            all(profile.coverage is RbbAuditCoverage.FULL for profile in expected)
        )
        self.assertEqual(len(config.playbooks), len(expected))
        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [profile.playbook_name for profile in expected],
        )

    def test_device_only_config_does_not_reserve_or_configure_ixia(self) -> None:
        config = create_rbb_state_audit_test_config(_topology())

        self.assertTrue(config.skip_ixia_protocol_verification)
        self.assertIsNone(config.basic_port_configs)
        self.assertIsNone(config.basic_traffic_item_configs)
        self.assertEqual(len(config.endpoints), 2)
        for endpoint in config.endpoints:
            self.assertFalse(endpoint.ixia_needed)
            self.assertIsNone(endpoint.ixia_ports)
            self.assertIsNone(endpoint.direct_ixia_connections)

    def test_read_only_config_has_no_setup_or_teardown_tasks(self) -> None:
        config = create_rbb_state_audit_test_config(_topology())

        self.assertEqual(config.setup_tasks, [])
        self.assertEqual(config.teardown_tasks, [])

    def test_explicit_full_profile_selection(self) -> None:
        topology = _topology()
        profile = select_rbb_state_audit_profiles(
            build_rbb_state_audit_profiles(topology)
        )[0]
        config = create_rbb_state_audit_test_config(
            topology, testplan_ids=[profile.testplan_id]
        )

        self.assertEqual(len(config.playbooks), 1)
        self.assertEqual(profile.playbook_name, config.playbooks[0].name)

    def test_partial_profile_requires_explicit_opt_in(self) -> None:
        topology = _topology()
        partial = next(
            profile
            for profile in build_rbb_state_audit_profiles(topology)
            if profile.coverage is RbbAuditCoverage.PARTIAL
        )

        with self.assertRaisesRegex(ValueError, "partial"):
            create_rbb_state_audit_test_config(
                topology, testplan_ids=[partial.testplan_id]
            )
        config = create_rbb_state_audit_test_config(
            topology,
            testplan_ids=[partial.testplan_id],
            allow_partial=True,
        )
        self.assertEqual(len(config.playbooks), 1)

    def test_unknown_testplan_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown"):
            create_rbb_state_audit_test_config(_topology(), testplan_ids=["P9-TC999"])

    def test_setup_duts_reuses_transactional_pr46_bootstrap(self) -> None:
        with mock.patch.object(C, "SETUP_DUTS_ENABLED", True):
            config = create_rbb_state_audit_test_config(_topology())

        self.assertEqual(
            [task.task_name for task in config.setup_tasks],
            ["rbb_dut_bootstrap", "rbb_dut_bootstrap"],
        )
        self.assertEqual(
            [task.task_name for task in config.teardown_tasks],
            ["rbb_dut_bootstrap", "rbb_dut_bootstrap"],
        )

    def test_setup_duts_without_explicit_wiring_rejects_placeholders(self) -> None:
        with (
            mock.patch.object(C, "SETUP_DUTS_ENABLED", True),
            mock.patch.dict(os.environ, {"TAAC_CIRCUIT_INFO_PATH": ""}),
            self.assertRaisesRegex(ValueError, "placeholder wiring"),
        ):
            create_rbb_state_audit_test_config()

    def test_oss_runner_wrapper_exports_default_test_config(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[4]
            / "examples"
            / "rbb_state_audit_config.py"
        )
        with mock.patch.object(C, "SETUP_DUTS_ENABLED", False):
            config = runpy.run_path(str(wrapper))["test_config"]

        self.assertEqual(config.name, "RBB_STATE_AUDIT_TEST")
        self.assertTrue(config.playbooks)


if __name__ == "__main__":
    unittest.main()

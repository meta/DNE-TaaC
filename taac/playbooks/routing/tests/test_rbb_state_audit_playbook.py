# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for the read-only RBB state-audit playbooks."""

import json
import unittest

from taac.test_as_a_config.types import StepName

from taac.playbooks.routing.factories.qual_rbb.rbb_state_audit_playbook import (
    create_rbb_state_audit_playbook,
)
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    RbbAuditCoverage,
    RbbRouteExpectation,
    RbbStateAuditProfile,
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


def _selected_profiles():
    profiles = build_rbb_state_audit_profiles(_topology())
    return select_rbb_state_audit_profiles(profiles)


def _task_payloads(playbook):
    payloads = []
    for stage in playbook.stages or []:
        for step in stage.steps or []:
            if step.name != StepName.RUN_TASK_STEP:
                continue
            run_task = json.loads(step.input_json)["task"]
            payloads.append(
                (run_task["task_name"], json.loads(run_task["params"]["json_params"]))
            )
    return payloads


class RbbStateAuditPlaybookTest(unittest.TestCase):
    def test_one_playbook_and_stage_per_testplan_profile(self) -> None:
        profile = _selected_profiles()[0]
        playbook = create_rbb_state_audit_playbook(
            profile,
            r1_hostname="audit-r1.example",
            r2_hostname="audit-r2.example",
        )

        self.assertEqual(playbook.name, profile.playbook_name)
        self.assertEqual(len(playbook.stages or []), 1)
        self.assertTrue(
            (playbook.stages or [])[0].description.startswith(profile.testplan_id)
        )

    def test_explicitly_queries_both_duts_from_one_r1_anchor(self) -> None:
        profile = _selected_profiles()[0]
        playbook = create_rbb_state_audit_playbook(
            profile,
            r1_hostname="audit-r1.example",
            r2_hostname="audit-r2.example",
        )
        payloads = _task_payloads(playbook)

        self.assertEqual([name for name, _ in payloads], ["rbb_state_audit"] * 2)
        self.assertEqual(
            [params["hostname"] for _, params in payloads],
            ["audit-r1.example", "audit-r2.example"],
        )
        self.assertEqual(
            [params["gate"] for _, params in payloads],
            [profile.testplan_id, profile.testplan_id],
        )
        self.assertEqual(playbook.device_regexes, [r"^audit\-r1\.example$"])

    def test_task_payload_is_the_profile_projection_for_each_node(self) -> None:
        profile = _selected_profiles()[0]
        playbook = create_rbb_state_audit_playbook(
            profile,
            r1_hostname="audit-r1.example",
            r2_hostname="audit-r2.example",
        )
        payloads = _task_payloads(playbook)

        for node, (_, params) in zip(("r1", "r2"), payloads):
            expected = profile.to_task_params(node)
            self.assertEqual(
                {
                    key: params[key]
                    for key in (
                        "routes",
                        "ndp",
                        "mysids",
                        "active_services",
                        "interfaces_up",
                    )
                },
                expected,
            )

    def test_r2_only_profile_queries_and_anchors_to_r2(self) -> None:
        profile = RbbStateAuditProfile(
            testplan_id="phase2:TC-1",
            playbook_name="rbb_r2_only",
            title="R2-only state audit",
            coverage=RbbAuditCoverage.FULL,
            target_roles=("r2",),
            routes=(RbbRouteExpectation("r2", "192.0.2.1/32", "OPENR"),),
        )
        playbook = create_rbb_state_audit_playbook(
            profile,
            r1_hostname="audit-r1.example",
            r2_hostname="audit-r2.example",
        )
        payloads = _task_payloads(playbook)

        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0][0], "rbb_state_audit")
        self.assertEqual(payloads[0][1]["hostname"], "audit-r2.example")
        self.assertEqual(payloads[0][1]["gate"], profile.testplan_id)
        self.assertEqual(playbook.device_regexes, [r"^audit\-r2\.example$"])

    def test_read_only_playbook_has_no_lifecycle_side_effects(self) -> None:
        profile = _selected_profiles()[0]
        playbook = create_rbb_state_audit_playbook(profile)

        self.assertEqual(playbook.prechecks, [])
        self.assertEqual(playbook.postchecks, [])
        self.assertEqual(playbook.cleanup_steps, [])
        self.assertFalse(playbook.backup_and_restore_ixia_config)

    def test_default_profile_playbook_names_are_unique_and_stable(self) -> None:
        profiles = _selected_profiles()
        names = [create_rbb_state_audit_playbook(profile).name for profile in profiles]

        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names, [profile.playbook_name for profile in profiles])

    def test_partial_profile_is_visibly_labeled(self) -> None:
        partial = next(
            profile
            for profile in build_rbb_state_audit_profiles(_topology())
            if profile.unmet_requirements
        )
        playbook = create_rbb_state_audit_playbook(partial)

        self.assertIn("[PARTIAL]", playbook.description)
        self.assertTrue(playbook.name.endswith("_partial"))


if __name__ == "__main__":
    unittest.main()

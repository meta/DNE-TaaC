# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Structure tests for reversible Open/R core ECMP playbooks."""

import json
import unittest

from taac.test_as_a_config import types as taac_types
from taac.playbooks.routing.factories.qual_rbb.rbb_core_ecmp_playbook import (
    create_rbb_core_ecmp_playbook,
)
from taac.testconfigs.routing.util.bgp_rbb_core_ecmp_profiles import (
    OPENR_PREFERRED_METRIC,
    OPENR_STANDBY_METRIC,
    build_rbb_core_ecmp_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology():
    return RbbTopology(
        r1=NodeTopology(
            "r1",
            "core-r1.example",
            (
                CorePortChannel("port-channel1", ("eth1/1/1", "eth1/1/2")),
                CorePortChannel("port-channel2", ("eth1/2/1",)),
            ),
            (IxiaEdge("eth1/10", "1/1"),),
        ),
        r2=NodeTopology(
            "r2",
            "core-r2.example",
            (
                CorePortChannel("peer-a", ("eth1/1/1", "eth1/1/2")),
                CorePortChannel("peer-b", ("eth1/2/1",)),
            ),
            (IxiaEdge("eth1/10", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


def _profile(testplan_id):
    return next(
        profile
        for profile in build_rbb_core_ecmp_profiles(_topology())
        if profile.testplan_id == testplan_id
    )


def _task_payload(step):
    task = json.loads(step.input_json or "{}")["task"]
    return task["task_name"], json.loads(task["params"]["json_params"])


def _run_tasks(playbook, task_name=None):
    result = []
    for stage in playbook.stages:
        for step in stage.steps:
            if step.name != taac_types.StepName.RUN_TASK_STEP:
                continue
            name, params = _task_payload(step)
            if task_name is None or name == task_name:
                result.append((name, params))
    return result


class RbbCoreEcmpPlaybookTest(unittest.TestCase):
    def test_tc02_selects_each_core_path_in_both_directions(self) -> None:
        playbook = create_rbb_core_ecmp_playbook(
            _profile("phase1:TC-02"), topology=_topology()
        )
        tasks = [params for _, params in _run_tasks(playbook, "rbb_openr_core_path")]
        metric_writes = [
            params for params in tasks if params["action"] == "set_metrics"
        ]
        route_checks = [
            params for params in tasks if params["action"] == "assert_routes"
        ]

        self.assertEqual(
            [params["metrics"] for params in metric_writes],
            [
                [OPENR_PREFERRED_METRIC, OPENR_STANDBY_METRIC],
                [OPENR_PREFERRED_METRIC, OPENR_STANDBY_METRIC],
                [OPENR_STANDBY_METRIC, OPENR_PREFERRED_METRIC],
                [OPENR_STANDBY_METRIC, OPENR_PREFERRED_METRIC],
            ],
        )
        self.assertEqual(
            [params["path_indices"] for params in route_checks],
            [[0], [0], [1], [1]],
        )
        self.assertTrue(all(len(params["routes"]) == 2 for params in route_checks))
        self.assertIsNone(playbook.traffic_items_to_start)

    def test_tc03_programs_and_verifies_all_equal_cost_paths(self) -> None:
        playbook = create_rbb_core_ecmp_playbook(
            _profile("phase1:TC-03"), topology=_topology()
        )
        tasks = [params for _, params in _run_tasks(playbook, "rbb_openr_core_path")]
        metric_writes = [
            params for params in tasks if params["action"] == "set_metrics"
        ]
        route_checks = [
            params for params in tasks if params["action"] == "assert_routes"
        ]

        self.assertEqual(len(metric_writes), 2)
        self.assertTrue(
            all(
                params["metrics"] == [OPENR_PREFERRED_METRIC] * 2
                for params in metric_writes
            )
        )
        self.assertEqual(len(route_checks), 2)
        self.assertTrue(
            all(params["path_indices"] == [0, 1] for params in route_checks)
        )

    def test_cleanup_restores_both_duts(self) -> None:
        for testplan_id in ("phase1:TC-02", "phase1:TC-03"):
            with self.subTest(testplan_id=testplan_id):
                playbook = create_rbb_core_ecmp_playbook(
                    _profile(testplan_id), topology=_topology()
                )
                cleanup_tasks = [
                    _task_payload(step) for step in playbook.cleanup_steps
                ]
                self.assertEqual(
                    [name for name, _ in cleanup_tasks],
                    ["rbb_openr_core_path", "rbb_openr_core_path"],
                )
                self.assertEqual(
                    [params["hostname"] for _, params in cleanup_tasks],
                    ["core-r1.example", "core-r2.example"],
                )


if __name__ == "__main__":
    unittest.main()

# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

import json
import typing as t
import unittest

from taac.testconfigs.routing import cicd_ebb_int_tc
from taac.testconfigs.routing.adhoc_agent_restart_matrix import (
    NRQEB006_EBB01_RESTART_MATRIX_UG_ADHOC,
)
from taac.utils.json_thrift_utils import json_to_thrift
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config.types import (
    Playbook,
    PointInTimeHealthCheck,
    RunTaskInput,
    Stage,
    Step,
    StepName,
    TestConfig,
    ValidationInput,
)

_PLAYBOOK = "bgp_ebb_daemon_restart_playbook"
_STAGE_IDS = ["s1_fibagent_bgp_restart", "s3_bgpcpp_restart"]


def _playbook(config: TestConfig) -> Playbook:
    return next(playbook for playbook in config.playbooks if playbook.name == _PLAYBOOK)


def _json_params(step: Step) -> dict[str, t.Any]:
    if step.step_params is None or not step.step_params.json_params:
        return {}
    return json.loads(step.step_params.json_params)


def _daemon_actions(stage: Stage) -> list[tuple[str, str]]:
    actions = []
    for step in stage.steps:
        if step.name != StepName.RUN_TASK_STEP or not step.input_json:
            continue
        task = json_to_thrift(step.input_json, RunTaskInput).task
        if task.task_name != "arista_daemon_control":
            continue
        params = json.loads(task.params.json_params or "{}")
        actions.append((params["daemon_name"], params["action"]))
    return actions


def _custom_step_names(stage: Stage) -> list[str]:
    return [
        _json_params(step)["custom_step_name"]
        for step in stage.steps
        if "custom_step_name" in _json_params(step)
    ]


def _stage_checks(stage: Stage) -> list[PointInTimeHealthCheck]:
    last = stage.steps[-1]
    if last.name != StepName.VALIDATION_STEP or not last.input_json:
        raise AssertionError(f"{stage.id} does not end with a validation step")
    return list(json_to_thrift(last.input_json, ValidationInput).point_in_time_checks)


def _check(
    checks: list[PointInTimeHealthCheck], check_id: str
) -> PointInTimeHealthCheck:
    return next(check for check in checks if check.check_id == check_id)


def _jq_params(check: PointInTimeHealthCheck) -> t.Mapping[str, str]:
    if check.check_params is None or check.check_params.jq_params is None:
        return {}
    return check.check_params.jq_params


def _expected_restarts(check: PointInTimeHealthCheck) -> list[str]:
    params = check.check_params
    if params is None or not params.json_params:
        return []
    return json.loads(params.json_params).get("expected_restarted_services", [])


class AdhocEbb01RestartMatrixTest(unittest.TestCase):
    def setUp(self) -> None:
        self.playbook = _playbook(NRQEB006_EBB01_RESTART_MATRIX_UG_ADHOC)
        self.stages = {stage.id: stage for stage in self.playbook.stages}

    def test_binding_runs_only_ebb01_on_nrqeb006(self) -> None:
        config = NRQEB006_EBB01_RESTART_MATRIX_UG_ADHOC
        self.assertEqual("NRQEB006_EBB01_RESTART_MATRIX_UG_ADHOC", config.name)
        self.assertEqual([_PLAYBOOK], [playbook.name for playbook in config.playbooks])
        self.assertEqual(
            ["nrqeb006.ash6"],
            [endpoint.name for endpoint in config.endpoints if endpoint.dut],
        )

    def test_one_stage_per_scenario_in_order(self) -> None:
        self.assertEqual(_STAGE_IDS, [stage.id for stage in self.playbook.stages])

    def test_each_stage_restarts_its_daemon_without_ixia_toggle(self) -> None:
        self.assertEqual(
            [("FibAgentBgp", "disable"), ("FibAgentBgp", "enable")],
            _daemon_actions(self.stages["s1_fibagent_bgp_restart"]),
        )
        self.assertEqual(
            [("Bgpcpp", "disable"), ("Bgpcpp", "enable")],
            _daemon_actions(self.stages["s3_bgpcpp_restart"]),
        )
        for stage in self.playbook.stages:
            self.assertFalse(
                any(
                    "Toggle all device groups" in (step.description or "")
                    for step in stage.steps
                ),
                stage.id,
            )

    def test_fibagent_bgp_stage_waits_for_fibagent_before_checks(self) -> None:
        self.assertIn(
            "wait_for_fibagent_bgp_ready",
            _custom_step_names(self.stages["s1_fibagent_bgp_restart"]),
        )
        self.assertNotIn(
            "wait_for_fibagent_bgp_ready",
            _custom_step_names(self.stages["s3_bgpcpp_restart"]),
        )
        self.assertIn(
            "test_bgp_lifecycle_convergence",
            _custom_step_names(self.stages["s3_bgpcpp_restart"]),
        )

    def test_each_stage_ends_with_ebb01_postchecks(self) -> None:
        playbook_check_names = sorted(
            check.name for check in self.playbook.postchecks or []
        )
        for stage_id in _STAGE_IDS:
            checks = _stage_checks(self.stages[stage_id])
            self.assertEqual(
                playbook_check_names, sorted(check.name for check in checks)
            )
            self.assertIn(
                hc_types.CheckName.BGP_RIB_FIB_CONSISTENCY_CHECK,
                [check.name for check in checks],
            )
            self.assertTrue(
                all(
                    (check.check_id or "").startswith(f"{stage_id}_")
                    for check in checks
                )
            )

    def test_log_checks_scan_only_their_stage(self) -> None:
        s1_checks = _stage_checks(self.stages["s1_fibagent_bgp_restart"])
        s3_checks = _stage_checks(self.stages["s3_bgpcpp_restart"])
        for suffix in ("system_level_log_check", "bgp_time_bound_check"):
            self.assertEqual(
                {"start_time": ".test_case_start_time"},
                dict(
                    _jq_params(_check(s1_checks, f"s1_fibagent_bgp_restart_{suffix}"))
                ),
            )
            self.assertEqual(
                {"start_time": ".s3_bgpcpp_restart_start_time"},
                dict(_jq_params(_check(s3_checks, f"s3_bgpcpp_restart_{suffix}"))),
            )
        first_step = _json_params(self.stages["s3_bgpcpp_restart"].steps[0])
        self.assertEqual("record_jq_timestamp", first_step["custom_step_name"])
        self.assertEqual("s3_bgpcpp_restart_start_time", first_step["var_name"])

    def test_playbook_log_checks_keep_the_full_window(self) -> None:
        for check_id in ("system_level_log_check", "bgp_time_bound_check"):
            self.assertEqual(
                {
                    "start_time": ".test_case_start_time",
                    "end_time": ".test_case_end_time",
                },
                dict(
                    _jq_params(_check(list(self.playbook.postchecks or []), check_id))
                ),
            )

    def test_snapshot_checks_close_at_every_stage_end(self) -> None:
        post_checkpoints = [
            (check.name, check.post_snapshot_checkpoint_id)
            for check in self.playbook.snapshot_checks or []
        ]
        for checkpoint in [None, *(f"stage.{stage_id}.end" for stage_id in _STAGE_IDS)]:
            self.assertIn(
                (hc_types.CheckName.CORE_DUMPS_CHECK, checkpoint), post_checkpoints
            )
            self.assertIn(
                (hc_types.CheckName.BGP_SESSION_CHECK, checkpoint), post_checkpoints
            )
        self.assertTrue(
            all(
                check.pre_snapshot_checkpoint_id is None
                for check in self.playbook.snapshot_checks or []
            )
        )

    def test_every_service_restart_check_accepts_both_daemons(self) -> None:
        checks = list(self.playbook.postchecks or []) + [
            check
            for stage_id in _STAGE_IDS
            for check in _stage_checks(self.stages[stage_id])
        ]
        restart_checks = [
            check
            for check in checks
            if check.name == hc_types.CheckName.SERVICE_RESTART_CHECK
        ]
        self.assertEqual(3, len(restart_checks))
        for check in restart_checks:
            self.assertEqual(["Bgpcpp", "FibAgentBgp"], _expected_restarts(check))

    def test_scheduled_ebb01_keeps_single_bgpcpp_restart(self) -> None:
        playbook = _playbook(cicd_ebb_int_tc.NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_UG)
        self.assertEqual(1, len(playbook.stages))
        self.assertEqual(
            [("Bgpcpp", "disable"), ("Bgpcpp", "enable")],
            _daemon_actions(playbook.stages[0]),
        )
        restart_check = next(
            check
            for check in playbook.postchecks or []
            if check.name == hc_types.CheckName.SERVICE_RESTART_CHECK
        )
        self.assertEqual(["Bgpcpp"], _expected_restarts(restart_check))
        self.assertTrue(
            all(
                check.post_snapshot_checkpoint_id is None
                for check in playbook.snapshot_checks or []
            )
        )

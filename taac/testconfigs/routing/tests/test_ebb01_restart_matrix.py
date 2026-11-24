# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

import json
import typing as t
import unittest

from taac.playbooks.routing.bgp_ebb_playbooks import (
    get_bgp_ebb_daemon_restart_playbook,
)
from taac.testconfigs.routing import cicd_ebb_int_tc
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
_NIGHTLY_UG = cicd_ebb_int_tc.NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_UG
_STAGE_IDS = [
    "s1_fibagent_bgp_restart",
    "s2_fibagent_bgp_repeated_restart",
    "s3_bgpcpp_restart",
    "s4_bgpcpp_repeated_restart",
    "s5_fibagent_bgp_then_bgpcpp_restart",
    "s6_bgpcpp_then_fibagent_bgp_restart",
]
_FIBAGENT_BGP_RESTART = [
    "identity:record",
    "FibAgentBgp:disable",
    "FibAgentBgp:enable",
    "test_bgp_lifecycle_convergence",
    "wait_for_fibagent_bgp_ready",
    "identity:verify",
]
_BGPCPP_RESTART = [
    "identity:record",
    "Bgpcpp:disable",
    "Bgpcpp:enable",
    "test_bgp_lifecycle_convergence",
    "identity:verify",
]
# (restarted, kept) daemons of each record/verify block, in stage order.
_IDENTITY_BLOCKS = {
    "s1_fibagent_bgp_restart": [(["FibAgentBgp"], ["Bgpcpp"])],
    "s2_fibagent_bgp_repeated_restart": [(["FibAgentBgp"], ["Bgpcpp"])] * 3,
    "s3_bgpcpp_restart": [(["Bgpcpp"], ["FibAgentBgp"])],
    "s4_bgpcpp_repeated_restart": [(["Bgpcpp"], ["FibAgentBgp"])] * 3,
    "s5_fibagent_bgp_then_bgpcpp_restart": [(["FibAgentBgp", "Bgpcpp"], [])],
    "s6_bgpcpp_then_fibagent_bgp_restart": [(["Bgpcpp", "FibAgentBgp"], [])],
}


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


def _restart_events(stage: Stage) -> list[str]:
    """Daemon actions, recovery waits and PID/memory checks in step order."""
    events = []
    for step in stage.steps:
        actions = _daemon_actions(Stage(steps=[step]))
        if actions:
            events.extend(f"{daemon}:{action}" for daemon, action in actions)
            continue
        params = _json_params(step)
        name = params.get("custom_step_name")
        if name in ("test_bgp_lifecycle_convergence", "wait_for_fibagent_bgp_ready"):
            events.append(name)
        elif name == "verify_daemon_identity":
            events.append(f"identity:{params['action']}")
    return events


def _identity_steps(stage: Stage) -> list[dict[str, t.Any]]:
    return [
        params
        for params in map(_json_params, stage.steps)
        if params.get("custom_step_name") == "verify_daemon_identity"
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


class Ebb01RestartMatrixTest(unittest.TestCase):
    def setUp(self) -> None:
        self.playbook = _playbook(_NIGHTLY_UG)
        self.stages = {stage.id: stage for stage in self.playbook.stages}

    def test_nightly_ug_config_runs_the_matrix_on_nrqeb006(self) -> None:
        config = _NIGHTLY_UG
        self.assertEqual("NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_UG", config.name)
        self.assertIn(_PLAYBOOK, [playbook.name for playbook in config.playbooks])
        self.assertEqual(
            ["nrqeb006.ash6"],
            [endpoint.name for endpoint in config.endpoints if endpoint.dut],
        )

    def test_one_stage_per_scenario_in_order(self) -> None:
        self.assertEqual(_STAGE_IDS, [stage.id for stage in self.playbook.stages])

    def test_restart_sequences(self) -> None:
        self.assertEqual(
            {
                "s1_fibagent_bgp_restart": _FIBAGENT_BGP_RESTART,
                "s2_fibagent_bgp_repeated_restart": _FIBAGENT_BGP_RESTART * 3,
                "s3_bgpcpp_restart": _BGPCPP_RESTART,
                "s4_bgpcpp_repeated_restart": _BGPCPP_RESTART * 3,
                "s5_fibagent_bgp_then_bgpcpp_restart": [
                    "identity:record",
                    "FibAgentBgp:disable",
                    "FibAgentBgp:enable",
                    "Bgpcpp:disable",
                    "Bgpcpp:enable",
                    "test_bgp_lifecycle_convergence",
                    "wait_for_fibagent_bgp_ready",
                    "identity:verify",
                ],
                "s6_bgpcpp_then_fibagent_bgp_restart": [
                    "identity:record",
                    "Bgpcpp:disable",
                    "Bgpcpp:enable",
                    "FibAgentBgp:disable",
                    "FibAgentBgp:enable",
                    "test_bgp_lifecycle_convergence",
                    "wait_for_fibagent_bgp_ready",
                    "identity:verify",
                ],
            },
            {
                stage_id: _restart_events(self.stages[stage_id])
                for stage_id in _STAGE_IDS
            },
        )

    def test_sequence_stages_start_the_second_restart_without_a_gap(self) -> None:
        for stage_id in (
            "s5_fibagent_bgp_then_bgpcpp_restart",
            "s6_bgpcpp_then_fibagent_bgp_restart",
        ):
            steps = self.stages[stage_id].steps
            actions = [_daemon_actions(Stage(steps=[step])) for step in steps]
            first_enable = next(
                index
                for index, action in enumerate(actions)
                if action and action[0][1] == "enable"
            )
            second_disable = next(
                index
                for index, action in enumerate(actions)
                if index > first_enable and action and action[0][1] == "disable"
            )
            waits = [
                _json_params(step)["duration"]
                for step in steps[first_enable + 1 : second_disable]
                if "duration" in _json_params(step)
            ]
            self.assertEqual([0], waits, stage_id)

    def test_repeat_count_sets_restarts_in_repeated_stages(self) -> None:
        playbook = get_bgp_ebb_daemon_restart_playbook(
            device_name="dut.example.com",
            peergroup_ibgp_v6="PG_IBGP_V6",
            peergroup_ibgp_v4="PG_IBGP_V4",
            expected_established_sessions=4,
            enable_restart_matrix=True,
            restart_matrix_repeat_count=2,
        )
        stages = {stage.id: stage for stage in playbook.stages}
        self.assertEqual(
            _FIBAGENT_BGP_RESTART * 2,
            _restart_events(stages["s2_fibagent_bgp_repeated_restart"]),
        )
        self.assertEqual(
            _BGPCPP_RESTART * 2, _restart_events(stages["s4_bgpcpp_repeated_restart"])
        )
        with self.assertRaises(ValueError):
            get_bgp_ebb_daemon_restart_playbook(
                device_name="dut.example.com",
                peergroup_ibgp_v6="PG_IBGP_V6",
                peergroup_ibgp_v4="PG_IBGP_V4",
                expected_established_sessions=4,
                enable_restart_matrix=True,
                restart_matrix_repeat_count=0,
            )

    def test_no_stage_retoggles_ixia(self) -> None:
        for stage in self.playbook.stages:
            self.assertFalse(
                any(
                    "Toggle all device groups" in (step.description or "")
                    for step in stage.steps
                ),
                stage.id,
            )

    def test_each_stage_ends_with_ebb01_postchecks(self) -> None:
        playbook_check_names = sorted(
            check.name for check in self.playbook.postchecks or []
        )
        self.assertNotIn(hc_types.CheckName.RSS_DELTA_CHECK, playbook_check_names)
        for stage_id in _STAGE_IDS:
            checks = _stage_checks(self.stages[stage_id])
            self.assertEqual(
                playbook_check_names,
                sorted(
                    check.name
                    for check in checks
                    if check.name != hc_types.CheckName.RSS_DELTA_CHECK
                ),
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

    def test_each_restart_verifies_pids_then_gates_memory(self) -> None:
        for stage_id, blocks in _IDENTITY_BLOCKS.items():
            identity = _identity_steps(self.stages[stage_id])
            self.assertEqual(
                ["record", "verify"] * len(blocks),
                [params["action"] for params in identity],
                stage_id,
            )
            expected_checks = {}
            for index, (restarted, kept) in enumerate(blocks):
                record, verify = identity[2 * index : 2 * index + 2]
                for params in (record, verify):
                    self.assertEqual(restarted, params["restarted_daemons"])
                    self.assertEqual(kept, params["unchanged_daemons"])
                self.assertEqual(record["record_jq_var"], verify["record_jq_var"])
                for daemon in restarted:
                    check_id = (
                        f"{stage_id}_restart{index + 1}_{daemon.lower()}"
                        "_rss_delta_check"
                    )
                    expected_checks[check_id] = (
                        daemon,
                        verify["rss_summary_jq_vars"][daemon],
                    )
            rss_checks: dict[str, PointInTimeHealthCheck] = {}
            for check in _stage_checks(self.stages[stage_id]):
                if check.name == hc_types.CheckName.RSS_DELTA_CHECK:
                    assert check.check_id is not None
                    rss_checks[check.check_id] = check
            self.assertEqual(sorted(expected_checks), sorted(rss_checks), stage_id)
            for check_id, (daemon, summary_var) in expected_checks.items():
                params = rss_checks[check_id].check_params
                assert params is not None
                self.assertEqual(
                    {
                        "max_growth_pct": 10.0,
                        "daemon_name": daemon,
                        "restart_expected": True,
                    },
                    json.loads(params.json_params or "{}"),
                )
                self.assertEqual(
                    {"summary": f".{summary_var}"},
                    dict(_jq_params(rss_checks[check_id])),
                )

    def test_every_restart_observes_resources(self) -> None:
        for stage_id in _IDENTITY_BLOCKS:
            identity = _identity_steps(self.stages[stage_id])
            self.assertTrue(identity, stage_id)
            for params in identity:
                self.assertTrue(params["observe_resources"], stage_id)
                if params["action"] == "verify":
                    self.assertEqual(2, params["resource_max_delta"])
                    self.assertEqual(180.0, params["resource_observe_seconds"])

    def test_log_checks_scan_only_their_stage(self) -> None:
        for index, stage_id in enumerate(_STAGE_IDS):
            start_var = (
                "test_case_start_time" if index == 0 else f"{stage_id}_start_time"
            )
            checks = _stage_checks(self.stages[stage_id])
            for suffix in ("system_level_log_check", "bgp_time_bound_check"):
                self.assertEqual(
                    {"start_time": f".{start_var}"},
                    dict(_jq_params(_check(checks, f"{stage_id}_{suffix}"))),
                )
            first_step = _json_params(self.stages[stage_id].steps[0])
            if index == 0:
                self.assertNotEqual(
                    "record_jq_timestamp", first_step.get("custom_step_name")
                )
            else:
                self.assertEqual("record_jq_timestamp", first_step["custom_step_name"])
                self.assertEqual(start_var, first_step["var_name"])

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
        self.assertEqual(1 + len(_STAGE_IDS), len(restart_checks))
        for check in restart_checks:
            self.assertEqual(["Bgpcpp", "FibAgentBgp"], _expected_restarts(check))

    def test_nightly_non_ug_ebb01_keeps_single_bgpcpp_restart(self) -> None:
        playbook = _playbook(
            cicd_ebb_int_tc.NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_NO_UG
        )
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

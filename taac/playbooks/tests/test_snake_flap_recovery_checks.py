#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

"""Pins the opt-in retries on the snake flap-recovery MID_TEST checks.

LLDP neighbors can only reappear after the port is back up, so when a config
opts into ``flap_recovery_check_retry_count`` the LLDP check must retry on the
same schedule as the port-state check. Configs that don't opt in keep both
checks single-shot.
"""

import json
import typing as t
import unittest

from taac.playbooks.playbook_definitions import (
    gen_snake_playbooks,
)
from taac.utils.json_thrift_utils import json_to_thrift
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types

_FLAP_RECOVERY_PLAYBOOKS = (
    "test_snake_link_flap_with_longevity",
    "test_snake_rapid_a_end_flap_stress",
)


def _mid_test_checks(
    playbook: taac_types.Playbook,
) -> t.Dict[hc_types.CheckName, t.Optional[t.Dict[str, t.Any]]]:
    """Return {check name: json_params} for the playbook's MID_TEST validation."""
    for stage in playbook.stages or []:
        for step in stage.steps or []:
            if step.name != taac_types.StepName.VALIDATION_STEP:
                continue
            if step.input_json is None:
                raise AssertionError("validation step has no typed input")
            validation = json_to_thrift(step.input_json, taac_types.ValidationInput)
            if validation.stage != taac_types.ValidationStage.MID_TEST:
                continue
            return {
                check.name: (
                    json.loads(check.check_params.json_params)
                    if check.check_params is not None
                    and check.check_params.json_params is not None
                    else None
                )
                for check in validation.point_in_time_checks or []
            }
    raise AssertionError(f"{playbook.name} has no MID_TEST validation step")


def _flap_recovery_playbooks(**kwargs: t.Any) -> t.Dict[str, taac_types.Playbook]:
    playbooks = gen_snake_playbooks(
        hostname="dut1",
        iteration=1,
        include_link_flap_longevity=True,
        include_rapid_a_end_flap_stress=True,
        **kwargs,
    )
    return {pb.name: pb for pb in playbooks if pb.name in _FLAP_RECOVERY_PLAYBOOKS}


class SnakeFlapRecoveryChecksTest(unittest.TestCase):
    def test_lldp_check_retries_like_port_state_when_opted_in(self) -> None:
        playbooks = _flap_recovery_playbooks(
            flap_recovery_check_retry_count=6,
            flap_recovery_check_retry_delay_seconds=10.0,
        )
        self.assertCountEqual(playbooks, _FLAP_RECOVERY_PLAYBOOKS)
        expected = {
            "retry_count": 6,
            "retry_delay_seconds": 10.0,
            "retry_delay_multiplier": 1.0,
        }
        for name, playbook in playbooks.items():
            with self.subTest(playbook=name):
                checks = _mid_test_checks(playbook)
                self.assertEqual(checks[hc_types.CheckName.PORT_STATE_CHECK], expected)
                self.assertEqual(checks[hc_types.CheckName.LLDP_CHECK], expected)

    def test_checks_stay_single_shot_by_default(self) -> None:
        playbooks = _flap_recovery_playbooks()
        self.assertCountEqual(playbooks, _FLAP_RECOVERY_PLAYBOOKS)
        for name, playbook in playbooks.items():
            with self.subTest(playbook=name):
                checks = _mid_test_checks(playbook)
                self.assertIsNone(checks[hc_types.CheckName.PORT_STATE_CHECK])
                self.assertIsNone(checks[hc_types.CheckName.LLDP_CHECK])

    def test_skip_lldp_check_still_honored(self) -> None:
        playbooks = _flap_recovery_playbooks(
            flap_recovery_check_retry_count=6, skip_lldp_check=True
        )
        for name, playbook in playbooks.items():
            with self.subTest(playbook=name):
                self.assertNotIn(
                    hc_types.CheckName.LLDP_CHECK, _mid_test_checks(playbook)
                )

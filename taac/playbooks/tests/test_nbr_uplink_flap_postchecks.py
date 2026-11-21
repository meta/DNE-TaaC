# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""The neighbour-uplink-flap playbooks restart a service and kill every path
through the neighbour on purpose. Their postchecks must not fail on that."""

import json
import unittest

from taac.health_check.health_check import types as hc_types
from taac.health_checks.constants import (
    SERVICES_EXPECTED_TO_RESTART_DURING_AGENT_WARMBOOT,
)
from taac.health_checks.healthcheck_definitions import (
    create_systemctl_active_state_check,
)
from taac.playbooks.playbook_definitions import (
    BGP_RESTART_SERVICE_CHECK,
    create_gtsw_service_restart_nbr_uplink_flap_playbook,
    create_gtsw_warmboot_nbr_uplink_flap_playbook,
)
from taac.test_as_a_config import types as taac_types
from taac.utils.json_thrift_utils import thrift_to_json


def _systemctl_params(playbook) -> dict:
    checks = [
        c
        for c in playbook.postchecks
        if c.name == hc_types.CheckName.SYSTEMCTL_ACTIVE_STATE_CHECK
    ]
    assert len(checks) == 1, checks
    return json.loads(checks[0].check_params.json_params)


def _systemctl_allowlist(playbook) -> list:
    return _systemctl_params(playbook)["expected_restarted_services"]


def _stage(playbook, stage_id: str):
    matches = [s for s in playbook.stages if s.id == stage_id]
    assert len(matches) == 1, [s.id for s in playbook.stages]
    return matches[0]


def _longevity_step_names(playbook) -> list:
    return [s.name for s in _stage(playbook, "longevity").steps]


def _first_ixia_api_call(playbook) -> str:
    step = _stage(playbook, "longevity").steps[0]
    return json.loads(step.step_params.json_params)["api_name"]


def _mid_test_checks(playbook, stage_id: str) -> list:
    validation = _stage(playbook, stage_id).steps[-1]
    assert validation.name == taac_types.StepName.VALIDATION_STEP, validation.name
    return json.loads(validation.input_json)["point_in_time_checks"]


def _serialized(check) -> dict:
    return json.loads(thrift_to_json(check))


class WarmbootNbrFlapPostchecksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.playbook = create_gtsw_warmboot_nbr_uplink_flap_playbook(
            nbr_device_name="nbr001",
            nbr_uplink_neighbor_pattern="nbr*",
        )

    def test_systemctl_check_tolerates_the_warmboot(self) -> None:
        self.assertEqual(
            _systemctl_allowlist(self.playbook),
            list(SERVICES_EXPECTED_TO_RESTART_DURING_AGENT_WARMBOOT),
        )
        self.assertEqual(_systemctl_params(self.playbook)["retry_count"], 3)

    def test_warmboot_allowlist_excludes_services_that_must_stay_up(self) -> None:
        self.assertFalse(
            {"fsdb", "qsfp_service", "coop"} & set(_systemctl_allowlist(self.playbook))
        )

    def test_mid_test_systemctl_check_tolerates_the_warmboot(self) -> None:
        expected = create_systemctl_active_state_check(
            expected_restarted_services=list(
                SERVICES_EXPECTED_TO_RESTART_DURING_AGENT_WARMBOOT
            ),
            retry_count=3,
            retry_delay_seconds=10,
            retry_delay_multiplier=1.0,
        )
        self.assertIn(_serialized(expected), _mid_test_checks(self.playbook, "warmboot_nbr_flap"))

    def test_loss_is_measured_after_the_flap_has_converged(self) -> None:
        names = _longevity_step_names(self.playbook)
        self.assertLess(
            names.index(taac_types.StepName.INVOKE_IXIA_API_STEP),
            names.index(taac_types.StepName.LONGEVITY_STEP),
        )
        self.assertEqual(_first_ixia_api_call(self.playbook), "clear_traffic_stats")



class ServiceRestartNbrFlapPostchecksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.playbook = create_gtsw_service_restart_nbr_uplink_flap_playbook(
            nbr_device_name="nbr001",
            playbook_name="test_bgp_restart_nbr_uplink_flap",
            service=taac_types.Service.BGP,
            restart_service_check=BGP_RESTART_SERVICE_CHECK,
            convergence_services=[taac_types.Service.BGP, taac_types.Service.AGENT],
            service_label="bgpd",
            nbr_uplink_neighbor_pattern="nbr*",
        )

    def test_systemctl_check_tolerates_the_restarted_service(self) -> None:
        self.assertEqual(_systemctl_allowlist(self.playbook), ["bgpd"])
        self.assertEqual(_systemctl_params(self.playbook)["retry_count"], 3)

    def test_mid_test_systemctl_check_tolerates_the_restarted_service(self) -> None:
        expected = create_systemctl_active_state_check(
            expected_restarted_services=["bgpd"],
            retry_count=3,
            retry_delay_seconds=10,
            retry_delay_multiplier=1.0,
        )
        self.assertIn(_serialized(expected), _mid_test_checks(self.playbook, "service_restart_nbr_flap"))

    def test_loss_is_measured_after_the_flap_has_converged(self) -> None:
        names = _longevity_step_names(self.playbook)
        self.assertLess(
            names.index(taac_types.StepName.INVOKE_IXIA_API_STEP),
            names.index(taac_types.StepName.LONGEVITY_STEP),
        )
        self.assertEqual(_first_ixia_api_call(self.playbook), "clear_traffic_stats")


if __name__ == "__main__":
    unittest.main()

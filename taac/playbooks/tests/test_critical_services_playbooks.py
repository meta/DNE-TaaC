# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

import json
import unittest

from taac.playbooks.playbook_definitions import (
    create_qsfp_service_warmboot_and_reset_playbook,
    get_critical_services_single_box_playbooks,
)
from taac.test_as_a_config import types as taac_types


_INTERFACES = ["eth1/3/1", "eth1/4/1"]


def _params(step: taac_types.Step) -> taac_types.Params:
    if step.step_params is None:
        raise AssertionError(f"Step has no params: {step}")
    return step.step_params


def _step_params(step: taac_types.Step) -> dict[str, object]:
    return json.loads(_params(step).json_params or "{}")


class CriticalServicesPlaybooksTest(unittest.TestCase):
    def test_reset_scopes_disruption_to_explicit_interfaces(self) -> None:
        playbook = create_qsfp_service_warmboot_and_reset_playbook(
            iteration=1,
            interfaces=_INTERFACES,
        )

        reset = next(
            step
            for step in playbook.stages[0].steps
            if step.name == taac_types.StepName.INTERFACE_FLAP_STEP
        )
        self.assertEqual(_INTERFACES, _step_params(reset)["interfaces"])
        self.assertIsNone(_params(reset).jq_params)

    def test_reset_rejects_an_explicit_empty_interface_list(self) -> None:
        with self.assertRaisesRegex(ValueError, "interfaces.*empty list"):
            create_qsfp_service_warmboot_and_reset_playbook(interfaces=[])

    def test_single_box_factory_forwards_settle_and_interfaces(self) -> None:
        playbooks = get_critical_services_single_box_playbooks(
            iteration=1,
            agent_post_restart_settle_seconds=60,
            interfaces=_INTERFACES,
        )

        self.assertEqual(23, len(playbooks))
        agent_warmboot = playbooks[0]
        settle = agent_warmboot.stages[0].steps[-1]
        self.assertEqual(taac_types.StepName.LONGEVITY_STEP, settle.name)
        self.assertEqual(60, _step_params(settle)["duration"])

        for name in (
            "test_qsfp_service_warmboot_and_tx_flap",
            "test_qsfp_service_warmboot_and_reset",
        ):
            with self.subTest(playbook=name):
                playbook = next(pb for pb in playbooks if pb.name == name)
                flap_steps = [
                    step
                    for step in playbook.stages[0].steps
                    if step.name == taac_types.StepName.INTERFACE_FLAP_STEP
                ]
                self.assertTrue(flap_steps)
                self.assertTrue(
                    all(
                        _step_params(step)["interfaces"] == _INTERFACES
                        for step in flap_steps
                    )
                )
                self.assertTrue(
                    all(_params(step).jq_params is None for step in flap_steps)
                )

    def test_single_box_factory_preserves_default_behavior(self) -> None:
        playbooks = get_critical_services_single_box_playbooks(iteration=1)

        self.assertEqual(23, len(playbooks))
        agent_steps = playbooks[0].stages[0].steps
        self.assertNotEqual(taac_types.StepName.LONGEVITY_STEP, agent_steps[-1].name)
        for name in (
            "test_qsfp_service_warmboot_and_tx_flap",
            "test_qsfp_service_warmboot_and_reset",
        ):
            with self.subTest(playbook=name):
                playbook = next(pb for pb in playbooks if pb.name == name)
                flap_steps = [
                    step
                    for step in playbook.stages[0].steps
                    if step.name == taac_types.StepName.INTERFACE_FLAP_STEP
                ]
                self.assertTrue(flap_steps)
                self.assertTrue(
                    all(
                        _params(step).jq_params == {"interfaces": '."{dut}".interfaces'}
                        for step in flap_steps
                    )
                )

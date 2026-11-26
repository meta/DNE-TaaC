#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Every snake MID_TEST check that fires right after an interface re-enable
must honour ``flap_recovery_check_retry_count``.

Those validations run 0-2 s after the enable step, while slow-training optics
are still linking. Without retries PORT_STATE_CHECK fails on a single read and
LLDP_CHECK -- which raises on a mismatch and only has a ~16 s internal retry --
surfaces as ERROR.
"""

import json
import typing as t
import unittest

from taac.health_check.health_check import types as hc_types
from taac.playbooks.playbook_definitions import gen_snake_playbooks
from taac.test_as_a_config import types as taac_types

FLAP_PLAYBOOKS = {
    "test_snake_half_interface_toggle_with_thrift_api",
    "test_snake_link_flap_with_longevity",
    "test_snake_rapid_a_end_flap_stress",
}
RETRIED_CHECKS = {
    hc_types.CheckName.PORT_STATE_CHECK.value,
    hc_types.CheckName.LLDP_CHECK.value,
}


def _mid_test_checks(playbook) -> t.List[t.Dict[str, t.Any]]:
    out = []
    for stage in playbook.stages:
        for step in stage.steps:
            if step.name != taac_types.StepName.VALIDATION_STEP or not step.input_json:
                continue
            payload = json.loads(step.input_json)
            if payload.get("stage") != taac_types.ValidationStage.MID_TEST.value:
                continue
            out.extend(payload["point_in_time_checks"])
    return out


def _retry_payload(check: t.Dict[str, t.Any]) -> t.Optional[t.Dict[str, t.Any]]:
    raw = (check.get("check_params") or {}).get("json_params")
    if raw is None:
        return None
    params = json.loads(raw)
    return {k: v for k, v in params.items() if k.startswith("retry_")} or None


class SnakeFlapRecoveryRetryTest(unittest.TestCase):
    def _flap_playbooks(self, **kwargs):
        pbs = gen_snake_playbooks(
            hostname="dut01",
            iteration=1,
            include_link_flap_longevity=True,
            include_rapid_a_end_flap_stress=True,
            **kwargs,
        )
        found = [pb for pb in pbs if pb.name in FLAP_PLAYBOOKS]
        self.assertEqual({pb.name for pb in found}, FLAP_PLAYBOOKS)
        return found

    def test_retry_applies_to_port_state_and_lldp(self) -> None:
        for pb in self._flap_playbooks(
            flap_recovery_check_retry_count=6,
            flap_recovery_check_retry_delay_seconds=10.0,
        ):
            checks = [c for c in _mid_test_checks(pb) if c["name"] in RETRIED_CHECKS]
            self.assertTrue(checks, pb.name)
            self.assertIn(
                hc_types.CheckName.LLDP_CHECK.value,
                {c["name"] for c in checks},
                pb.name,
            )
            for check in checks:
                self.assertEqual(
                    _retry_payload(check),
                    {
                        "retry_count": 6,
                        "retry_delay_seconds": 10.0,
                        "retry_delay_multiplier": 1.0,
                    },
                    f"{pb.name}: {check}",
                )

    def test_unset_keeps_checks_single_shot(self) -> None:
        for pb in self._flap_playbooks():
            for check in _mid_test_checks(pb):
                if check["name"] in RETRIED_CHECKS:
                    self.assertIsNone(_retry_payload(check), f"{pb.name}: {check}")


if __name__ == "__main__":
    unittest.main()

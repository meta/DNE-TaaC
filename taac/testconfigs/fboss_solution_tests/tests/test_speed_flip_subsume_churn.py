# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""The subsume churn playbook."""

import json
import unittest
from unittest.mock import patch

from taac.testconfigs.fboss_solution_tests import speed_flip_test_configs as sf


BASELINE = 400
TARGET = 800


def _circuits():
    return [
        sf.Circuit("dut", f"eth1/{cage}/{sub}", "peer", f"eth1/{cage}/{sub}")
        for cage in (1, 2, 3)
        for sub in (1, 5)
    ]


class SubsumeChurnTest(unittest.TestCase):
    def _build(self, churn_iterations=1, taac_oss=False):
        with patch.object(sf, "TAAC_OSS", taac_oss):
            return sf.build_speed_flip_subsume_churn_playbook(
                "churn", _circuits(), BASELINE, TARGET, churn_iterations
            )

    def _primary_speeds(self, churn_iterations):
        validations = []
        real = sf.get_validation_step

        def record(params):
            validations.append(params)
            return real(params)

        with patch.object(sf, "get_validation_step", record):
            self._build(churn_iterations)
        # The first validation is the precheck and the last is the restore stage.
        return [
            {i["interface_name"]: i["expected_speed"] for i in v["dut"]["interfaces"]}
            for v in validations[1:-1]
        ]

    def test_missing_mate_is_skipped_only_in_oss(self):
        for taac_oss in (True, False):
            playbook = self._build(taac_oss=taac_oss)
            params = [
                json.loads(step.step_params.json_params)
                for stage in playbook.stages
                for step in stage.steps
                if step.step_params
                and "fpf_set_interface_admin" in step.step_params.json_params
            ]
            self.assertEqual([p["is_enable"] for p in params], [False, True])
            for step_params in params:
                self.assertEqual(step_params.get("skip_missing", False), taac_oss)

    def test_primary_speed_follows_the_patchers_that_stay_registered(self):
        up = {"eth1/1/1": TARGET, "eth1/2/1": TARGET, "eth1/3/1": TARGET}
        cage_1_base = {**up, "eth1/1/1": BASELINE}
        base = {port: BASELINE for port in up}
        first_cycle = [up, up, cage_1_base, base, up, up, up]
        second_cycle = [base, base, up, up, up]
        self.assertEqual(self._primary_speeds(1), first_cycle)
        self.assertEqual(self._primary_speeds(2), first_cycle + second_cycle)


if __name__ == "__main__":
    unittest.main()

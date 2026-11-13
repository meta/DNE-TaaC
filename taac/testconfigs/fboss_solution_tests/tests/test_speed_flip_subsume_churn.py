# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""The subsume churn playbook."""

import json
import unittest
from unittest.mock import patch

from taac.testconfigs.fboss_solution_tests import speed_flip_test_configs as sf


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
                "churn", _circuits(), 400, 800, churn_iterations
            )

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
            self.assertEqual(len(params), 1)
            self.assertEqual(params[0].get("skip_missing", False), taac_oss)


if __name__ == "__main__":
    unittest.main()

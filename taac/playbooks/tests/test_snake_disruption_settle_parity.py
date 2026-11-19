#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Parity invariants for every snake playbook that interrupts a service.

Each such playbook must (a) wait for convergence of the service it just
disrupted and (b) settle before its postchecks run; otherwise the postchecks
sample while the service is still coming up.

Enforced as parity across the whole family rather than per playbook: adding a
new disruption playbook without both fails here.
"""

import json
import typing as t
import unittest

from taac.playbooks.playbook_definitions import gen_snake_playbooks
from taac.test_as_a_config import types as taac_types


def _steps(playbook) -> t.List[t.Any]:
    return [step for stage in playbook.stages for step in stage.steps]


def _interrupted_service(step) -> taac_types.Service:
    """The service a SERVICE_INTERRUPTION_STEP disrupts."""
    payload = json.loads(step.input_json)
    return taac_types.Service(payload["name"])


def _converged_services(step) -> t.List[taac_types.Service]:
    payload = json.loads(step.input_json)
    return [taac_types.Service(s) for s in payload["services"]]


class SnakeDisruptionSettleParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.playbooks = gen_snake_playbooks(hostname="dut01", iteration=1)
        cls.disruptive = [
            pb
            for pb in cls.playbooks
            if any(
                s.name == taac_types.StepName.SERVICE_INTERRUPTION_STEP
                for s in _steps(pb)
            )
        ]

    def test_the_family_is_discovered(self) -> None:
        """Guards the discovery itself: if the step name or generator shape
        changes, every other test here would vacuously pass on an empty list."""
        self.assertGreaterEqual(len(self.disruptive), 5)

    def test_convergence_covers_the_interrupted_service(self) -> None:
        for pb in self.disruptive:
            with self.subTest(playbook=pb.name):
                steps = _steps(pb)
                interrupted = [
                    _interrupted_service(s)
                    for s in steps
                    if s.name == taac_types.StepName.SERVICE_INTERRUPTION_STEP
                ]
                converged: t.Set[taac_types.Service] = set()
                for s in steps:
                    if s.name == taac_types.StepName.SERVICE_CONVERGENCE_STEP:
                        converged.update(_converged_services(s))
                for service in interrupted:
                    self.assertIn(
                        service,
                        converged,
                        f"{pb.name} interrupts {service} but never waits for it "
                        f"to converge (waits for {sorted(s.name for s in converged)}). "
                        "Waiting only on an untouched service returns instantly, "
                        "so postchecks sample mid-recovery.",
                    )

    def test_a_settle_step_follows_convergence(self) -> None:
        for pb in self.disruptive:
            with self.subTest(playbook=pb.name):
                names = [s.name for s in _steps(pb)]
                self.assertIn(
                    taac_types.StepName.LONGEVITY_STEP,
                    names,
                    f"{pb.name} has no settle step, so its postchecks can run "
                    "before the service has finished recovering.",
                )
                self.assertLess(
                    names.index(taac_types.StepName.SERVICE_CONVERGENCE_STEP),
                    names.index(taac_types.StepName.LONGEVITY_STEP),
                    f"{pb.name} settles before it converges, which measures the "
                    "wrong window.",
                )

    def test_settle_duration_is_positive(self) -> None:
        for pb in self.disruptive:
            with self.subTest(playbook=pb.name):
                settles = [
                    s
                    for s in _steps(pb)
                    if s.name == taac_types.StepName.LONGEVITY_STEP
                ]
                for settle in settles:
                    duration = json.loads(settle.step_params.json_params)["duration"]
                    self.assertGreater(
                        duration, 0, f"{pb.name} settles for {duration}s"
                    )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Every LAG baseline stage that re-enables members and then expects the
port-channel UP must wait ``link_up_wait_s`` in between.

The members come up in a few seconds, but LACP still has to re-bundle them
before the port-channel reaches MinCapacityToUp, so a check taken right after
the flap step's own short sleep races LACP and intermittently sees DOWN.
"""

import json
import typing as t
import unittest

from taac.playbooks.playbook_definitions import create_lag_baseline_playbook_1
from taac.test_as_a_config import types as taac_types

_LINK_UP_WAIT_S = 30


def _find_key(node: t.Any, key: str) -> t.List[t.Any]:
    """All values of ``key`` anywhere in ``node``, decoding nested JSON strings."""
    if isinstance(node, str):
        try:
            node = json.loads(node)
        except ValueError:
            return []
    if isinstance(node, dict):
        found = [node[key]] if key in node else []
        for value in node.values():
            found.extend(_find_key(value, key))
        return found
    if isinstance(node, list):
        return [v for item in node for v in _find_key(item, key)]
    return []


def _params(step) -> t.Dict[str, t.Any]:
    return json.loads(step.step_params.json_params) if step.step_params else {}


def _is_enable_flap(step) -> bool:
    return (
        step.name == taac_types.StepName.INTERFACE_FLAP_STEP
        and _params(step).get("enable") is True
    )


def _is_link_up_wait(step) -> bool:
    return (
        step.name == taac_types.StepName.LONGEVITY_STEP
        and _params(step).get("duration", 0) >= _LINK_UP_WAIT_S
    )


def _expects_lag_up(step) -> bool:
    if step.name != taac_types.StepName.VALIDATION_STEP or not step.input_json:
        return False
    return True in _find_key(step.input_json, "expected_up")


class LagBaselineLinkUpWaitTest(unittest.TestCase):
    def test_enable_then_expect_up_waits_for_lacp(self) -> None:
        playbook = create_lag_baseline_playbook_1(
            playbook_name="lag_001_baseline_functionality_1",
            member_interfaces=[f"eth1/{i}/1" for i in range(1, 33)],
            min_link_percentage=0.875,
            min_link_up_percentage=0.9375,
            portchannel_name_map={"dut": ["Port-Channel1"]},
            iteration=1,
            link_up_wait_s=_LINK_UP_WAIT_S,
        )
        checked = 0
        for index, stage in enumerate(playbook.stages):
            enabled_without_wait = False
            for step in stage.steps:
                if _is_enable_flap(step):
                    enabled_without_wait = True
                elif _is_link_up_wait(step):
                    enabled_without_wait = False
                elif _expects_lag_up(step) and enabled_without_wait:
                    self.fail(
                        f"stage {index} checks the port-channel UP right after "
                        "re-enabling members, without waiting link_up_wait_s"
                    )
                elif _expects_lag_up(step):
                    checked += 1
        # Guards the step matching itself: a renamed field would pass vacuously.
        self.assertGreaterEqual(checked, 2)

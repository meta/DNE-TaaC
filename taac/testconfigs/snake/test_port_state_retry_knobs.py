#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""``precheck_port_state_retry_count`` / ``postcheck_port_state_retry_count``
each retry only their own stage's PORT_STATE_CHECK *and* LLDP_CHECK, and only
when set.

Both checks read the same recovering links. The qsfp_util playbooks use the
common postchecks, not the flap-recovery helper, so retrying only PORT_STATE
there would leave LLDP to ERROR while its sibling passes on a later attempt.
Prechecks get their own knob so a wedge_agent thrift stall that outlives the
driver-level retry does not surface as ERROR.
"""

import json
import typing as t
import unittest

from taac.health_check.health_check import types as hc_types
from taac.testconfigs.snake.test_test_config import gen_snake_test_config
from taac.test_as_a_config import types as taac_types

RETRY = {"retry_count": 6, "retry_delay_seconds": 10.0, "retry_delay_multiplier": 1.0}


def _config(**kwargs):
    return gen_snake_test_config(
        name="X",
        basset_pool="",
        hostname="h",
        snake_configs=[
            taac_types.SnakeConfig(
                source="h:eth1/1/1",
                destination="h:eth1/2/1",
                source_ip="5000:1::1/64",
                destination_ip="5000:1::2/64",
            )
        ],
        ixia_ports=["eth1/1/1", "eth1/2/1"],
        use_ipv6_ping=False,
        **kwargs,
    )(ptp_configs=[])


def _retry(checks, name) -> t.Optional[t.Dict[str, t.Any]]:
    (check,) = [c for c in checks if c.name == name]
    if check.check_params is None or check.check_params.json_params is None:
        return None
    params = json.loads(check.check_params.json_params)
    return {k: v for k, v in params.items() if k.startswith("retry_")} or None


def _port_state_retry(checks) -> t.Optional[t.Dict[str, t.Any]]:
    return _retry(checks, hc_types.CheckName.PORT_STATE_CHECK)


def _lldp_retry(checks) -> t.Optional[t.Dict[str, t.Any]]:
    return _retry(checks, hc_types.CheckName.LLDP_CHECK)


class PortStateRetryKnobsTest(unittest.TestCase):
    def _playbook(self, cfg, name="test_snake_qsfp_service_crash"):
        return next(pb for pb in cfg.playbooks if pb.name == name)

    def test_unset_is_single_shot_both_stages(self) -> None:
        pb = self._playbook(_config())
        for checks in (pb.prechecks, pb.postchecks):
            self.assertIsNone(_port_state_retry(checks))
            self.assertIsNone(_lldp_retry(checks))

    def test_precheck_knob_only_touches_prechecks(self) -> None:
        pb = self._playbook(_config(precheck_port_state_retry_count=6))
        self.assertEqual(_port_state_retry(pb.prechecks), RETRY)
        self.assertEqual(_lldp_retry(pb.prechecks), RETRY)
        self.assertIsNone(_port_state_retry(pb.postchecks))
        self.assertIsNone(_lldp_retry(pb.postchecks))

    def test_postcheck_knob_only_touches_postchecks(self) -> None:
        pb = self._playbook(_config(postcheck_port_state_retry_count=6))
        self.assertIsNone(_port_state_retry(pb.prechecks))
        self.assertIsNone(_lldp_retry(pb.prechecks))
        self.assertEqual(_port_state_retry(pb.postchecks), RETRY)
        self.assertEqual(_lldp_retry(pb.postchecks), RETRY)

    def test_qsfp_util_disable_postchecks_retry_lldp(self) -> None:
        """Uses the common postchecks, not the flap-recovery helper, so it only
        gets LLDP retry through this knob."""
        pb = self._playbook(
            _config(postcheck_port_state_retry_count=6),
            name="test_snake_interface_toggle_with_qsfp_util_disable",
        )
        self.assertEqual(_lldp_retry(pb.postchecks), RETRY)
        self.assertEqual(_port_state_retry(pb.postchecks), RETRY)

    def test_both_knobs_apply_to_every_playbook(self) -> None:
        cfg = _config(
            precheck_port_state_retry_count=6, postcheck_port_state_retry_count=6
        )
        for pb in cfg.playbooks:
            for checks in (pb.prechecks, pb.postchecks):
                self.assertEqual(_port_state_retry(checks), RETRY, pb.name)
                self.assertEqual(_lldp_retry(checks), RETRY, pb.name)

    def test_retry_survives_precheck_packet_loss_clear_stats(self) -> None:
        """precheck_packet_loss_clear_stats=True together with the precheck
        knob: the packet-loss override must layer on the retry rewrite, not
        rebuild the precheck list from common_hcs."""
        cfg = _config(
            precheck_port_state_retry_count=6,
            postcheck_port_state_retry_count=6,
            precheck_packet_loss_clear_stats=True,
        )
        pb = self._playbook(cfg)
        self.assertEqual(_port_state_retry(pb.prechecks), RETRY)
        self.assertEqual(_lldp_retry(pb.prechecks), RETRY)
        self.assertEqual(_port_state_retry(pb.postchecks), RETRY)
        self.assertEqual(_lldp_retry(pb.postchecks), RETRY)
        (loss,) = [
            c
            for c in pb.prechecks
            if c.name == hc_types.CheckName.IXIA_PACKET_LOSS_CHECK
        ]
        self.assertTrue(json.loads(loss.input_json)["clear_traffic_stats"])

    def test_retry_survives_non_default_packet_loss_sleep_time(self) -> None:
        """Same footgun on the postcheck side, reachable via packet_loss_sleep_time."""
        cfg = _config(
            precheck_port_state_retry_count=6,
            postcheck_port_state_retry_count=6,
            packet_loss_sleep_time=30,
        )
        pb = self._playbook(cfg)
        for checks in (pb.prechecks, pb.postchecks):
            self.assertEqual(_port_state_retry(checks), RETRY)
            self.assertEqual(_lldp_retry(checks), RETRY)
            # Playbooks may append their own IXIA check with the default sleep;
            # the common one must carry the overridden value.
            sleeps = [
                json.loads(c.input_json)["sleep_time"]
                for c in checks
                if c.name == hc_types.CheckName.IXIA_PACKET_LOSS_CHECK
            ]
            self.assertIn(30, sleeps)

    def test_skip_lldp_check_leaves_no_lldp_to_retry(self) -> None:
        pb = self._playbook(
            _config(postcheck_port_state_retry_count=6, skip_lldp_check=True)
        )
        self.assertFalse(
            [c for c in pb.postchecks if c.name == hc_types.CheckName.LLDP_CHECK]
        )
        self.assertEqual(_port_state_retry(pb.postchecks), RETRY)


if __name__ == "__main__":
    unittest.main()

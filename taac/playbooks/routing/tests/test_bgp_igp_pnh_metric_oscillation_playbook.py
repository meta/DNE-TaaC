# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-strict

import json
import unittest

from taac.abstractions.churn.workloads import IgpMetricChurn
from taac.abstractions.topologies.ebb_full_scale import (
    EBB_FY26_SCALE,
    EBB_FY27_SCALE,
)
from taac.constants import (
    BgpPlusPlusProfile,
    DEFAULT_OPENR_START_IPV4S,
    DEFAULT_OPENR_START_IPV6S,
)
from taac.playbooks.routing.bgp_ebb_playbooks import (
    get_bgp_ebb_igp_pnh_metric_oscillation_playbook,
)
from taac.steps.step_definitions import (
    create_igp_metric_churn_step,
    create_validated_igp_pnh_metric_oscillation_step,
)
from taac.test_as_a_config import types as taac_types


def _step_payload(step: taac_types.Step) -> dict:
    params = step.step_params
    if params is None or params.json_params is None:
        raise AssertionError("custom step is missing serialized parameters")
    return json.loads(params.json_params)


class BgpIgpPnhMetricOscillationPlaybookTest(unittest.TestCase):
    def test_typed_step_matches_legacy_payload(self) -> None:
        kwargs = {
            "device_name": "dut.example.com",
            "start_ipv4s": ["20.164.28.10", "20.165.28.10"],
            "start_ipv6s": ["2401:db00:e80d:11:9::10", "2401:db00:e80d:11:10::10"],
            "local_link": {"ifName": "po1", "metric": 10},
            "other_link": {"ifName": "po1", "metric": 20},
            "count": 63,
            "step": 2,
            "duration": 2400,
            "frequency": 30,
        }
        legacy = create_validated_igp_pnh_metric_oscillation_step(**kwargs)
        typed = create_igp_metric_churn_step(
            IgpMetricChurn.create(
                hostname="dut.example.com",
                start_ipv4s=kwargs["start_ipv4s"],
                start_ipv6s=kwargs["start_ipv6s"],
                local_link=kwargs["local_link"],
                other_link=kwargs["other_link"],
                count=63,
                step=2,
                duration=2400,
                frequency=30,
            )
        )

        self.assertEqual(_step_payload(legacy), _step_payload(typed))
        self.assertEqual(legacy.description, typed.description)

    def test_playbook_wires_acknowledged_stage_and_fallback_cleanup(self) -> None:
        local_link = {
            "ifName": "po1",
            "ipv4": "10.0.0.1",
            "ipv6": "fe80::1",
            "metric": 10,
        }
        other_link = {
            "ifName": "po1",
            "ipv4": "10.0.0.2",
            "ipv6": "fe80::2",
            "metric": 10,
        }
        playbook = get_bgp_ebb_igp_pnh_metric_oscillation_playbook(
            device_name="dut.example.com",
            peergroup_ibgp_v6="IBGP_V6",
            peergroup_ibgp_v4="IBGP_V4",
            local_link=local_link,
            other_link=other_link,
            expected_established_sessions=1272,
            profile=BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R,
        )

        self.assertEqual(1, len(playbook.stages))
        self.assertEqual(1, len(playbook.stages[0].steps))
        payload = _step_payload(playbook.stages[0].steps[0])
        self.assertEqual("bgp_igp_pnh_metric_oscillation", payload["custom_step_name"])
        self.assertEqual(63, payload["count"])
        self.assertEqual(2, payload["step"])
        self.assertEqual(2400, payload["duration"])
        self.assertEqual(30, payload["frequency"])
        self.assertEqual(local_link, payload["local_link"])
        self.assertEqual(other_link, payload["other_link"])
        self.assertIsNotNone(playbook.cleanup_steps)
        assert playbook.cleanup_steps is not None
        self.assertEqual(1, len(playbook.cleanup_steps))


class BgpIgpPnhMetricOscillationDualScaleTest(unittest.TestCase):
    """FY26 geometry is frozen; FY27 is the scale's, not a second constant."""

    _LOCAL_LINK: dict = {
        "ifName": "po100212",
        "ipv4": "10.217.12.12",
        "ipv6": "2620:0:1cff:dead:bef1:100:13:3120",
        "metric": 10,
    }
    _OTHER_LINK: dict = {
        "ifName": "po100212",
        "ipv4": "10.217.12.13",
        "ipv6": "2620:0:1cff:dead:bef1:100:13:3121",
        "metric": 10,
    }

    @classmethod
    def _playbook(cls, **overrides) -> taac_types.Playbook:
        kwargs = {
            "device_name": "nrqeb012.ash6",
            "peergroup_ibgp_v6": "IBGP_V6",
            "peergroup_ibgp_v4": "IBGP_V4",
            "local_link": cls._LOCAL_LINK,
            "other_link": cls._OTHER_LINK,
            "expected_established_sessions": 1880,
            "profile": BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R,
            "start_ipv4s": list(DEFAULT_OPENR_START_IPV4S),
            "start_ipv6s": list(DEFAULT_OPENR_START_IPV6S),
        }
        kwargs.update(overrides)
        return get_bgp_ebb_igp_pnh_metric_oscillation_playbook(**kwargs)

    @staticmethod
    def _workload_payload(playbook: taac_types.Playbook) -> dict:
        return _step_payload(playbook.stages[0].steps[0])

    @staticmethod
    def _cleanup_payload(playbook: taac_types.Playbook) -> dict:
        cleanup_steps = playbook.cleanup_steps
        assert cleanup_steps is not None
        return _step_payload(cleanup_steps[0])

    def test_fy26_defaults_keep_sixty_three_sites_per_range(self) -> None:
        payload = self._workload_payload(self._playbook())

        self.assertEqual(63, EBB_FY26_SCALE.he_sites_per_range)
        self.assertEqual(EBB_FY26_SCALE.he_sites_per_range, payload["count"])
        self.assertEqual(EBB_FY26_SCALE.next_hop_step, payload["step"])
        self.assertEqual(2400, payload["duration"])
        self.assertEqual(30, payload["frequency"])
        self.assertEqual(list(DEFAULT_OPENR_START_IPV4S), payload["start_ipv4s"])
        self.assertEqual(list(DEFAULT_OPENR_START_IPV6S), payload["start_ipv6s"])

    def test_fy26_workload_serialization_is_byte_stable(self) -> None:
        """The FY26 payload is the registered-config byte sequence."""
        step = self._playbook().stages[0].steps[0]
        params = step.step_params
        assert params is not None

        self.assertEqual(
            json.dumps(
                {
                    "custom_step_name": "bgp_igp_pnh_metric_oscillation",
                    "hostname": "nrqeb012.ash6",
                    "start_ipv4s": list(DEFAULT_OPENR_START_IPV4S),
                    "start_ipv6s": list(DEFAULT_OPENR_START_IPV6S),
                    "local_link": self._LOCAL_LINK,
                    "other_link": self._OTHER_LINK,
                    "count": 63,
                    "step": 2,
                    "duration": 2400,
                    "frequency": 30,
                }
            ),
            params.json_params,
        )
        self.assertEqual(
            "Run acknowledged Open/R PNH metric oscillations", step.description
        )

    def test_fy27_targets_one_hundred_sites_in_every_resolved_plane(self) -> None:
        payload = self._workload_payload(
            self._playbook(
                count=EBB_FY27_SCALE.he_sites_per_range,
                step_size=EBB_FY27_SCALE.next_hop_step,
                ibgp_pnh_count=EBB_FY27_SCALE.he_sites_per_range,
                ibgp_pnh_step=EBB_FY27_SCALE.next_hop_step,
            )
        )

        self.assertEqual(100, EBB_FY27_SCALE.he_sites_per_range)
        self.assertEqual(EBB_FY27_SCALE.he_sites_per_range, payload["count"])
        self.assertEqual(EBB_FY27_SCALE.next_hop_step, payload["step"])
        self.assertNotEqual(EBB_FY26_SCALE.he_sites_per_range, payload["count"])
        self.assertEqual(4, len(payload["start_ipv4s"]))
        self.assertEqual(4, len(payload["start_ipv6s"]))
        # Four planes x 100 sites, in each address family.
        self.assertEqual(400, len(payload["start_ipv4s"]) * payload["count"])

    def test_only_the_site_count_separates_the_two_scales(self) -> None:
        fy26 = self._workload_payload(self._playbook())
        fy27 = self._workload_payload(
            self._playbook(count=EBB_FY27_SCALE.he_sites_per_range)
        )

        self.assertEqual(
            {key: value for key, value in fy26.items() if key != "count"},
            {key: value for key, value in fy27.items() if key != "count"},
        )

    def test_restoration_re_injects_exactly_the_oscillated_inventory(self) -> None:
        for scale in (EBB_FY26_SCALE, EBB_FY27_SCALE):
            with self.subTest(scale=scale.name):
                playbook = self._playbook(
                    count=scale.he_sites_per_range,
                    step_size=scale.next_hop_step,
                )
                workload = self._workload_payload(playbook)
                cleanup = self._cleanup_payload(playbook)

                self.assertEqual("inject", cleanup["action"])
                for key in (
                    "hostname",
                    "start_ipv4s",
                    "start_ipv6s",
                    "local_link",
                    "other_link",
                    "count",
                    "step",
                ):
                    self.assertEqual(workload[key], cleanup[key], key)
                self.assertEqual(scale.he_sites_per_range, cleanup["count"])


if __name__ == "__main__":
    unittest.main()

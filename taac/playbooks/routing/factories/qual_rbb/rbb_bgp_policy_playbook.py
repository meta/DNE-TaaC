# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Playbooks for Phase-2 TC-65--68 BGP policy validation."""

from __future__ import annotations

import re

from taac.health_check.health_check import types as hc_types
from taac.health_checks.healthcheck_definitions import create_ixia_packet_loss_check
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import create_run_task_step, create_validation_step
from taac.test_as_a_config.types import Playbook, Step
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_edge_config import EDGE_EBGP_PEER_GROUP
from taac.testconfigs.routing.util.bgp_rbb_policy_profiles import (
    BGPD_NETWORKS_BY_TESTPLAN,
    RbbBgpPolicyAction,
    RbbBgpPolicyProfile,
    TC65_PREFIX,
    TC65_UNDRAIN_COMMUNITY,
    TC66_ALLOWED_PREFIX,
    TC66_DENIED_PREFIX,
    TC67_INTERNAL_COMMUNITY,
    TC67_PREFIX,
    TC68_DEFAULT_PREFIX,
    TC68_OVERSPECIFIC_PREFIX,
    TC68_SAFE_PREFIX,
    tc65_baseline_policy,
    tc65_undrain_policy,
    tc66_export_policy,
    tc67_export_policy,
    tc68_import_policy,
)

_TASK = "rbb_bgp_policy_lifecycle"
_TRAFFIC = "RBB_P2_TC65_UNDRAIN"


def _task(hostname: str, action: str, description: str, **params: object) -> Step:
    return create_run_task_step(
        task_name=_TASK,
        params_dict={"hostname": hostname, "action": action, **params},
        description=description,
        start_traffic=False,
    )


def _apply(
    hostname: str,
    testplan_id: str,
    policy: tuple[str, dict],
    direction: str,
) -> Step:
    name, document = policy
    return _task(
        hostname,
        "apply",
        f"[{testplan_id}] apply scoped {direction} policy {name}",
        peer_group_name=EDGE_EBGP_PEER_GROUP,
        **{f"{direction}_policy_name": name},
        policy_config=document,
        networks6=list(BGPD_NETWORKS_BY_TESTPLAN[testplan_id]),
    )


def _ixia_routes(port_identifier: str, tid: str, **params: object) -> Step:
    return create_run_task_step(
        task_name="rbb_ixia_bgp_learned_routes",
        params_dict={"gate": tid, "port_identifier": port_identifier, **params},
        description=f"[{tid}] verify IXIA learned-route evidence",
        ixia_needed=True,
        start_traffic=False,
    )


def _stages(profile: RbbBgpPolicyProfile, hostname: str, port_identifier: str) -> list:
    tid = profile.testplan_id
    stages = [
        create_steps_stage(
            steps=[
                _task(
                    hostname,
                    "snapshot",
                    f"[{tid}] snapshot BGP and policy config",
                )
            ],
            description=f"{tid}: establish reversible policy baseline",
        )
    ]
    if profile.action is RbbBgpPolicyAction.UNDRAIN_LOCAL_PREF:
        stages.extend(
            [
                create_steps_stage(
                    steps=[_apply(hostname, tid, tc65_baseline_policy(), "ingress")],
                    description=f"{tid}: establish drained local-preference baseline",
                ),
                create_steps_stage(
                    steps=[
                        _task(
                            hostname,
                            "assert_rib",
                            f"[{tid}] verify drained baseline",
                            expected_present=[TC65_PREFIX],
                            expected_local_pref={TC65_PREFIX: 25},
                            required_communities={
                                TC65_PREFIX: [TC65_UNDRAIN_COMMUNITY]
                            },
                            fib_present=[TC65_PREFIX],
                        )
                    ],
                    description=f"{tid}: prove the route starts drained",
                ),
                create_steps_stage(
                    steps=[_apply(hostname, tid, tc65_undrain_policy(), "ingress")],
                    description=f"{tid}: activate community-driven undrain",
                ),
                create_steps_stage(
                    steps=[
                        _task(
                            hostname,
                            "assert_rib",
                            f"[{tid}] verify undrained route",
                            expected_present=[TC65_PREFIX],
                            expected_local_pref={TC65_PREFIX: 100},
                            required_communities={
                                TC65_PREFIX: [TC65_UNDRAIN_COMMUNITY]
                            },
                            fib_present=[TC65_PREFIX],
                        ),
                        create_validation_step(
                            point_in_time_checks=[
                                create_ixia_packet_loss_check(
                                    thresholds=[
                                        hc_types.PacketLossThreshold(
                                            names=[_TRAFFIC],
                                            metric=(
                                                hc_types.PacketLossMetric.PERCENTAGE
                                            ),
                                            str_value=C.PACKET_LOSS_THRESHOLD_PCT,
                                            expect_packet_loss=False,
                                        )
                                    ]
                                )
                            ],
                            description=(
                                f"[{tid}] IXIA dataplane forwards after undrain"
                            ),
                            start_traffic=True,
                            fail_on_failure=True,
                            fail_fast=True,
                        ),
                    ],
                    description=f"{tid}: validate control plane, FIB, and dataplane",
                ),
            ]
        )
    elif profile.action is RbbBgpPolicyAction.DENY_EXPORT:
        stages.extend([
            create_steps_stage(
                steps=[_apply(hostname, tid, tc66_export_policy(), "egress")],
                description=f"{tid}: apply export deny policy",
            ),
            create_steps_stage(
                steps=[
                    _task(
                        hostname,
                        "assert_peer_routes",
                        f"[{tid}] verify post-policy exports",
                        peer_addr=C.IXIA_R2_EDGE_V6,
                        peer_view="postfilter_advertised",
                        expected_present=[TC66_ALLOWED_PREFIX],
                        expected_absent=[TC66_DENIED_PREFIX],
                    ),
                    _ixia_routes(
                        port_identifier,
                        tid,
                        expected_prefixes=[TC66_ALLOWED_PREFIX],
                        forbidden_prefixes=[TC66_DENIED_PREFIX],
                    ),
                ],
                description=(
                    f"{tid}: prove precise propagation control at DUT and IXIA"
                ),
            ),
        ])
    elif profile.action is RbbBgpPolicyAction.STRIP_EXPORT_COMMUNITY:
        stages.extend([
            create_steps_stage(
                steps=[_apply(hostname, tid, tc67_export_policy(), "egress")],
                description=f"{tid}: strip internal community at boundary",
            ),
            create_steps_stage(
                steps=[
                    _task(
                        hostname,
                        "assert_peer_routes",
                        f"[{tid}] verify stripped advertisement",
                        peer_addr=C.IXIA_R2_EDGE_V6,
                        peer_view="postfilter_advertised",
                        expected_present=[TC67_PREFIX],
                        forbidden_communities={
                            TC67_PREFIX: [TC67_INTERNAL_COMMUNITY]
                        },
                    ),
                    _ixia_routes(
                        port_identifier,
                        tid,
                        expected_prefixes=[TC67_PREFIX],
                        forbidden_communities={
                            TC67_PREFIX: [TC67_INTERNAL_COMMUNITY]
                        },
                    ),
                ],
                description=(
                    f"{tid}: prove the route is exported without internal metadata"
                ),
            ),
        ])
    else:
        stages.extend([
            create_steps_stage(
                steps=[_apply(hostname, tid, tc68_import_policy(), "ingress")],
                description=f"{tid}: apply dangerous-prefix import filter",
            ),
            create_steps_stage(
                steps=[
                    _task(
                        hostname,
                        "assert_peer_routes",
                        f"[{tid}] prove all inputs reached the peer",
                        peer_addr=C.IXIA_R2_EDGE_V6,
                        peer_view="prefilter_received",
                        expected_present=[
                            TC68_DEFAULT_PREFIX,
                            TC68_SAFE_PREFIX,
                            TC68_OVERSPECIFIC_PREFIX,
                        ],
                    ),
                    _task(
                        hostname,
                        "assert_rib",
                        f"[{tid}] verify RIB/FIB filtering",
                        expected_present=[TC68_SAFE_PREFIX],
                        expected_absent=[
                            TC68_DEFAULT_PREFIX,
                            TC68_OVERSPECIFIC_PREFIX,
                        ],
                        fib_present=[TC68_SAFE_PREFIX],
                        fib_absent=[
                            TC68_DEFAULT_PREFIX,
                            TC68_OVERSPECIFIC_PREFIX,
                        ],
                    ),
                ],
                description=(
                    f"{tid}: distinguish received input from accepted routes"
                ),
            ),
        ])
    stages.append(
        create_steps_stage(
            steps=[
                _task(
                    hostname,
                    "restore",
                    f"[{tid}] restore exact BGP baseline",
                )
            ],
            description=f"{tid}: restore configuration",
        )
    )
    return stages


def create_rbb_bgp_policy_playbook(
    profile: RbbBgpPolicyProfile,
    *,
    r2_hostname: str,
    r2_ixia_interface: str,
) -> Playbook:
    cleanup = _task(r2_hostname, "restore", f"[{profile.testplan_id}] recovery restore")
    return Playbook(
        name=profile.playbook_name,
        description=f"{profile.testplan_id} [FULL]: {profile.title}",
        prechecks=[],
        postchecks=[],
        stages=_stages(
            profile, r2_hostname, f"{r2_hostname}:{r2_ixia_interface}"
        ),
        cleanup_steps=[cleanup],
        traffic_items_to_start=(
            [_TRAFFIC]
            if profile.action is RbbBgpPolicyAction.UNDRAIN_LOCAL_PREF
            else None
        ),
        device_regexes=[f"^{re.escape(r2_hostname)}$"],
    )


__all__ = ["create_rbb_bgp_policy_playbook"]

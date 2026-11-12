# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Named SRv6 NHG lifecycle playbooks, with IXIA proof for TC-03/TC-04.

Each playbook owns a complete transaction and leaves no dependency for a later
playbook. TC-07 therefore recreates TC-06's forward reference before adding
the group. On an FBOSS version that rejects forward references, the registered
task raises ``unittest.SkipTest`` and cleanup still verifies pristine state.
"""

from __future__ import annotations

import re
import typing as t

from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_clear_traffic_stats_step,
    create_longevity_step,
    create_run_task_step,
    create_start_traffic_step,
    create_stop_traffic_step,
)
from taac.test_as_a_config.types import Playbook, Step
from taac.playbooks.routing.factories.qual_rbb.rbb_srv6_playbook import (
    _counter_step,
    _traffic_loss_validation_step,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_named_nhg_profiles import (
    RbbNamedNhgAction,
    RbbNamedNhgProfile,
)
from taac.testconfigs.routing.util.bgp_rbb_recursive_route_profiles import (
    RECURSIVE_ROUTE_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    srv6_decap_counter_spec,
    srv6_encap_counter_spec,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology

_TASK_NAME = "rbb_srv6_named_nhg"
_TRAFFIC_WARMUP_SECONDS = 5
_TRAFFIC_MEASUREMENT_SECONDS = 10
_MIN_PATH_COUNTER_DELTA = 100_000
_MIN_TAIL_TO_HEAD_COUNTER_RATIO = 0.10


def _step(
    profile: RbbNamedNhgProfile,
    hostname: str,
    action: str,
    *,
    include_members: bool = False,
    expected_programmed: bool | None = None,
) -> Step:
    params = {
        "hostname": hostname,
        "action": action,
        **profile.task_params(include_members=include_members),
    }
    if expected_programmed is not None:
        params["expected_programmed"] = expected_programmed
    return create_run_task_step(
        task_name=_TASK_NAME,
        params_dict=params,
        description=f"[{profile.testplan_id}] {action} named SRv6 NHG lifecycle",
        start_traffic=False,
    )


def _stage(profile: RbbNamedNhgProfile, step: Step, label: str) -> t.Any:
    return create_steps_stage(
        steps=[step],
        description=f"{profile.testplan_id}: {label}",
    )


def _recursive_step(
    head_hostname: str,
    tail_hostname: str,
    action: str,
    *,
    loopback_owner: str = "OPENR",
    baseline_route_expected: bool = False,
    route_prefix: str = RECURSIVE_ROUTE_PROFILE.route_prefix,
) -> Step:
    return create_run_task_step(
        task_name="rbb_recursive_route",
        params_dict={
            "action": action,
            "head_hostname": head_hostname,
            "tail_hostname": tail_hostname,
            "route_prefix": route_prefix,
            "recursive_next_hop": RECURSIVE_ROUTE_PROFILE.recursive_next_hop,
            "loopback_owner": loopback_owner,
            "baseline_route_expected": baseline_route_expected,
        },
        description=(
            f"[phase2:TC-03] {action} recursive route "
            f"with {loopback_owner} loopback owner"
        ),
        start_traffic=False,
    )


def _tc02_stages(profile: RbbNamedNhgProfile, hostname: str) -> list[t.Any]:
    return [
        _stage(
            profile,
            _step(profile, hostname, "precheck"),
            "refuse pre-existing test-owned names",
        ),
        _stage(
            profile,
            _step(profile, hostname, "program_nhg", include_members=True),
            "program the named SRv6 NHG and exact SID-list NHEs",
        ),
        _stage(
            profile,
            _step(
                profile,
                hostname,
                "verify_nhg",
                include_members=True,
            ),
            "verify exact unreferenced group and NHE readback",
        ),
        _stage(
            profile,
            _step(profile, hostname, "program_route"),
            "add a TE_AGENT route that references the named group",
        ),
        _stage(
            profile,
            _step(
                profile,
                hostname,
                "verify_nhg",
                include_members=True,
                expected_programmed=True,
            ),
            "verify the referenced group is programmed",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_programmed"),
            "verify exact route ownership and resolved agent-FIB next hops",
        ),
    ]


def _traffic_stage(
    profile: RbbNamedNhgProfile,
    r1_hostname: str,
    r2_hostname: str,
    topology: RbbTopology,
    *,
    stop_after: bool = True,
) -> t.Any:
    """Prove packets traverse the programmed SRv6 NHG in hardware."""
    encap = srv6_encap_counter_spec("r1", topology)
    decap = srv6_decap_counter_spec("r2", topology)
    encap = {**encap, "min_delta": _MIN_PATH_COUNTER_DELTA}
    decap = {
        **decap,
        "min_delta": _MIN_PATH_COUNTER_DELTA,
        "reference_hostname": r1_hostname,
        "reference_direction": encap["direction"],
        "min_reference_ratio": _MIN_TAIL_TO_HEAD_COUNTER_RATIO,
    }
    steps = [
        _counter_step(r1_hostname, "snapshot", encap, start_traffic=False),
        _counter_step(r2_hostname, "snapshot", decap, start_traffic=False),
        create_start_traffic_step(),
        create_longevity_step(
            duration=_TRAFFIC_WARMUP_SECONDS,
            description=(
                f"{profile.testplan_id}: warm up IXIA forwarding state"
            ),
            start_traffic=False,
        ),
        create_clear_traffic_stats_step(start_traffic=False),
        create_longevity_step(
            duration=_TRAFFIC_MEASUREMENT_SECONDS,
            description=(
                f"{profile.testplan_id}: collect steady-state IXIA traffic"
            ),
            start_traffic=False,
        ),
        _traffic_loss_validation_step(
            f"{profile.testplan_id}: IXIA forwarding through named SRv6 NHG",
            traffic_items=(C.TRAFFIC_ITEM_NAMED_NHG,),
            start_traffic=False,
        ),
        _counter_step(r1_hostname, "assert", encap, start_traffic=False),
        _counter_step(r2_hostname, "assert", decap, start_traffic=False),
    ]
    if stop_after:
        steps.append(create_stop_traffic_step())
    return create_steps_stage(
        steps=steps,
        description=(
            f"{profile.testplan_id}: prove lossless IXIA forwarding and "
            "head/tail hardware counter movement"
        ),
    )


def _baseline_traffic_stage(profile: RbbNamedNhgProfile) -> t.Any:
    """Prove the IXIA/BGP path works before installing the SRv6 override."""
    return create_steps_stage(
        steps=[
            create_start_traffic_step(),
            create_longevity_step(
                duration=_TRAFFIC_WARMUP_SECONDS,
                description=f"{profile.testplan_id}: warm up baseline forwarding",
                start_traffic=False,
            ),
            create_clear_traffic_stats_step(start_traffic=False),
            create_longevity_step(
                duration=_TRAFFIC_MEASUREMENT_SECONDS,
                description=f"{profile.testplan_id}: measure baseline forwarding",
                start_traffic=False,
            ),
            _traffic_loss_validation_step(
                f"{profile.testplan_id}: IXIA baseline before SRv6 override",
                traffic_items=(C.TRAFFIC_ITEM_NAMED_NHG,),
                start_traffic=False,
            ),
            create_stop_traffic_step(),
        ],
        description=(
            f"{profile.testplan_id}: prove the IXIA/BGP baseline before "
            "installing the better-distance loopback route"
        ),
    )


def _tc03_stages(
    profile: RbbNamedNhgProfile,
    hostname: str,
    tail_hostname: str,
    topology: RbbTopology | None,
) -> list[t.Any]:
    """Prove OPENR-to-TE_AGENT loopback ownership and recursive resolution."""
    # In live-IXIA mode the R2 edge overlay already advertises the IXIA-learned
    # tail prefix to R1 with R2's loopback as its iBGP next hop. Do not also
    # originate that prefix from R2's local ``networks6``: the local candidate
    # replaces the eBGP forwarding path on R2 and blackholes the baseline
    # traffic. The install/cleanup pair remains for non-IXIA construction.
    stages = [
        _stage(
            profile,
            _recursive_step(
                hostname,
                tail_hostname,
                "precheck",
                baseline_route_expected=topology is not None,
                route_prefix=C.TAIL_DEST_PREFIX,
            ),
            "verify the IXIA BGPD/FIB baseline and no local test origination",
        ),
        _stage(
            profile,
            _step(profile, hostname, "precheck"),
            "refuse pre-existing loopback ownership or named-NHG state",
        ),
        *(
            []
            if topology is not None
            else [
                _stage(
                    profile,
                    _recursive_step(
                        hostname,
                        tail_hostname,
                        "install",
                        baseline_route_expected=False,
                        route_prefix=C.TAIL_DEST_PREFIX,
                    ),
                    "originate the load-bearing prefix through the remote loopback",
                )
            ]
        ),
        _stage(
            profile,
            _recursive_step(
                hostname,
                tail_hostname,
                "verify",
                baseline_route_expected=topology is not None,
                route_prefix=C.TAIL_DEST_PREFIX,
            ),
            "prove the baseline resolves through the OPENR loopback winner",
        ),
        *([_baseline_traffic_stage(profile)] if topology is not None else []),
        _stage(
            profile,
            _step(profile, hostname, "program_nhg", include_members=True),
            "program the named SRv6 NHG",
        ),
        _stage(
            profile,
            _step(profile, hostname, "program_route"),
            "install a better-distance TE_AGENT loopback route",
        ),
        _stage(
            profile,
            _step(
                profile,
                hostname,
                "verify_nhg",
                include_members=True,
                expected_programmed=True,
            ),
            "verify the loopback-referenced NHG is programmed",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_programmed"),
            "prove TE_AGENT beats OPENR and programs the SRv6 FIB members",
        ),
        _stage(
            profile,
            _recursive_step(
                hostname,
                tail_hostname,
                "verify",
                loopback_owner="TE_AGENT",
                baseline_route_expected=topology is not None,
                route_prefix=C.TAIL_DEST_PREFIX,
            ),
            "prove the load-bearing prefix follows the TE_AGENT loopback winner",
        ),
        _stage(
            profile,
            _recursive_step(
                hostname,
                tail_hostname,
                "verify_hw",
                loopback_owner="TE_AGENT",
                baseline_route_expected=topology is not None,
                route_prefix=C.TAIL_DEST_PREFIX,
            ),
            "prove the recursive service route uses the SRv6 NHG in ASIC",
        ),
    ]
    # TC-03's plan ends at the forwarding/FIB and hardware installation of
    # both the better-distance loopback route and its load-bearing dependent
    # prefix. The IXIA baseline above proves that the dependent prefix carries
    # traffic before the override. End-to-end SRv6 service-prefix forwarding
    # is asserted by TC-04; making it a second TC-03 requirement conflates an
    # independent named-NHG dataplane capability with admin-distance behavior.
    stages.extend(
        [
            _stage(
                profile,
                _step(profile, hostname, "cleanup", include_members=True),
                "remove the TE_AGENT loopback route and named NHG",
            ),
            _stage(
                profile,
                _recursive_step(
                    hostname,
                    tail_hostname,
                    "verify",
                    baseline_route_expected=topology is not None,
                    route_prefix=C.TAIL_DEST_PREFIX,
                ),
                "prove OPENR regains the loopback and recursive service route",
            ),
            *(
                []
                if topology is not None
                else [
                    _stage(
                        profile,
                        _recursive_step(
                            hostname,
                            tail_hostname,
                            "cleanup",
                            baseline_route_expected=False,
                            route_prefix=C.TAIL_DEST_PREFIX,
                        ),
                        "remove the test-originated recursive route",
                    )
                ]
            ),
        ]
    )
    return stages


def _tc06_stages(profile: RbbNamedNhgProfile, hostname: str) -> list[t.Any]:
    return [
        _stage(
            profile,
            _step(profile, hostname, "precheck"),
            "refuse pre-existing test-owned names",
        ),
        _stage(
            profile,
            _step(profile, hostname, "install_forward_ref"),
            "install the route before its named group or SKIP if unsupported",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_rib_only"),
            "verify the TE_AGENT candidate is retained without resolved next hops",
        ),
    ]


def _tc07_stages(profile: RbbNamedNhgProfile, hostname: str) -> list[t.Any]:
    return [
        _stage(
            profile,
            _step(profile, hostname, "precheck"),
            "refuse pre-existing test-owned names",
        ),
        _stage(
            profile,
            _step(profile, hostname, "install_forward_ref"),
            "independently stage the forward reference or SKIP if unsupported",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_rib_only"),
            "verify the unresolved route is RIB-only before NHG creation",
        ),
        _stage(
            profile,
            _step(profile, hostname, "program_nhg", include_members=True),
            "add the missing named SRv6 NHG",
        ),
        _stage(
            profile,
            _step(
                profile,
                hostname,
                "verify_nhg",
                include_members=True,
                expected_programmed=True,
            ),
            "verify exact NHE readback and programmed state",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_programmed"),
            "verify the retained route transitioned into the resolved agent FIB",
        ),
    ]


def create_rbb_named_nhg_playbook(
    profile: RbbNamedNhgProfile,
    *,
    r1_hostname: str,
    r2_hostname: str | None = None,
    topology: RbbTopology | None = None,
    include_traffic: bool = False,
) -> Playbook:
    """Build one self-cleaning named-NHG lifecycle playbook."""
    if not r1_hostname.strip():
        raise ValueError("named-NHG playbook requires the R1 hostname")
    full_dataplane_case = profile.action in {
        RbbNamedNhgAction.ADMIN_DISTANCE_OVERRIDE,
        RbbNamedNhgAction.BIND_SERVICE_PREFIX,
    }
    if full_dataplane_case and not include_traffic:
        raise ValueError(
            f"{profile.testplan_id} is a full dataplane test and requires IXIA traffic"
        )
    if profile.action in {
        RbbNamedNhgAction.PROGRAM_AND_VERIFY,
    }:
        stages = _tc02_stages(profile, r1_hostname)
    elif profile.action is RbbNamedNhgAction.BIND_SERVICE_PREFIX:
        if include_traffic and (
            topology is None
            or not r2_hostname
            or not r2_hostname.strip()
            or r2_hostname == r1_hostname
        ):
            raise ValueError("TC-04 traffic requires topology and distinct DUTs")
        stages = _tc02_stages(profile, r1_hostname)
        if include_traffic:
            stages.append(
                _traffic_stage(
                    profile,
                    r1_hostname,
                    t.cast(str, r2_hostname),
                    t.cast(RbbTopology, topology),
                )
            )
    elif profile.action is RbbNamedNhgAction.ADMIN_DISTANCE_OVERRIDE:
        if not r2_hostname or not r2_hostname.strip() or r2_hostname == r1_hostname:
            raise ValueError("TC-03 requires distinct R1 and R2 hostnames")
        if include_traffic and topology is None:
            raise ValueError("TC-03 traffic requires the RBB topology")
        stages = _tc03_stages(
            profile,
            r1_hostname,
            r2_hostname,
            topology if include_traffic else None,
        )
    elif profile.action is RbbNamedNhgAction.FORWARD_REFERENCE:
        stages = _tc06_stages(profile, r1_hostname)
    elif profile.action is RbbNamedNhgAction.RESOLVE_FORWARD_REFERENCE:
        stages = _tc07_stages(profile, r1_hostname)
    else:  # pragma: no cover - frozen enum exhaustiveness guard
        raise ValueError(f"unsupported named-NHG action {profile.action!r}")

    support_note = (
        " Forward-reference rejection is reported as SKIP, not PASS."
        if profile.requires_forward_reference_support
        else ""
    )
    limitation_note = (
        " Limitations: " + "; ".join(profile.unmet_requirements) + "."
        if profile.unmet_requirements
        else ""
    )
    cleanup_steps = []
    if include_traffic and full_dataplane_case:
        cleanup_steps.append(create_stop_traffic_step())
    cleanup_steps.append(
        _step(profile, r1_hostname, "cleanup", include_members=True)
    )
    if profile.action is RbbNamedNhgAction.ADMIN_DISTANCE_OVERRIDE:
        cleanup_steps.append(
            _recursive_step(
                r1_hostname,
                t.cast(str, r2_hostname),
                "cleanup",
                baseline_route_expected=include_traffic,
                route_prefix=C.TAIL_DEST_PREFIX,
            )
        )
    return Playbook(
        name=profile.playbook_name,
        description=(
            f"{profile.testplan_id} [{profile.coverage.value.upper()}]: "
            f"{profile.title}.{support_note}{limitation_note}"
        ),
        prechecks=[],
        postchecks=[],
        stages=stages,
        cleanup_steps=cleanup_steps,
        traffic_items_to_start=(
            [C.TRAFFIC_ITEM_NAMED_NHG]
            if include_traffic and full_dataplane_case
            else None
        ),
        device_regexes=[f"^{re.escape(r1_hostname)}$"],
    )


__all__ = ["create_rbb_named_nhg_playbook"]

# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Playbooks for Phase-1 Open/R path selection and core ECMP state."""

from __future__ import annotations

import ipaddress
import re
import typing as t

from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import create_run_task_step
from taac.test_as_a_config.types import Playbook, Step
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_core_ecmp_profiles import (
    OPENR_PREFERRED_METRIC,
    OPENR_STANDBY_METRIC,
    RbbCoreEcmpAction,
    RbbCoreEcmpProfile,
    validate_core_ecmp_topology,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology
_METRIC_TIMEOUT_SECONDS = 30
_ROUTE_TIMEOUT_SECONDS = 60


def _sample_id(profile: RbbCoreEcmpProfile, role: str) -> str:
    return f"{profile.testplan_id}:{role}:openr-core"


def _core_rif_cidrs(role: str, path_count: int) -> list[str]:
    return [C.core_rif_cidr(role, index, 6) for index in range(path_count)]


def _remote_loopback_routes(role: str) -> list[dict[str, t.Any]]:
    if role == "r1":
        remote_v4, remote_v6 = C.R2_ROUTER_ID, C.R2_LOOPBACK_V6
    elif role == "r2":
        remote_v4, remote_v6 = C.R1_ROUTER_ID, C.R1_LOOPBACK_V6
    else:
        raise ValueError(f"unknown RBB role {role!r}")
    return [
        {
            "prefix": str(ipaddress.ip_network(f"{remote_v4}/32", strict=False)),
            "client": "OPENR",
            "require_fib": True,
        },
        {
            "prefix": str(ipaddress.ip_network(f"{remote_v6}/128", strict=False)),
            "client": "OPENR",
            "require_fib": True,
        },
    ]


def _task_step(
    profile: RbbCoreEcmpProfile,
    topology: RbbTopology,
    role: str,
    action: str,
    **params: t.Any,
) -> Step:
    hostname = topology.node(role).hostname
    return create_run_task_step(
        task_name="rbb_openr_core_path",
        params_dict={
            "action": action,
            "hostname": hostname,
            "gate": profile.testplan_id,
            "sample_id": _sample_id(profile, role),
            **params,
        },
        description=f"[{profile.testplan_id}:{role}] {action} Open/R core paths",
        start_traffic=False,
    )


def _snapshot_stage(
    profile: RbbCoreEcmpProfile, topology: RbbTopology, path_count: int
) -> t.Any:
    return create_steps_stage(
        steps=[
            _task_step(
                profile,
                topology,
                role,
                "snapshot",
                core_rif_cidrs=_core_rif_cidrs(role, path_count),
            )
            for role in ("r1", "r2")
        ],
        description=(
            f"{profile.testplan_id}: claim pristine Open/R metric state on both DUTs"
        ),
    )


def _metric_stage(
    profile: RbbCoreEcmpProfile,
    topology: RbbTopology,
    metrics: list[int],
    label: str,
) -> t.Any:
    return create_steps_stage(
        steps=[
            _task_step(
                profile,
                topology,
                role,
                "set_metrics",
                metrics=metrics,
                timeout_seconds=_METRIC_TIMEOUT_SECONDS,
                poll_interval_seconds=1,
            )
            for role in ("r1", "r2")
        ],
        description=f"{profile.testplan_id}: {label}",
    )


def _route_stage(
    profile: RbbCoreEcmpProfile,
    topology: RbbTopology,
    path_indices: list[int],
    *,
    routes_by_role: t.Mapping[str, list[dict[str, t.Any]]] | None = None,
    label: str,
) -> t.Any:
    routes_by_role = routes_by_role or {
        role: _remote_loopback_routes(role) for role in ("r1", "r2")
    }
    return create_steps_stage(
        steps=[
            _task_step(
                profile,
                topology,
                role,
                "assert_routes",
                path_indices=path_indices,
                routes=routes,
                timeout_seconds=_ROUTE_TIMEOUT_SECONDS,
                poll_interval_seconds=2,
            )
            for role, routes in routes_by_role.items()
        ],
        description=f"{profile.testplan_id}: {label}",
    )


def _restore_stage(profile: RbbCoreEcmpProfile, topology: RbbTopology) -> t.Any:
    return create_steps_stage(
        steps=[
            _task_step(
                profile,
                topology,
                role,
                "restore",
                timeout_seconds=_METRIC_TIMEOUT_SECONDS,
                poll_interval_seconds=1,
            )
            for role in ("r1", "r2")
        ],
        description=(
            f"{profile.testplan_id}: clear task-owned Open/R metric overrides"
        ),
    )


def _cleanup_steps(
    profile: RbbCoreEcmpProfile, topology: RbbTopology
) -> list[Step]:
    """Restore each DUT's task-owned metric overrides during teardown."""
    return [
        _task_step(
            profile,
            topology,
            role,
            "restore",
            timeout_seconds=_METRIC_TIMEOUT_SECONDS,
            poll_interval_seconds=1,
        )
        for role in ("r1", "r2")
    ]


def create_rbb_core_ecmp_playbook(
    profile: RbbCoreEcmpProfile,
    *,
    topology: RbbTopology,
) -> Playbook:
    """Build one reversible TC-02 or TC-03 playbook."""
    path_count = validate_core_ecmp_topology(topology)
    stages = []
    stages.append(_snapshot_stage(profile, topology, path_count))

    if profile.action is RbbCoreEcmpAction.OPENR_PATH_SELECTION:
        for selected in range(path_count):
            metrics = [
                OPENR_PREFERRED_METRIC if index == selected else OPENR_STANDBY_METRIC
                for index in range(path_count)
            ]
            stages.append(
                _metric_stage(
                    profile,
                    topology,
                    metrics,
                    f"make core path {selected} uniquely lowest cost",
                )
            )
            stages.append(
                _route_stage(
                    profile,
                    topology,
                    [selected],
                    label=f"verify core path {selected} is the only SPF next hop",
                )
            )
    else:
        stages.append(
            _metric_stage(
                profile,
                topology,
                [OPENR_PREFERRED_METRIC] * path_count,
                "configure equal metrics on every declared core path",
            )
        )
        stages.append(
            _route_stage(
                profile,
                topology,
                list(range(path_count)),
                label="verify Open/R installs every equal-cost next hop",
            )
        )
    stages.append(_restore_stage(profile, topology))
    return Playbook(
        name=profile.playbook_name,
        description=(
            f"{profile.testplan_id} [{profile.coverage.value.upper()}]: "
            f"{profile.title}"
        ),
        prechecks=[],
        postchecks=[],
        stages=stages,
        cleanup_steps=_cleanup_steps(profile, topology),
        traffic_items_to_start=None,
        device_regexes=[f"^{re.escape(topology.r1.hostname)}$"],
    )


__all__ = ["create_rbb_core_ecmp_playbook"]

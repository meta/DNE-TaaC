# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Read-only RBB state-audit playbook factory.

Each profile represents one original test-plan requirement and becomes one
independently reported playbook. The playbook is anchored once to its first
target role, while its task steps explicitly name every target role; this
avoids TAAC expanding an already host-specific command over every DUT in the
topology and permits later headend-only or tail-only requirements.
"""

from __future__ import annotations

import re

from taac.test_as_a_config.types import Playbook, Step

from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import create_run_task_step
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    RbbStateAuditProfile,
)


def _task_params(
    profile: RbbStateAuditProfile, node: str, hostname: str
) -> dict[str, object]:
    """Project one declarative profile into the registered task contract."""
    expectations = profile.to_task_params(node)
    expected_keys = {
        "routes",
        "ndp",
        "mysids",
        "active_services",
        "interfaces_up",
    }
    if set(expectations) != expected_keys:
        raise ValueError(
            f"{profile.testplan_id} returned invalid task keys for {node}: "
            f"expected {sorted(expected_keys)}, got {sorted(expectations)}"
        )
    params: dict[str, object] = {
        "hostname": hostname,
        "gate": profile.testplan_id,
        **expectations,
    }
    if not any(
        params[key]
        for key in ("routes", "ndp", "mysids", "active_services", "interfaces_up")
    ):
        raise ValueError(
            f"{profile.testplan_id} has no state-audit expectations for {node}"
        )
    return params


def _audit_step(profile: RbbStateAuditProfile, node: str, hostname: str) -> Step:
    return create_run_task_step(
        task_name="rbb_state_audit",
        params_dict=_task_params(profile, node, hostname),
        description=(
            f"[{profile.testplan_id}:{node}] read-only state audit on {hostname}"
        ),
    )


def create_rbb_state_audit_playbook(
    profile: RbbStateAuditProfile,
    *,
    r1_hostname: str = C.R1_HOSTNAME,
    r2_hostname: str = C.R2_HOSTNAME,
    name: str | None = None,
) -> Playbook:
    """Build one non-mutating, independently reported test-plan audit."""
    title = getattr(profile, "title", "RBB state audit")
    coverage = profile.coverage.value.upper()
    hostnames = {"r1": r1_hostname, "r2": r2_hostname}
    anchor_hostname = hostnames[profile.target_roles[0]]
    return Playbook(
        name=name or profile.playbook_name,
        description=f"{profile.testplan_id} [{coverage}]: {title}",
        stages=[
            create_steps_stage(
                steps=[
                    _audit_step(profile, node, hostnames[node])
                    for node in profile.target_roles
                ],
                description=f"{profile.testplan_id} [{coverage}]: {title}",
            )
        ],
        prechecks=[],
        postchecks=[],
        cleanup_steps=[],
        device_regexes=[f"^{re.escape(anchor_hostname)}$"],
    )


__all__ = ["create_rbb_state_audit_playbook"]

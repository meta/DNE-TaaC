# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig factory for the read-only two-node RBB state audits."""

from __future__ import annotations

import typing as t

from taac.test_as_a_config.types import TestConfig

from taac.playbooks.routing.factories.qual_rbb.rbb_state_audit_playbook import (
    create_rbb_state_audit_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _build_rbb_test_config,
    _resolve_topology,
)
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import build_rbb_inventories
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    build_rbb_state_audit_profiles,
    select_rbb_state_audit_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


def create_rbb_state_audit_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_STATE_AUDIT_TEST",
    testplan_ids: t.Iterable[str] | None = None,
    allow_partial: bool = False,
) -> TestConfig:
    """Build device-only audit playbooks, one per selected test-plan ID.

    The audit never reserves IXIA.  When the normal ``--setup-duts`` input is
    enabled, it reuses PR #46's transactional bootstrap/restore tasks; the
    playbooks themselves remain read-only. Default selection includes only
    fully runnable profiles. A caller must select a partial profile explicitly
    *and* set ``allow_partial=True``.
    """
    topology = _resolve_topology(topology, include_traffic=False)
    profiles = build_rbb_state_audit_profiles(
        topology, srv6_profile=SRV6_3_USIDS_PROFILE
    )
    selected = select_rbb_state_audit_profiles(
        profiles,
        testplan_ids=testplan_ids,
        allow_partial=allow_partial,
    )
    if not selected:
        raise ValueError("state-audit profile selection is empty")

    r1, r2 = build_rbb_inventories(topology)
    return _build_rbb_test_config(
        name=name,
        profile=SRV6_3_USIDS_PROFILE,
        playbooks=[
            create_rbb_state_audit_playbook(
                profile,
                r1_hostname=r1.device_name,
                r2_hostname=r2.device_name,
            )
            for profile in selected
        ],
        r1=r1,
        r2=r2,
        topology=topology,
        include_traffic=False,
    )


__all__ = ["create_rbb_state_audit_test_config"]

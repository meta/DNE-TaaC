# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig for full Phase-2 TC-05/08/113 wire validation."""

from __future__ import annotations

import typing as t

from taac.test_as_a_config.types import TestConfig
from taac.playbooks.routing.factories.qual_rbb.rbb_srv6_wire_playbook import (
    create_rbb_srv6_wire_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _build_rbb_test_config,
    _resolve_topology,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import build_rbb_inventories
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_srv6_wire_profiles import (
    select_rbb_srv6_wire_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


def create_rbb_srv6_wire_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_P2_SRV6_WIRE_VALIDATION",
    testplan_ids: t.Iterable[str] | None = None,
) -> TestConfig:
    topology = _resolve_topology(topology, include_traffic=True)
    selected = select_rbb_srv6_wire_profiles(testplan_ids)
    if not selected:
        raise ValueError("SRv6 wire profile selection is empty")
    r1, r2 = build_rbb_inventories(topology)
    return _build_rbb_test_config(
        name=name,
        profile=SRV6_3_USIDS_PROFILE,
        playbooks=[
            create_rbb_srv6_wire_playbook(profile, topology=topology)
            for profile in selected
        ],
        r1=r1,
        r2=r2,
        topology=topology,
        include_traffic=True,
        traffic_route_prefix=C.TAIL_DEST_PREFIX,
        traffic_item_name=C.TRAFFIC_ITEM_NAMED_NHG,
        traffic_ibgp_next_hop=C.R2_LOOPBACK_V6,
    )


__all__ = ["create_rbb_srv6_wire_test_config"]

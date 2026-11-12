# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Profiles for Phase-2 TC-05/08/113 SRv6 wire validation."""

from __future__ import annotations

import dataclasses
import re
import typing as t
from dataclasses import dataclass

from taac.testconfigs.routing.util.bgp_rbb_named_nhg_profiles import (
    RbbNamedNhgAction,
    RbbNamedNhgCoverage,
    RbbNamedNhgProfile,
    build_rbb_named_nhg_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


@dataclass(frozen=True)
class RbbSrv6WireProfile:
    testplan_id: str
    playbook_name: str
    title: str
    group_name: str
    require_distribution: bool

    def __post_init__(self) -> None:
        if self.testplan_id not in {
            "phase2:TC-05",
            "phase2:TC-08",
            "phase2:TC-113",
        }:
            raise ValueError(f"unsupported SRv6 wire case {self.testplan_id!r}")
        if not self.playbook_name.strip() or not self.title.strip():
            raise ValueError("SRv6 wire profile requires a name and title")
        if re.fullmatch(r"[A-Za-z0-9_.:-]{1,31}", self.group_name) is None:
            raise ValueError("SRv6 wire profile has an invalid named-NHG name")

    def provisioning_profile(self, topology: RbbTopology) -> RbbNamedNhgProfile:
        """Clone TC-04's exact load-bearing NHG contract under a unique name."""
        template = next(
            profile
            for profile in build_rbb_named_nhg_profiles(
                topology, SRV6_3_USIDS_PROFILE
            )
            if profile.action is RbbNamedNhgAction.BIND_SERVICE_PREFIX
        )
        return dataclasses.replace(
            template,
            testplan_id=self.testplan_id,
            playbook_name=self.playbook_name,
            title=self.title,
            coverage=RbbNamedNhgCoverage.FULL,
            group_name=self.group_name,
        )


SRV6_WIRE_PROFILES: tuple[RbbSrv6WireProfile, ...] = (
    RbbSrv6WireProfile(
        testplan_id="phase2:TC-05",
        playbook_name="rbb_p2_tc05_headend_encap_nhg_traffic",
        title="Head-end SRv6 encapsulation and NHG traffic distribution",
        group_name="taac-rbb-p2-tc05",
        require_distribution=True,
    ),
    RbbSrv6WireProfile(
        testplan_id="phase2:TC-08",
        playbook_name="rbb_p2_tc08_resolved_nhg_encap_traffic",
        title="Resolved SRv6 NHG encapsulation and forwarding",
        group_name="taac-rbb-p2-tc08",
        require_distribution=True,
    ),
    RbbSrv6WireProfile(
        testplan_id="phase2:TC-113",
        playbook_name="rbb_p2_tc113_usid_carrier_on_wire",
        title="uSID carrier encoding on wire",
        group_name="taac-rbb-p2-tc113",
        require_distribution=False,
    ),
)


def select_rbb_srv6_wire_profiles(
    testplan_ids: t.Iterable[str] | None = None,
) -> tuple[RbbSrv6WireProfile, ...]:
    if testplan_ids is None:
        return SRV6_WIRE_PROFILES
    requested = tuple(testplan_ids)
    if len(requested) != len(set(requested)):
        raise ValueError("duplicate SRv6 wire testplan IDs")
    known = {profile.testplan_id for profile in SRV6_WIRE_PROFILES}
    unknown = sorted(set(requested) - known)
    if unknown:
        raise ValueError(f"unknown SRv6 wire testplan IDs: {unknown}")
    selected = set(requested)
    return tuple(
        profile for profile in SRV6_WIRE_PROFILES if profile.testplan_id in selected
    )


__all__ = [
    "RbbSrv6WireProfile",
    "SRV6_WIRE_PROFILES",
    "select_rbb_srv6_wire_profiles",
]

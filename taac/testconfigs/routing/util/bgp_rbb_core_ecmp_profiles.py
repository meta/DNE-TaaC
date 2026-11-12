# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Declarative Phase-1 Open/R and BGP ECMP profiles for two-node RBB."""

from __future__ import annotations

import enum
import math
import os
import re
import typing as t
from dataclasses import dataclass

from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


class RbbCoreEcmpAction(enum.Enum):
    OPENR_PATH_SELECTION = "openr_path_selection"
    OPENR_ECMP = "openr_ecmp"
    BGP_ECMP_TRAFFIC = "bgp_ecmp_traffic"


class RbbCoreEcmpCoverage(enum.Enum):
    FULL = "full"
    ADAPTED = "adapted"


@dataclass(frozen=True)
class RbbCoreEcmpProfile:
    """One independently reported requirement from the Phase-1 test plan."""

    testplan_id: str
    playbook_name: str
    title: str
    action: RbbCoreEcmpAction
    coverage: RbbCoreEcmpCoverage

    def __post_init__(self) -> None:
        if not re.fullmatch(r"phase1:TC-[0-9]+", self.testplan_id):
            raise ValueError(f"invalid Phase-1 testplan ID {self.testplan_id!r}")
        if not self.playbook_name.strip() or not self.title.strip():
            raise ValueError("core ECMP profile requires a name and title")
        if not isinstance(self.action, RbbCoreEcmpAction):
            raise TypeError("core ECMP action must be an RbbCoreEcmpAction")
        if not isinstance(self.coverage, RbbCoreEcmpCoverage):
            raise TypeError("core ECMP coverage must be an RbbCoreEcmpCoverage")


CORE_ECMP_SUITE_TESTPLAN_IDS: tuple[str, ...] = (
    "phase1:TC-02",
    "phase1:TC-03",
    "phase1:TC-08",
)


def _positive_metric(env_name: str, default: int) -> int:
    value = int(os.environ.get(env_name, str(default)))
    if not 1 <= value <= (1 << 31) - 1:
        raise ValueError(f"{env_name} must be in 1..{(1 << 31) - 1}")
    return value


def _path_share(env_name: str, default: float) -> float:
    value = float(os.environ.get(env_name, str(default)))
    if not math.isfinite(value) or not 0 < value <= 100:
        raise ValueError(f"{env_name} must be finite and in (0, 100]")
    return value


OPENR_PREFERRED_METRIC = _positive_metric("TAAC_RBB_OPENR_PREFERRED_METRIC", 10)
OPENR_STANDBY_METRIC = _positive_metric("TAAC_RBB_OPENR_STANDBY_METRIC", 1000)
if OPENR_STANDBY_METRIC <= OPENR_PREFERRED_METRIC:
    raise ValueError(
        "TAAC_RBB_OPENR_STANDBY_METRIC must be greater than "
        "TAAC_RBB_OPENR_PREFERRED_METRIC"
    )
MIN_PATH_TRAFFIC_SHARE_PCT = _path_share("TAAC_RBB_CORE_ECMP_MIN_PATH_SHARE_PCT", 1.0)


def validate_core_ecmp_topology(topology: RbbTopology) -> int:
    """Return the symmetric core-path count or fail before device mutation."""
    r1_paths = topology.r1.core_pcs
    r2_paths = topology.r2.core_pcs
    if len(r1_paths) < 2 or len(r2_paths) < 2:
        raise ValueError("RBB core ECMP tests require at least two core paths")
    if len(r1_paths) != len(r2_paths):
        raise ValueError("RBB core ECMP tests require symmetric core-path counts")
    for role, paths in (("r1", r1_paths), ("r2", r2_paths)):
        if any(not path.members for path in paths):
            raise ValueError(f"{role} core ECMP paths must have physical members")
    if MIN_PATH_TRAFFIC_SHARE_PCT * len(r1_paths) > 100:
        raise ValueError(
            "TAAC_RBB_CORE_ECMP_MIN_PATH_SHARE_PCT multiplied by the core-path "
            "count must not exceed 100"
        )
    return len(r1_paths)


def build_rbb_core_ecmp_profiles(
    topology: RbbTopology,
) -> tuple[RbbCoreEcmpProfile, ...]:
    """Build the path-selection, route-ECMP, then traffic-ECMP sequence."""
    validate_core_ecmp_topology(topology)
    return (
        RbbCoreEcmpProfile(
            testplan_id="phase1:TC-02",
            playbook_name="rbb_p1_tc02_openr_path_selection",
            title="Open/R shortest-path selection across every core path",
            action=RbbCoreEcmpAction.OPENR_PATH_SELECTION,
            # The original requirement names head, midpoint, and tail roles.
            # This two-node topology validates the same SPF behavior between
            # its head and tail, so the mapping is explicit rather than FULL.
            coverage=RbbCoreEcmpCoverage.ADAPTED,
        ),
        RbbCoreEcmpProfile(
            testplan_id="phase1:TC-03",
            playbook_name="rbb_p1_tc03_openr_ecmp",
            title="Open/R equal-cost next-hop installation",
            action=RbbCoreEcmpAction.OPENR_ECMP,
            coverage=RbbCoreEcmpCoverage.FULL,
        ),
        RbbCoreEcmpProfile(
            testplan_id="phase1:TC-08",
            playbook_name="rbb_p1_tc08_bgp_core_ecmp_traffic",
            title="BGP traffic distribution across every core ECMP path",
            action=RbbCoreEcmpAction.BGP_ECMP_TRAFFIC,
            coverage=RbbCoreEcmpCoverage.FULL,
        ),
    )


def select_rbb_core_ecmp_profiles(
    profiles: t.Iterable[RbbCoreEcmpProfile],
    testplan_ids: t.Iterable[str] | None = None,
) -> tuple[RbbCoreEcmpProfile, ...]:
    """Select known IDs while preserving dependency-safe catalog order."""
    catalog = tuple(profiles)
    known = {profile.testplan_id for profile in catalog}
    if len(known) != len(catalog):
        raise ValueError("duplicate core ECMP testplan IDs")
    if testplan_ids is None:
        return catalog
    requested = tuple(testplan_ids)
    if len(requested) != len(set(requested)):
        raise ValueError("duplicate core ECMP testplan IDs in selection")
    unknown = sorted(set(requested) - known)
    if unknown:
        raise ValueError(f"unknown RBB core ECMP testplan IDs: {unknown}")
    selected = set(requested)
    return tuple(profile for profile in catalog if profile.testplan_id in selected)


__all__ = [
    "CORE_ECMP_SUITE_TESTPLAN_IDS",
    "MIN_PATH_TRAFFIC_SHARE_PCT",
    "OPENR_PREFERRED_METRIC",
    "OPENR_STANDBY_METRIC",
    "RbbCoreEcmpAction",
    "RbbCoreEcmpCoverage",
    "RbbCoreEcmpProfile",
    "build_rbb_core_ecmp_profiles",
    "select_rbb_core_ecmp_profiles",
    "validate_core_ecmp_topology",
]

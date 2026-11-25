# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Declarative Phase-2 TC-65--68 BGP policy profiles."""

from __future__ import annotations

import enum
import ipaddress
import typing as t
from dataclasses import dataclass


TC65_PREFIX = "2001:db8:6500::/64"
TC65_UNDRAIN_COMMUNITY = "65000:65"
TC66_DENIED_PREFIX = "2001:db8:6600::/64"
TC66_ALLOWED_PREFIX = "2001:db8:6601::/64"
TC67_PREFIX = "2001:db8:6700::/64"
TC67_INTERNAL_COMMUNITY = "65000:67"
TC68_DEFAULT_PREFIX = "::/0"
TC68_SAFE_PREFIX = "2001:db8:6800::/64"
TC68_OVERSPECIFIC_PREFIX = "2001:db8:6800::1/128"


class RbbBgpPolicyAction(enum.Enum):
    UNDRAIN_LOCAL_PREF = "undrain_local_pref"
    DENY_EXPORT = "deny_export"
    STRIP_EXPORT_COMMUNITY = "strip_export_community"
    DENY_DANGEROUS_IMPORTS = "deny_dangerous_imports"


@dataclass(frozen=True)
class RbbBgpPolicyProfile:
    testplan_id: str
    playbook_name: str
    title: str
    action: RbbBgpPolicyAction

    def __post_init__(self) -> None:
        if self.testplan_id not in {
            "phase2:TC-65",
            "phase2:TC-66",
            "phase2:TC-67",
            "phase2:TC-68",
        }:
            raise ValueError(f"unsupported BGP policy case {self.testplan_id!r}")
        if not self.playbook_name.strip() or not self.title.strip():
            raise ValueError("BGP policy profile requires a name and title")
        if not isinstance(self.action, RbbBgpPolicyAction):
            raise TypeError("BGP policy action must be an RbbBgpPolicyAction")


def _always() -> dict[str, t.Any]:
    return {"type": 20}


def _community(community: str) -> dict[str, t.Any]:
    return {
        "type": 3,
        "communities_filter": {
            "name": f"TAAC_{community.replace(':', '_')}",
            "communities": [community],
        },
    }


def _prefix(base: str, operator: int, length: int) -> dict[str, t.Any]:
    return {
        "type": 5,
        "prefix_filters": {
            "name": "TAAC_RBB_POLICY_PREFIXES",
            "prefixes": [
                {
                    "base_prefix": base,
                    "prefix_len_ranges": [
                        {"value": length, "compare_operator": operator}
                    ],
                }
            ],
        },
    }


def _term(
    name: str,
    match: dict[str, t.Any],
    actions: list[dict[str, t.Any]],
) -> dict[str, t.Any]:
    return {
        "name": name,
        "policy_match_entries": {"match_entries": [match]},
        "policy_action_entries": actions,
    }


def _statement(
    name: str,
    terms: list[dict[str, t.Any]],
    *,
    result: int = 1,
) -> dict[str, t.Any]:
    return {
        "name": name,
        "description": f"TAAC RBB {name}",
        "policy_version": "1",
        "policy_entries": terms,
        "result": result,
    }


def policy_document(*statements: dict[str, t.Any]) -> dict[str, t.Any]:
    """Return the split-config ``BgpPolicyConfig`` JSON shape."""
    return {
        "communities": [],
        "localprefs": [],
        "policies": {
            "bgp_policy_statements": list(statements),
            "community_lists": [],
            "aspath_lists": [],
            "prefix_lists": [],
            "as_paths": [],
            "communities": [],
        },
    }


def tc65_baseline_policy() -> tuple[str, dict[str, t.Any]]:
    name = "TAAC_RBB_TC65_DRAINED_IN"
    statement = _statement(
        name,
        [
            _term(
                "DEFAULT_DRAINED",
                _always(),
                [{"type": 3, "set_local_pref": {"local_pref": 25}}],
            )
        ],
    )
    return name, policy_document(statement)


def tc65_undrain_policy() -> tuple[str, dict[str, t.Any]]:
    name = "TAAC_RBB_TC65_UNDRAIN_IN"
    statement = _statement(
        name,
        [
            _term(
                "COMMUNITY_UNDRAIN",
                _community(TC65_UNDRAIN_COMMUNITY),
                [{"type": 3, "set_local_pref": {"local_pref": 100}}],
            ),
            _term(
                "DEFAULT_DRAINED",
                _always(),
                [{"type": 3, "set_local_pref": {"local_pref": 25}}],
            ),
        ],
    )
    return name, policy_document(statement)


def tc66_export_policy() -> tuple[str, dict[str, t.Any]]:
    name = "TAAC_RBB_TC66_EXPORT"
    statement = _statement(
        name,
        [
            _term(
                "DENY_SELECTED_PREFIX",
                _prefix(TC66_DENIED_PREFIX, 1, 64),
                [{"type": 6}],
            ),
            _term("PERMIT_REMAINDER", _always(), []),
        ],
    )
    return name, policy_document(statement)


def tc67_export_policy() -> tuple[str, dict[str, t.Any]]:
    name = "TAAC_RBB_TC67_STRIP_INTERNAL"
    statement = _statement(
        name,
        [
            _term(
                "STRIP_INTERNAL_COMMUNITY",
                _always(),
                [
                    {
                        "type": 2,
                        "community_action": {
                            "communities": [TC67_INTERNAL_COMMUNITY],
                            "action_type": 3,
                        },
                    }
                ],
            )
        ],
    )
    return name, policy_document(statement)


def tc68_import_policy() -> tuple[str, dict[str, t.Any]]:
    name = "TAAC_RBB_TC68_SAFE_IMPORT"
    statement = _statement(
        name,
        [
            _term(
                "DENY_DEFAULT",
                _prefix(TC68_DEFAULT_PREFIX, 1, 0),
                [{"type": 6}],
            ),
            # IPv6 routes longer than /64 are over-specific for this test.
            _term(
                "DENY_OVER_SPECIFIC",
                _prefix(TC68_DEFAULT_PREFIX, 2, 65),
                [{"type": 6}],
            ),
            _term("PERMIT_SAFE", _always(), []),
        ],
    )
    return name, policy_document(statement)


def _network(prefix: str, *, communities: list[str] | None = None) -> dict[str, t.Any]:
    normalized = str(ipaddress.ip_network(prefix, strict=True))
    result: dict[str, t.Any] = {"prefix": normalized}
    if communities:
        result["communities"] = communities
    return result


BGPD_NETWORKS_BY_TESTPLAN: t.Mapping[str, tuple[dict[str, t.Any], ...]] = {
    "phase2:TC-65": (),
    "phase2:TC-66": (
        _network(TC66_DENIED_PREFIX),
        _network(TC66_ALLOWED_PREFIX),
    ),
    "phase2:TC-67": (
        _network(TC67_PREFIX, communities=[TC67_INTERNAL_COMMUNITY]),
    ),
    "phase2:TC-68": (),
}


BGP_POLICY_PROFILES: tuple[RbbBgpPolicyProfile, ...] = (
    RbbBgpPolicyProfile(
        "phase2:TC-65",
        "rbb_p2_tc65_community_undrain",
        "Community-driven local-preference restoration",
        RbbBgpPolicyAction.UNDRAIN_LOCAL_PREF,
    ),
    RbbBgpPolicyProfile(
        "phase2:TC-66",
        "rbb_p2_tc66_export_deny",
        "Export deny and propagation control",
        RbbBgpPolicyAction.DENY_EXPORT,
    ),
    RbbBgpPolicyProfile(
        "phase2:TC-67",
        "rbb_p2_tc67_strip_internal_community",
        "Internal-community stripping at the eBGP boundary",
        RbbBgpPolicyAction.STRIP_EXPORT_COMMUNITY,
    ),
    RbbBgpPolicyProfile(
        "phase2:TC-68",
        "rbb_p2_tc68_dangerous_prefix_filter",
        "Default and over-specific import filtering",
        RbbBgpPolicyAction.DENY_DANGEROUS_IMPORTS,
    ),
)


def select_rbb_bgp_policy_profiles(
    testplan_ids: t.Iterable[str] | None = None,
) -> tuple[RbbBgpPolicyProfile, ...]:
    if testplan_ids is None:
        return BGP_POLICY_PROFILES
    requested = tuple(testplan_ids)
    if len(requested) != len(set(requested)):
        raise ValueError("duplicate BGP policy testplan IDs")
    known = {profile.testplan_id for profile in BGP_POLICY_PROFILES}
    unknown = sorted(set(requested) - known)
    if unknown:
        raise ValueError(f"unknown RBB BGP policy testplan IDs: {unknown}")
    selected = set(requested)
    return tuple(p for p in BGP_POLICY_PROFILES if p.testplan_id in selected)


__all__ = [
    "BGPD_NETWORKS_BY_TESTPLAN",
    "BGP_POLICY_PROFILES",
    "RbbBgpPolicyAction",
    "RbbBgpPolicyProfile",
    "TC65_PREFIX",
    "TC65_UNDRAIN_COMMUNITY",
    "TC66_ALLOWED_PREFIX",
    "TC66_DENIED_PREFIX",
    "TC67_INTERNAL_COMMUNITY",
    "TC67_PREFIX",
    "TC68_DEFAULT_PREFIX",
    "TC68_OVERSPECIFIC_PREFIX",
    "TC68_SAFE_PREFIX",
    "select_rbb_bgp_policy_profiles",
    "tc65_baseline_policy",
    "tc65_undrain_policy",
    "tc66_export_policy",
    "tc67_export_policy",
    "tc68_import_policy",
]

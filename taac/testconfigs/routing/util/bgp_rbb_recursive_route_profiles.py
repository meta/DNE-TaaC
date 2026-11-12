# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Declarative profile for Phase-2 TC-01 recursive route resolution."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from taac.testconfigs.routing.util import bgp_rbb_constants as C


@dataclass(frozen=True)
class RbbRecursiveRouteProfile:
    testplan_id: str = "phase2:TC-01"
    playbook_name: str = "rbb_p2_tc01_recursive_route"
    title: str = "iBGP service prefix recursively resolved through OpenR loopback"
    route_prefix: str = C.RECURSIVE_ROUTE_TEST_PREFIX
    recursive_next_hop: str = C.R2_LOOPBACK_V6

    def __post_init__(self) -> None:
        if self.testplan_id != "phase2:TC-01":
            raise ValueError("recursive-route profile is restricted to phase2:TC-01")
        if not self.playbook_name.strip() or not self.title.strip():
            raise ValueError("recursive-route profile requires a name and title")
        network = ipaddress.ip_network(self.route_prefix, strict=True)
        next_hop = ipaddress.ip_address(self.recursive_next_hop)
        if network.version != 6 or next_hop.version != 6:
            raise ValueError("TC-01 route and recursive next hop must be IPv6")
        forbidden = (
            ipaddress.ip_network(C.TAIL_DEST_PREFIX, strict=True),
            ipaddress.ip_network(C.NAMED_NHG_TEST_PREFIX, strict=True),
            ipaddress.ip_network(C.SRV6_LOCATOR, strict=False),
        )
        if any(network.overlaps(candidate) for candidate in forbidden):
            raise ValueError("TC-01 route prefix overlaps another RBB test resource")
        if next_hop in network:
            raise ValueError("TC-01 recursive next hop must be outside its service prefix")
        object.__setattr__(self, "route_prefix", str(network))
        object.__setattr__(self, "recursive_next_hop", str(next_hop))


RECURSIVE_ROUTE_PROFILE = RbbRecursiveRouteProfile()

__all__ = ["RECURSIVE_ROUTE_PROFILE", "RbbRecursiveRouteProfile"]

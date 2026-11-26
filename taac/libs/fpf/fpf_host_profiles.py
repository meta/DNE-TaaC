# Copyright (c) Meta Platforms, Inc. and affiliates.

"""Named host-pair profiles for reusable MWG2 FPF test instantiation.

A profile is the single source of truth for values that change together when a
test moves to another pair of BE nodes: traffic roles, production prefixes,
GTSW breakout bundle, HRT device/plane layout, and the RDMA/GID selector.

Select one with ``TAAC_FPF_HOST_PROFILE=<name>``. Legacy per-field environment
overrides remain supported when no profile is selected. When a profile is
selected, callers may repeat an identical legacy override, but conflicting
values fail during config construction rather than creating a mixed topology.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FpfHostProfile:
    """Host-specific FPF topology and addressing facts."""

    hostname: str
    pod: str
    gtsw_bundle_first_interface: str
    device_prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.hostname or self.hostname.endswith(".facebook.com"):
            raise ValueError(
                "FPF profile hostname must be the canonical short hostname"
            )
        if re.fullmatch(r"eth\d+/\d+/(1|5)", self.gtsw_bundle_first_interface) is None:
            raise ValueError(
                "FPF profile GTSW bundle must start at breakout channel 1 or 5; "
                f"got {self.gtsw_bundle_first_interface!r}"
            )
        if len(self.device_prefixes) != 8:
            raise ValueError(
                f"FPF paired-device host {self.hostname} must define 8 prefixes"
            )
        for prefix in self.device_prefixes:
            network = ipaddress.ip_network(prefix, strict=True)
            if network.version != 6 or network.prefixlen != 64:
                raise ValueError(
                    f"FPF profile prefix must be a canonical IPv6 /64; got {prefix!r}"
                )

    @property
    def prefixes_by_device(self) -> dict[int, str]:
        return dict(enumerate(self.device_prefixes))

    @property
    def gtsw_bundle_interfaces(self) -> tuple[str, ...]:
        stem, channel = self.gtsw_bundle_first_interface.rsplit("/", 1)
        first = int(channel)
        return tuple(f"{stem}/{first + offset}" for offset in range(4))


@dataclass(frozen=True)
class FpfHostPairProfile:
    """Complete host-derived input contract for one FPF testbed pair."""

    name: str
    server: FpfHostProfile
    client: FpfHostProfile
    hrt_device_ids: tuple[int, ...] = tuple(range(8))
    hrt_local_planes: tuple[int, ...] = (0, 1, 2, 3)
    vf1_device_ids: tuple[int, ...] = (0, 2, 4, 6)
    vf2_device_ids: tuple[int, ...] = (1, 3, 5, 7)
    ib_device: str = "mlx5_bveth0"
    gid_iface: str = "bveth0"
    gid_prefix: str = "2401"

    def __post_init__(self) -> None:
        if self.server.hostname == self.client.hostname:
            raise ValueError("FPF host-pair profile requires distinct hosts")
        configured = set(self.hrt_device_ids)
        vf1 = set(self.vf1_device_ids)
        vf2 = set(self.vf2_device_ids)
        if vf1 & vf2 or vf1 | vf2 != configured:
            raise ValueError(
                "FPF profile VF1/VF2 mappings must be disjoint and cover every "
                "HRT device"
            )
        if len(self.hrt_local_planes) != len(set(self.hrt_local_planes)):
            raise ValueError("FPF profile HRT local planes must be unique")

    @property
    def hosts(self) -> tuple[str, str]:
        return (self.server.hostname, self.client.hostname)


MWG2_TWSHARED_1354_1379 = FpfHostPairProfile(
    name="mwg2_twshared_1354_1379",
    server=FpfHostProfile(
        hostname="twshared1354.03.mwg2",
        pod="l1002.c087.mwg2",
        gtsw_bundle_first_interface="eth1/37/1",
        device_prefixes=(
            "2401:db00:292a:a270::/64",
            "2401:db00:292a:a570::/64",
            "2401:db00:292a:a271::/64",
            "2401:db00:292a:a571::/64",
            "2401:db00:292a:a272::/64",
            "2401:db00:292a:a572::/64",
            "2401:db00:292a:a273::/64",
            "2401:db00:292a:a573::/64",
        ),
    ),
    client=FpfHostProfile(
        hostname="twshared1379.03.mwg2",
        pod="l1001.c087.mwg2",
        gtsw_bundle_first_interface="eth1/25/5",
        device_prefixes=(
            "2401:db00:292a:a15c::/64",
            "2401:db00:292a:a45c::/64",
            "2401:db00:292a:a15d::/64",
            "2401:db00:292a:a45d::/64",
            "2401:db00:292a:a15e::/64",
            "2401:db00:292a:a45e::/64",
            "2401:db00:292a:a15f::/64",
            "2401:db00:292a:a45f::/64",
        ),
    ),
)


HOST_PAIR_PROFILES: dict[str, FpfHostPairProfile] = {
    MWG2_TWSHARED_1354_1379.name: MWG2_TWSHARED_1354_1379,
}


def get_host_pair_profile(name: str) -> FpfHostPairProfile:
    try:
        return HOST_PAIR_PROFILES[name]
    except KeyError:
        raise ValueError(
            f"Unknown TAAC_FPF_HOST_PROFILE {name!r}; known profiles: "
            f"{sorted(HOST_PAIR_PROFILES)}"
        ) from None


def selected_host_pair_profile() -> FpfHostPairProfile | None:
    name = os.environ.get("TAAC_FPF_HOST_PROFILE", "").strip()
    return get_host_pair_profile(name) if name else None


def host_device_prefixes_from_profiles() -> dict[str, dict[int, str]]:
    result: dict[str, dict[int, str]] = {}
    for profile in HOST_PAIR_PROFILES.values():
        for host in (profile.server, profile.client):
            previous = result.setdefault(host.hostname, host.prefixes_by_device)
            if previous != host.prefixes_by_device:
                raise ValueError(
                    f"Conflicting FPF profile prefixes for {host.hostname}"
                )
    return result

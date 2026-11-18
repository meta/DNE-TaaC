# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.
# pyre-unsafe
"""Physical inventories for routing EBB testbeds.

§1 Purpose
==========
Framework-owned inventories for the ASH6 NRQ EBB Conveyor fleet, including
the single-DUT IxANVL conformance rig (``nrqeb010``), ancillary EB0x lab
devices, the historical SNC1 BAG, the per-developer EBB box, and the SNC1
Arista device.

§2 IXIA chassis inventory
========================
``IXIA03_ASH6`` (``2401:db00:2066:3036::3003``) is primary for NRQEB006
through NRQEB009. ``IXIA11_ASH6`` (``2401:db00:2066:303b::3001``) is their
secondary wiring profile and remains primary for the EB0x lab devices.
``bag002.snc1`` uses the SNC1 ``ares1-my24520014`` chassis.

§3 Figure A — ASH6 NRQ physical topology
=========================================
::

    IXIA03_ASH6 (primary)                 IXIA11_ASH6 (secondary)
    1/{81..84} -- Eth3/35/{1..4} nrqeb006  9/{1..4}  -- Eth3/36/{1..4}
    1/{85..88} -- Eth3/35/{1..4} nrqeb007  9/{5..8}  -- Eth3/36/{1..4}
    1/{89..92} -- Eth3/35/{1..4} nrqeb008  10/{1..4} -- Eth3/36/{1..4}
    1/{93..96} -- Eth3/35/{1..4} nrqeb009  10/{5..8} -- Eth3/36/{1..4}

    Conformance-only single DUT (no OpenR pair, no secondary chassis):
    7/{2..4} -- Eth3/36/{2..4} nrqeb010  (IXIA11; DIface-0/1/2 in that order;
    lane 1 carries no light, per LLDP)

    nrqeb006 Eth3/1/1 -- Eth3/1/1 nrqeb007   po100306 owner link
    nrqeb006 Eth3/2/1 -- Eth3/2/1 nrqeb007   po100307 owner link
    nrqeb008 Eth3/1/1 -- Eth3/1/1 nrqeb009   po100308 owner link
    nrqeb008 Eth3/2/1 -- Eth3/2/1 nrqeb009   po100309 owner link

§4 Figure B — ownership-pair zoom
=================================
Each NRQ pair has two physical cross-links. The lower-numbered DUT owns the
first port-channel and is helper for the second; the higher-numbered DUT owns
the second and is helper for the first. Each owner runs standalone OpenR and
injects only its own synthetic KvStore adjacency state.

§5 Naming convention
====================
``port_channel_id = 1003NN`` maps to the owner whose hostname ends in ``NN``:
``po100306`` through ``po100309`` map to ``nrqeb006`` through ``nrqeb009``.

§6 See also
==========
See ``abstractions/README.md §4 OpenR standalone mode`` for the framework
contract and this package's ``README.md`` for the inventory authoring rules.
"""

from __future__ import annotations

import json
import typing as t

from taac.abstractions.physical_interface_semantics import (
    PhysicalInterfaceProfile,
    PhysicalLinkRate,
)
from taac.abstractions.physical_inventory.physical_inventory import (
    PhysicalInventory,
)
from taac.abstractions.routing_semantics import NetworkRole
from taac.abstractions.topology import (
    OpenRStandaloneEndpoint,
    OpenRStandaloneLink,
)
from taac.utils.lab_device_credentials import (
    get_lab_device_password,
)
from taac.test_as_a_config.types import MockDeviceInfo


def _ebb_peer_groups() -> dict[str, str]:
    return {
        "ibgp_v6": "EB-EB-V6",
        "ebgp_v6": "EB-FA-V6",
        "ibgp_v4": "EB-EB-V4",
        "ebgp_v4": "EB-FA-V4",
    }


# ─── Shared constants ─────────────────────────────────────────────────────

_EBB_BGPCPP_PATH = "taac/ebb_ci_cd_configs/ebb_full_scale_bgpcpp_config"
_EBB_PHYSICAL_INTERFACE_PROFILE = PhysicalInterfaceProfile(
    rate=PhysicalLinkRate(aggregate_gbps=100, lane_count=2)
)
IXIA03_ASH6 = "2401:db00:2066:3036::3003"
IXIA11_ASH6 = "2401:db00:2066:303b::3001"


# ─── Lab-wiring helpers (used by the ebXX.lab.ash6 + bgp.eb.test.ash6 boxes) ───
# These produce the ``host_driver_args`` / ``oss_mock_device_data`` payloads that
# the retired ``util/bgp_ebb_lab_wiring._lab_device_wiring`` helper used to
# synthesize at factory-call time. Byte-identical outputs preserved: password
# read via ``get_lab_device_password(env_var)`` (env-var lookup runs at
# PhysicalInventory construction/module-import time; TAAC test processes do
# not mutate the password env var after import).


def _lab_host_driver_args(
    device_name: str,
    *,
    password_env: str = "TAAC_EBB_LAB_DEVICE_PASSWORD",
    extra_kwargs: dict[str, t.Any] | None = None,
) -> dict[str, str]:
    driver_kwargs: dict[str, t.Any] = {
        "username": "admin",
        "password": get_lab_device_password(password_env),
    }
    if extra_kwargs:
        driver_kwargs.update(extra_kwargs)
    return {device_name: json.dumps(driver_kwargs)}


def _lab_oss_mock_device_data(
    device_name: str,
    *,
    network_type: str | None = None,
) -> dict[str, MockDeviceInfo]:
    mock_kwargs: dict[str, t.Any] = {
        "name": device_name,
        "hardware": "ARISTA_7516",
        "role": "EB",
        "operating_system": "EOS",
        "dc": "ash6",
        "region": "ash",
        "asset_id": 12345,
        "asic": "JERICHO",
        "routing_protocol": "BGP",
        "dc_type": "ONE",
        "network_area": "BACKBONE",
        "network_area_type": "BACKBONE",
    }
    if network_type is not None:
        mock_kwargs["network_type"] = network_type
    return {device_name: MockDeviceInfo(**mock_kwargs)}


# ─── nrqeb006 ↔ nrqeb007 OpenR-standalone pair ───────────────────────────

_NRQEB006_OPENR_LINK = OpenRStandaloneLink(
    port_channel_id=100306,
    owner=OpenRStandaloneEndpoint(
        hostname="nrqeb006.ash6",
        member_interface="Ethernet3/1/1",
        ipv4_cidr="10.217.6.6/31",
        ipv6_cidr="2620:0:1cff:dead:bef1:100:13:3060/127",
        link_local_cidr="fe80::100:306:0/64",
    ),
    helper=OpenRStandaloneEndpoint(
        hostname="nrqeb007.ash6",
        member_interface="Ethernet3/1/1",
        ipv4_cidr="10.217.6.7/31",
        ipv6_cidr="2620:0:1cff:dead:bef1:100:13:3061/127",
        link_local_cidr="fe80::100:306:1/64",
    ),
    speed="400g",
)

NRQEB006_ASH6 = PhysicalInventory(
    device_name="nrqeb006.ash6",
    basset_pool="routing.qual",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    usage=frozenset({"cicd", "qual"}),
    primary_ixia_chassis_ip=IXIA03_ASH6,
    secondary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/35/1", "1/81"),
        ("Ethernet3/35/2", "1/82"),
        ("Ethernet3/35/3", "1/83"),
        ("Ethernet3/35/4", "1/84"),
    ],
    secondary_ixia_ports=[
        ("Ethernet3/36/1", "9/1"),
        ("Ethernet3/36/2", "9/2"),
        ("Ethernet3/36/3", "9/3"),
        ("Ethernet3/36/4", "9/4"),
    ],
    dut_bgp_as=65006,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    openr_configerator_path="taac/ebb_ci_cd_configs/nrqeb006_ash6_openr_config",
    openr_standalone_link=_NRQEB006_OPENR_LINK,
    peer_groups=_ebb_peer_groups(),
)

_NRQEB007_OPENR_LINK = OpenRStandaloneLink(
    port_channel_id=100307,
    owner=OpenRStandaloneEndpoint(
        hostname="nrqeb007.ash6",
        member_interface="Ethernet3/2/1",
        ipv4_cidr="10.217.7.7/31",
        ipv6_cidr="2620:0:1cff:dead:bef1:100:13:3071/127",
        link_local_cidr="fe80::100:307:1/64",
    ),
    helper=OpenRStandaloneEndpoint(
        hostname="nrqeb006.ash6",
        member_interface="Ethernet3/2/1",
        ipv4_cidr="10.217.7.6/31",
        ipv6_cidr="2620:0:1cff:dead:bef1:100:13:3070/127",
        link_local_cidr="fe80::100:307:0/64",
    ),
    speed="400g",
)

NRQEB007_ASH6 = PhysicalInventory(
    device_name="nrqeb007.ash6",
    basset_pool="routing.qual",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    usage=frozenset({"cicd", "qual"}),
    primary_ixia_chassis_ip=IXIA03_ASH6,
    secondary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/35/1", "1/85"),
        ("Ethernet3/35/2", "1/86"),
        ("Ethernet3/35/3", "1/87"),
        ("Ethernet3/35/4", "1/88"),
    ],
    secondary_ixia_ports=[
        ("Ethernet3/36/1", "9/5"),
        ("Ethernet3/36/2", "9/6"),
        ("Ethernet3/36/3", "9/7"),
        ("Ethernet3/36/4", "9/8"),
    ],
    dut_bgp_as=65007,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    openr_configerator_path="taac/ebb_ci_cd_configs/nrqeb007_ash6_openr_config",
    openr_standalone_link=_NRQEB007_OPENR_LINK,
    peer_groups=_ebb_peer_groups(),
)


# ─── nrqeb008 ↔ nrqeb009 OpenR-standalone pair ───────────────────────────

_NRQEB008_OPENR_LINK = OpenRStandaloneLink(
    port_channel_id=100308,
    owner=OpenRStandaloneEndpoint(
        hostname="nrqeb008.ash6",
        member_interface="Ethernet3/1/1",
        ipv4_cidr="10.217.8.8/31",
        ipv6_cidr="2620:0:1cff:dead:bef1:100:13:3080/127",
        link_local_cidr="fe80::100:308:0/64",
    ),
    helper=OpenRStandaloneEndpoint(
        hostname="nrqeb009.ash6",
        member_interface="Ethernet3/1/1",
        ipv4_cidr="10.217.8.9/31",
        ipv6_cidr="2620:0:1cff:dead:bef1:100:13:3081/127",
        link_local_cidr="fe80::100:308:1/64",
    ),
    speed="400g",
)

NRQEB008_ASH6 = PhysicalInventory(
    device_name="nrqeb008.ash6",
    basset_pool="routing.qual",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    usage=frozenset({"cicd", "qual"}),
    primary_ixia_chassis_ip=IXIA03_ASH6,
    secondary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/35/1", "1/89"),
        ("Ethernet3/35/2", "1/90"),
        ("Ethernet3/35/3", "1/91"),
        ("Ethernet3/35/4", "1/92"),
    ],
    secondary_ixia_ports=[
        ("Ethernet3/36/1", "10/1"),
        ("Ethernet3/36/2", "10/2"),
        ("Ethernet3/36/3", "10/3"),
        ("Ethernet3/36/4", "10/4"),
    ],
    dut_bgp_as=65008,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    openr_configerator_path="taac/ebb_ci_cd_configs/nrqeb008_ash6_openr_config",
    openr_standalone_link=_NRQEB008_OPENR_LINK,
    peer_groups=_ebb_peer_groups(),
)

_NRQEB009_OPENR_LINK = OpenRStandaloneLink(
    port_channel_id=100309,
    owner=OpenRStandaloneEndpoint(
        hostname="nrqeb009.ash6",
        member_interface="Ethernet3/2/1",
        ipv4_cidr="10.217.9.9/31",
        ipv6_cidr="2620:0:1cff:dead:bef1:100:13:3091/127",
        link_local_cidr="fe80::100:309:1/64",
    ),
    helper=OpenRStandaloneEndpoint(
        hostname="nrqeb008.ash6",
        member_interface="Ethernet3/2/1",
        ipv4_cidr="10.217.9.8/31",
        ipv6_cidr="2620:0:1cff:dead:bef1:100:13:3090/127",
        link_local_cidr="fe80::100:309:0/64",
    ),
    speed="400g",
)

NRQEB009_ASH6 = PhysicalInventory(
    device_name="nrqeb009.ash6",
    basset_pool="routing.qual",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    usage=frozenset({"cicd", "qual"}),
    primary_ixia_chassis_ip=IXIA03_ASH6,
    secondary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/35/1", "1/93"),
        ("Ethernet3/35/2", "1/94"),
        ("Ethernet3/35/3", "1/95"),
        ("Ethernet3/35/4", "1/96"),
    ],
    secondary_ixia_ports=[
        ("Ethernet3/36/1", "10/5"),
        ("Ethernet3/36/2", "10/6"),
        ("Ethernet3/36/3", "10/7"),
        ("Ethernet3/36/4", "10/8"),
    ],
    dut_bgp_as=65009,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    openr_configerator_path="taac/ebb_ci_cd_configs/nrqeb009_ash6_openr_config",
    openr_standalone_link=_NRQEB009_OPENR_LINK,
    peer_groups=_ebb_peer_groups(),
)


# ─── NRQEB010 — IxANVL conformance single DUT ────────────────────────────
# Conformance-only: three IXIA11 links in DIface order, no OpenR pair and
# no secondary chassis. The DUT and IxANVL configs both resolve from this
# record, as they do from EB03_LAB_ASH6. The BGP AS is the one the
# conformance configs apply; NRQ devices are reached through FCR, so no
# lab login fields are set. Lane 1 (7/1) carries no light, so the rig
# uses lanes 2-4; lane order, not the lane numbers, decides DIface-N.
NRQEB010_ASH6 = PhysicalInventory(
    device_name="nrqeb010.ash6",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    usage=frozenset({"qual"}),
    primary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/36/2", "7/2"),
        ("Ethernet3/36/3", "7/3"),
        ("Ethernet3/36/4", "7/4"),
    ],
    dut_bgp_as=64981,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    peer_groups=_ebb_peer_groups(),
)


# ─── BAG002_SNC1 — qual-only, no OpenR (openr_standalone_link=None) ───────

BAG002_SNC1 = PhysicalInventory(
    device_name="bag002.snc1",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    usage=frozenset({"qual"}),
    primary_ixia_chassis_ip="ares1-my24520014",
    ixia_ports=[
        ("Ethernet3/25/1", "1/17"),
        ("Ethernet3/26/1", "1/18"),
        ("Ethernet3/27/1", "1/19"),
    ],
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    peer_groups=_ebb_peer_groups(),
)


# ─── EB0x lab physical inventories (Arista lab boxes in ASH6) ─────────────────────────
# The ebXX.lab.ash6 devices are lab boxes with admin/password auth
# (svc-netcastle_bot is not authorized). ``extras`` carries the shared lab
# credentials plus MockDeviceInfo fields (netwhoami returns ``#INVALID#`` for
# these devices, so ``get_common_setup_tasks`` needs a synthesized record).
EB01_LAB_ASH6 = PhysicalInventory(
    usage=frozenset({"qual"}),
    device_name="eb01.lab.ash6",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    primary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/1/3", "5/7"),
        ("Ethernet3/1/5", "5/8"),
        ("Ethernet4/36/1", "5/6"),
    ],
    dut_bgp_as=64981,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    lab_device_password_env_var="TAAC_EBB_LAB_DEVICE_PASSWORD",
    ssh_user="admin",
    host_driver_args=_lab_host_driver_args("eb01.lab.ash6"),
    oss_mock_device_data=_lab_oss_mock_device_data("eb01.lab.ash6", network_type="EBB"),
    peer_groups=_ebb_peer_groups(),
    extras={
        # Retained for ``factories/bgp_update_group.py`` which still reads
        # these keys inline (Wave 2 candidate: fold into the promoted
        # ``host_driver_args`` / ``oss_mock_device_data`` fields).
        "lab_admin_username": "admin",
        "mock_device_hardware": "ARISTA_7516",
        "mock_device_role": "EB",
        "mock_device_asic": "JERICHO",
        "mock_device_dc": "ash6",
        "mock_device_region": "ash",
        "mock_device_asset_id": 12345,
        "mock_device_network_area": "BACKBONE",
        "mock_device_network_type": "EBB",
    },
)

EB02_LAB_ASH6 = PhysicalInventory(
    usage=frozenset({"qual"}),
    device_name="eb02.lab.ash6",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    primary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/1/3", "6/2"),
        ("Ethernet3/1/5", "6/3"),
    ],
    dut_bgp_as=64981,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    lab_device_password_env_var="TAAC_EBB_LAB_DEVICE_PASSWORD",
    ssh_user="admin",
    host_driver_args=_lab_host_driver_args("eb02.lab.ash6"),
    oss_mock_device_data=_lab_oss_mock_device_data("eb02.lab.ash6", network_type="EBB"),
    peer_groups=_ebb_peer_groups(),
    extras={
        # Retained for ``factories/bgp_update_group.py`` which still reads
        # these keys inline (Wave 2 candidate: fold into the promoted
        # ``host_driver_args`` / ``oss_mock_device_data`` fields).
        "lab_admin_username": "admin",
        "mock_device_hardware": "ARISTA_7516",
        "mock_device_role": "EB",
        "mock_device_asic": "JERICHO",
        "mock_device_dc": "ash6",
        "mock_device_region": "ash",
        "mock_device_asset_id": 12345,
        "mock_device_network_area": "BACKBONE",
        "mock_device_network_type": "EBB",
    },
)

EB03_LAB_ASH6 = PhysicalInventory(
    usage=frozenset({"qual"}),
    device_name="eb03.lab.ash6",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    primary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/1/2", "6/5"),
        ("Ethernet3/36/3", "11/2"),
        ("Ethernet3/36/1", "11/1"),
    ],
    dut_bgp_as=64981,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    lab_device_password_env_var="TAAC_EBB_LAB_DEVICE_PASSWORD",
    ssh_user="admin",
    host_driver_args=_lab_host_driver_args("eb03.lab.ash6"),
    oss_mock_device_data=_lab_oss_mock_device_data("eb03.lab.ash6", network_type="EBB"),
    peer_groups=_ebb_peer_groups(),
    extras={
        # Retained for ``factories/bgp_update_group.py`` which still reads
        # these keys inline (Wave 2 candidate: fold into the promoted
        # ``host_driver_args`` / ``oss_mock_device_data`` fields).
        "lab_admin_username": "admin",
        "mock_device_hardware": "ARISTA_7516",
        "mock_device_role": "EB",
        "mock_device_asic": "JERICHO",
        "mock_device_dc": "ash6",
        "mock_device_region": "ash",
        "mock_device_asset_id": 12345,
        "mock_device_network_area": "BACKBONE",
        "mock_device_network_type": "EBB",
    },
)

EB04_LAB_ASH6 = PhysicalInventory(
    usage=frozenset({"qual"}),
    device_name="eb04.lab.ash6",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    primary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/1/1", "6/7"),
        ("Ethernet3/1/3", "6/8"),
    ],
    dut_bgp_as=64981,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    lab_device_password_env_var="TAAC_EBB_LAB_DEVICE_PASSWORD",
    ssh_user="admin",
    host_driver_args=_lab_host_driver_args("eb04.lab.ash6"),
    # NOTE: legacy eb04 source omits ``network_type`` on MockDeviceInfo,
    # unlike eb01/eb03 which set ``network_type="EBB"``. Preserved verbatim.
    oss_mock_device_data=_lab_oss_mock_device_data("eb04.lab.ash6"),
    peer_groups=_ebb_peer_groups(),
    extras={
        # Retained for ``factories/bgp_update_group.py`` which still reads
        # these keys inline (Wave 2 candidate: fold into the promoted
        # ``host_driver_args`` / ``oss_mock_device_data`` fields).
        "lab_admin_username": "admin",
        "mock_device_hardware": "ARISTA_7516",
        "mock_device_role": "EB",
        "mock_device_asic": "JERICHO",
        "mock_device_dc": "ash6",
        "mock_device_region": "ash",
        "mock_device_asset_id": 12345,
        "mock_device_network_area": "BACKBONE",
    },
)


# ─── Dev-only EB test device ──────────────────────────────────────────────
# ``bgp.eb.test.ash6`` is a per-developer BGP++ test switch — a lab box like
# the eb0x boxes above, but with IPv6 endpoint overrides because its regular
# loopback is not reachable from devservers. Only used by the queue-memory
# monitor testconfig.
EB_TEST_DEVICE = PhysicalInventory(
    usage=frozenset({"qual"}),
    device_name="bgp.eb.test.ash6",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    primary_ixia_chassis_ip=IXIA11_ASH6,
    ixia_ports=[
        ("Ethernet3/1/5", "5/3"),
        ("Ethernet3/1/3", "5/2"),
    ],
    dut_bgp_as=64981,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    lab_device_password_env_var="TAAC_EBB_LAB_DEVICE_PASSWORD",
    ssh_user="admin",
    # Extra host-driver JSON kwarg beyond the standard username/password
    # pair — routes the BGP++ thrift RPC to a specific IPv6 address on
    # the dev physical_inventory (device's regular loopback is not reachable from
    # devservers).
    host_driver_args=_lab_host_driver_args(
        "bgp.eb.test.ash6",
        extra_kwargs={"bgp_ip": "2401:db00:2066:304a::1001"},
    ),
    oss_mock_device_data=_lab_oss_mock_device_data(
        "bgp.eb.test.ash6", network_type="EBB"
    ),
    peer_groups=_ebb_peer_groups(),
    extras={
        "eapi_endpoint": "2401:db00:2066:304a::1001",
        # Retained for ``factories/bgp_update_group.py`` which still reads
        # these keys inline (Wave 2 candidate: fold into the promoted
        # ``host_driver_args`` / ``oss_mock_device_data`` fields).
        "lab_admin_username": "admin",
        "host_driver_extra_kwargs": {
            "bgp_ip": "2401:db00:2066:304a::1001",
        },
        "mock_device_hardware": "ARISTA_7516",
        "mock_device_role": "EB",
        "mock_device_asic": "JERICHO",
        "mock_device_dc": "ash6",
        "mock_device_region": "ash",
        "mock_device_asset_id": 12345,
        "mock_device_network_area": "BACKBONE",
        "mock_device_network_type": "EBB",
    },
)


# ─── Production Arista EB in SNC1 ─────────────────────────────────────────
# ``jsw002.m001.snc1`` is a production EB Arista used by the non-lab
# ARISTA_MIMIC_EBB_TEST_FULL_SCALE testconfig. The legacy source declares no
# ``direct_ixia_connections`` (topology is discovered at runtime), so the
# chassis + port map is intentionally left empty here — Wave 5B will surface
# the discovered ports if/when the factory needs them.
JSW002_M001_SNC1 = PhysicalInventory(
    usage=frozenset({"adhoc"}),
    device_name="jsw002.m001.snc1",
    network_role=NetworkRole.EB,
    default_physical_interface_profile=_EBB_PHYSICAL_INTERFACE_PROFILE,
    primary_ixia_chassis_ip="",
    dut_bgp_as=64981,
    bgpcpp_configerator_path=_EBB_BGPCPP_PATH,
    peer_groups=_ebb_peer_groups(),
    extras={
        # Reference DUT interfaces from the legacy source, kept here so Wave
        # 5B factories can wire up ixia setup without re-parsing the legacy
        # testconfig files.
        "dut_iface_ebgp": "Ethernet3/8/1",
        "dut_iface_ibgp": "Ethernet3/8/5",
        "dut_iface_bgp_mon": "Ethernet3/9/1",
    },
)

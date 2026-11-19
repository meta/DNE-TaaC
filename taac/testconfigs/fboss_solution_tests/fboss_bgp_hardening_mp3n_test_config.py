# Copyright (c) Meta Platforms, Inc. and affiliates.

"""Minipack3N (NVIDIA Spectrum-4) BGP hardening TestConfig.

IPv6-only port of `FBOSS_BGP_HARDENING_MP3BA_FA002_DU001_QZA1`: the same 13
BGP longevity playbooks at the same session and prefix scale, with a smaller
downlink NDP stressor. MP3N has no IPv4, so every IPv4 role of the original
(main peers, rogue session flap) is an IPv6 role here, and the ARP stressors
are gone.

Spectrum ASICs accept neighbors from only one MAC per physical port. Each IXIA
port therefore has one `NDP_HANDLER` device group owning every peer address,
with every BGP role a `CHAINED_0` device group on top of it, as in
`ai_bb/mp3n_bgp_path_scale_test_config.py`. The NDP stressor is the only
handler on a port of its own, so toggling it withdraws its neighbors without
touching the peers. All addresses sit in the /64 that is already on each DUT
port, behind the DUT's `::a`.
"""

import ipaddress
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

from ixia.ixia import types as ixia_types
from taac.constants import (
    BROADCAST_DST_MAC_ADDRESS,
    DEFAULT_SRC_MAC_ADDRESS,
    ROGUE_SRC_MAC_ADDRESS,
)
from taac.health_checks.healthcheck_definitions import (
    create_bgp_session_establish_check,
    create_core_dumps_snapshot_check,
    create_cpu_utilization_check,
    create_device_core_dumps_check,
    create_ixia_packet_loss_check,
    create_memory_utilization_check,
    create_prefix_limit_check,
    create_service_restart_check,
    create_systemctl_active_state_check,
    create_unclean_exit_check,
)
from taac.playbooks.playbook_definitions import (
    BGP_HARDENING_TIMING_PROFILES,
    create_bgp_longevity_ndp_device_group_toggle_playbook,
    create_longevity_continuous_toggle_device_group_playbook,
    get_longevity_playbooks,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_ixia_api_step,
    create_longevity_step,
    create_service_convergence_step,
    create_validation_step,
)
from taac.task_definitions import (
    create_coop_apply_patchers_task,
    create_coop_register_patcher_task,
    create_coop_unregister_patchers_task,
    create_run_commands_on_shell_task,
    create_wait_for_agent_convergence_task,
)
from taac.testconfigs.fboss_solution_tests.fboss_bgp_hardening_mp3ba_fa002_du001_qza1_test_config import (
    MP3BA_BGP_PLAYBOOK_NAMES,
)
from taac.testconfigs.routing.util.bgp_dc_tc_checks import (
    _apply_tc_checks_to_playbooks,
    _PERMIT_ALL_POLICY_TERM,
)
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import (
    Params,
    Playbook,
    PointInTimeHealthCheck,
    Service,
    TestConfig,
    ValidationStage,
)


MP3N_BGP_PLAYBOOK_NAMES: tuple[str, ...] = MP3BA_BGP_PLAYBOOK_NAMES

_NDP_HANDLER_INDEX = 0
_MAIN_V6_INDEX = 1
_PREFIX_GROUP_INDEX = 2
_DUT_HOST = 0xA
_FIRST_IXIA_HOST = 0x100
_CHAINED = f"CHAINED_{_NDP_HANDLER_INDEX}:"
# A chained group does not answer NDP for addresses its parent does not own,
# and IXIA delivers unicast frames for a MAC to only one device group, so the
# stressor is a handler alone on its own port.
_STRESSOR_HANDLER = "NDP_HANDLER:"
# Chenab (Spectrum-4) sets no NDP table size, so the agent's `max_ndp_entries`
# (4000) is the whole budget, shared with the DUT's real neighbors.
_MAX_TEST_NDP_ENTRIES = 3000

# The original's default `NDP` would also match `NDP_HANDLER`, and disabling
# the handler takes every peer on the port down with it.
_CONTINUOUS_TOGGLE_REGEX = "ROGUE|NO_PACKET_LOSS_EXPECTED|ECMP_1|NDP_STRESSOR"

# MP3NM has a single hardware agent and runs no Open/R, so the checks are
# scoped to the services that exist (same lists as the MP3N CPU queue config).
_SYSTEMCTL_SERVICES: list[hc_types.Service] = [
    service
    for service in hc_types.Service
    if service != hc_types.Service.FBOSS_HW_AGENT_1
]
_SERVICE_RESTART_SERVICES: tuple[str, ...] = (
    "bgpd",
    "fboss_sw_agent",
    "fsdb",
    "qsfp_service",
    "wedge_agent",
)
_EXPECTED_BGP_CRASH_CORES = ["bgpd_cpp", "bgpd_main"]


@dataclass(frozen=True)
class Mp3nHardeningPort:
    """IXIA port whose devices all sit behind one IXIA MAC.

    Attributes:
        interface: DUT port.
        network: The /64 already on the DUT port, without the host part
            (`2401:db00:209e:2` for `2401:db00:209e:2::a/64`).
        ixia_chassis_ip / ixia_port: Direct IXIA connection.
    """

    interface: str
    network: str
    ixia_chassis_ip: str
    ixia_port: str


@dataclass(frozen=True)
class PeerRole:
    """One chained BGP device group: `peer_count` sessions sharing a prefix set.

    Every peer of the role advertises the same `prefix_count` /64s, so the DUT
    holds `prefix_count` prefixes with `peer_count` paths each.
    """

    tag: str
    device_group_index: int
    peer_count: int
    remote_as_4byte: int
    remote_as_4byte_step: int
    prefix_count: int
    starting_prefix: str
    prefix_step: str = "0:0:0:0::0"
    prefix_flap: bool = False
    session_flap: bool = False
    enabled: bool = True


def _address(port: Mp3nHardeningPort, host: int) -> str:
    """Canonical form, which is how the DUT reports its BGP peers."""
    return str(ipaddress.ip_address(f"{port.network}::{host:x}"))


def _addresses(
    port: Mp3nHardeningPort, first_host: int
) -> taac_types.IpAddressesConfig:
    return taac_types.IpAddressesConfig(
        starting_ip=_address(port, first_host),
        increment_ip="::1",
        gateway_starting_ip=_address(port, _DUT_HOST),
        gateway_increment_ip="::",
        mask=64,
    )


@dataclass(frozen=True)
class _PortLayout:
    port: Mp3nHardeningPort
    roles: tuple[PeerRole, ...]

    def first_host(self, role: PeerRole) -> int:
        offset = 0
        for other in self.roles:
            if other is role:
                return _FIRST_IXIA_HOST + offset
            offset += other.peer_count
        raise ValueError(f"{role.tag} is not on {self.port.interface}")

    @property
    def peer_count(self) -> int:
        return sum(role.peer_count for role in self.roles)

    def peer_addresses(self, role: PeerRole) -> list[str]:
        first = self.first_host(role)
        return [_address(self.port, first + i) for i in range(role.peer_count)]

    def validate(self) -> None:
        indices = [role.device_group_index for role in self.roles]
        if len(set(indices)) != len(indices) or _NDP_HANDLER_INDEX in indices:
            raise ValueError(f"{self.port.interface}: device group indices collide")


@dataclass(frozen=True)
class NdpStressor:
    """`count` IPv6 neighbors answered by one handler alone on `port`."""

    port: Mp3nHardeningPort
    tag: str
    count: int


def _role_device_group(
    layout: _PortLayout, role: PeerRole, communities: list[str]
) -> taac_types.DeviceGroupConfig:
    return taac_types.DeviceGroupConfig(
        device_group_index=role.device_group_index,
        tag_name=f"{_CHAINED}{role.tag}",
        enable=role.enabled,
        multiplier=role.peer_count,
        v6_addresses_config=_addresses(layout.port, layout.first_host(role)),
        v6_bgp_config=taac_types.BgpConfig(
            local_as_4_bytes=role.remote_as_4byte,
            local_as_increment=role.remote_as_4byte_step,
            enable_4_byte_local_as=True,
            is_confed=False,
            bgp_capabilities=[ixia_types.BgpCapability.IpV6Unicast],
            hold_timer=30,
            keepalive_timer=10,
            peer_flap_config=ixia_types.BgpFlapConfig(
                uptime_in_sec=120, downtime_in_sec=15
            )
            if role.session_flap
            else None,
            route_scales=[
                taac_types.RouteScaleSpec(
                    network_group_index=0,
                    v6_route_scale=taac_types.RouteScale(
                        multiplier=1,
                        prefix_count=role.prefix_count,
                        prefix_length=64,
                        starting_prefixes=role.starting_prefix,
                        prefix_step=role.prefix_step,
                        bgp_communities=communities,
                        ip_address_family=ixia_types.IpAddressFamily.IPV6,
                        prefix_flap_config=ixia_types.BgpFlapConfig(
                            uptime_in_sec=15, downtime_in_sec=15
                        )
                        if role.prefix_flap
                        else None,
                    ),
                ),
            ],
        ),
    )


def _port_config(
    device_name: str, layout: _PortLayout, communities: list[str]
) -> taac_types.BasicPortConfig:
    return taac_types.BasicPortConfig(
        endpoint=f"{device_name}:{layout.port.interface}",
        device_group_configs=[
            taac_types.DeviceGroupConfig(
                device_group_index=_NDP_HANDLER_INDEX,
                tag_name="NDP_HANDLER",
                multiplier=layout.peer_count,
                v6_addresses_config=_addresses(layout.port, _FIRST_IXIA_HOST),
            ),
            *[_role_device_group(layout, role, communities) for role in layout.roles],
        ],
    )


def _stressor_port_config(
    device_name: str, stressor: NdpStressor
) -> taac_types.BasicPortConfig:
    return taac_types.BasicPortConfig(
        endpoint=f"{device_name}:{stressor.port.interface}",
        device_group_configs=[
            taac_types.DeviceGroupConfig(
                device_group_index=_NDP_HANDLER_INDEX,
                tag_name=f"{_STRESSOR_HANDLER}{stressor.tag}",
                multiplier=stressor.count,
                v6_addresses_config=_addresses(stressor.port, _FIRST_IXIA_HOST),
            ),
        ],
    )


def _dut_peer_configs(
    layout: _PortLayout, peer_group_name: str
) -> list[dict[str, str]]:
    return [
        {
            "local_addr": _address(layout.port, _DUT_HOST),
            "peer_addr": address,
            "peer_group_name": peer_group_name,
            "remote_as_4_byte": str(
                role.remote_as_4byte + i * role.remote_as_4byte_step
            ),
            "description": f"IXIA {role.tag} {i}",
        }
        for role in layout.roles
        for i, address in enumerate(layout.peer_addresses(role))
    ]


def _directional_traffic(
    device_name: str, name: str, downlink: str, uplink: str, device_group_index: int
) -> taac_types.BasicTrafficItemConfig:
    return taac_types.BasicTrafficItemConfig(
        name=name,
        bidirectional=True,
        merge_destinations=True,
        line_rate=10,
        src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
        src_endpoints=[
            taac_types.TrafficEndpoint(
                name=f"{device_name}:{uplink}",
                device_group_index=device_group_index,
                network_group_index=0,
            )
        ],
        dest_endpoints=[
            taac_types.TrafficEndpoint(
                name=f"{device_name}:{downlink}",
                device_group_index=device_group_index,
                network_group_index=0,
            )
        ],
        traffic_type=ixia_types.TrafficType.IPV6,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
    )


def _l2_broadcast_traffic(
    device_name: str, name: str, downlink: str, src_mac: str, mac_count: int
) -> taac_types.BasicTrafficItemConfig:
    def field(regex: str, start: str, step: str, count: int) -> taac_types.Field:
        return taac_types.Field(
            query=ixia_types.Query(regex=regex),
            attrs_json=json.dumps(
                {
                    "ValueType": "increment",
                    "StartValue": start,
                    "StepValue": step,
                    "CountValue": count,
                }
            ),
        )

    endpoint = taac_types.TrafficEndpoint(
        name=f"{device_name}:{downlink}", device_group_index=_NDP_HANDLER_INDEX
    )
    return taac_types.BasicTrafficItemConfig(
        name=name,
        src_endpoints=[endpoint],
        dest_endpoints=[endpoint],
        line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
        line_rate=2000,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
        traffic_type=ixia_types.TrafficType.RAW,
        allow_self_destined=True,
        bidirectional=False,
        packet_headers=[
            taac_types.PacketHeader(
                query=ixia_types.Query(
                    regex="^ethernet$",
                    query_type=ixia_types.QueryType.STACK_TYPE_ID,
                ),
                fields=[
                    field(
                        "Destination MAC Address",
                        BROADCAST_DST_MAC_ADDRESS,
                        "00:00:00:00:00:00",
                        1,
                    ),
                    field(
                        "Source MAC Address", src_mac, "00:00:00:00:00:01", mac_count
                    ),
                ],
            ),
        ],
    )


@dataclass(frozen=True)
class _TrafficNames:
    main_directional: str
    prefix_group_directional: str
    layer3: str
    lossy: tuple[str, str]

    @property
    def lossless(self) -> list[str]:
        return [self.main_directional, self.prefix_group_directional, self.layer3]

    @property
    def all(self) -> list[str]:
        return [*self.lossless, *self.lossy]


def _traffic_names(device_name: str) -> _TrafficNames:
    prefix = device_name.upper()
    return _TrafficNames(
        main_directional=f"{prefix}_V6_DIRECTIONAL_TRAFFIC_BETWEEN_DOWNLINK_AND_UPLINK",
        prefix_group_directional=(
            f"{prefix}_V6_PREFIX_GROUP_DIRECTIONAL_TRAFFIC_BETWEEN_DOWNLINK_AND_UPLINK"
        ),
        layer3=f"{prefix}_V6_LAYER3_TRAFFIC_DOWNLINK_AND_UPLINK",
        lossy=(
            f"{prefix}_GOOD_BUT_LOSSY_NDP_TRAFFIC",
            f"{prefix}_LOSSY_ROGUE_NDP_TRAFFIC",
        ),
    )


def _traffic_items(
    device_name: str,
    downlink: str,
    uplink: str,
    stressor: NdpStressor,
    good_mac_entry_count: int,
) -> list[taac_types.BasicTrafficItemConfig]:
    names = _traffic_names(device_name)
    return [
        taac_types.BasicTrafficItemConfig(
            name=names.layer3,
            bidirectional=True,
            merge_destinations=True,
            line_rate=10,
            src_dest_mesh=ixia_types.SrcDestMeshType.ONE_TO_ONE,
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{uplink}",
                    device_group_index=_NDP_HANDLER_INDEX,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{stressor.port.interface}",
                    device_group_index=_NDP_HANDLER_INDEX,
                )
            ],
            traffic_type=ixia_types.TrafficType.IPV6,
            tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
        ),
        _directional_traffic(
            device_name,
            names.main_directional,
            downlink,
            uplink,
            _MAIN_V6_INDEX,
        ),
        _directional_traffic(
            device_name,
            names.prefix_group_directional,
            downlink,
            uplink,
            _PREFIX_GROUP_INDEX,
        ),
        _l2_broadcast_traffic(
            device_name,
            names.lossy[0],
            downlink,
            DEFAULT_SRC_MAC_ADDRESS,
            good_mac_entry_count,
        ),
        _l2_broadcast_traffic(
            device_name, names.lossy[1], downlink, ROGUE_SRC_MAC_ADDRESS, 1
        ),
    ]


def _fault_windows(names: _TrafficNames) -> dict[str, list[str]]:
    """Traffic each playbook disrupts on purpose; the rest must stay lossless."""
    directional = [names.main_directional, names.prefix_group_directional]
    return {
        **{
            name: directional
            for name in (
                "test_longevity_prefix_flap_all_prefixes",
                "test_longevity_activate_deactivate_all_prefixes",
                "test_longevity_session_flap_all_prefixes",
                "test_longevity_prefix_flap_all_prefixes_plus_bgp_restart",
                "test_longevity_session_flap_all_prefixes_plus_bgp_restart",
            )
        },
        "test_longevity_continuous_toggle_device_group": [
            names.prefix_group_directional,
            names.layer3,
        ],
        "test_longevity_cold_start_with_prefix_and_session_oscillations": [
            *directional,
            names.layer3,
        ],
        "test_bgp_longevity_ndp_device_group_toggle": [names.layer3],
    }


def _stable_traffic_check(
    names: _TrafficNames, clear_traffic_stats: bool
) -> PointInTimeHealthCheck:
    """`clear_traffic_stats` belongs on prechecks only: IXIA counters run from
    setup, while neighbors were still resolving, and a postcheck must measure
    the playbook's own window."""
    return create_ixia_packet_loss_check(
        thresholds=[
            hc_types.PacketLossThreshold(
                names=list(names.lossy), expect_packet_loss=True
            ),
            hc_types.PacketLossThreshold(
                names=names.lossless,
                metric=hc_types.PacketLossMetric.DURATION,
                str_value="0.1",
                expect_packet_loss=False,
            ),
        ],
        clear_traffic_stats=clear_traffic_stats,
    )


def _fault_window_check(
    names: _TrafficNames, affected: list[str]
) -> PointInTimeHealthCheck:
    unaffected = [name for name in names.lossless if name not in affected]
    return create_ixia_packet_loss_check(
        thresholds=[
            hc_types.PacketLossThreshold(
                names=affected,
                metric=hc_types.PacketLossMetric.PERCENTAGE,
                str_value="100",
                expect_packet_loss=False,
            ),
            *(
                [
                    hc_types.PacketLossThreshold(
                        names=unaffected,
                        metric=hc_types.PacketLossMetric.DURATION,
                        str_value="0.1",
                        expect_packet_loss=False,
                    )
                ]
                if unaffected
                else []
            ),
            hc_types.PacketLossThreshold(
                names=list(names.lossy), expect_packet_loss=True
            ),
        ],
        clear_traffic_stats=False,
        check_id="intentional_churn_window",
    )


def _with_recovered_traffic_check(
    playbook: Playbook, windows: dict[str, list[str]], names: _TrafficNames
) -> Playbook:
    """Judge the churn window leniently, then require clean traffic afterwards."""
    affected = windows.get(playbook.name)
    if affected is None:
        return playbook
    steps = [
        create_validation_step(
            point_in_time_checks=[_fault_window_check(names, affected)],
            stage=ValidationStage.POST_TEST,
        )
    ]
    if playbook.name == "test_longevity_continuous_toggle_device_group":
        assert playbook.cleanup_steps
        steps.append(playbook.cleanup_steps[-1])
    steps.extend(
        [
            create_service_convergence_step(services=[Service.AGENT, Service.BGP]),
            create_ixia_api_step(api_name="clear_traffic_stats", args_dict={}),
            create_longevity_step(duration=30),
        ]
    )
    return playbook(stages=[*(playbook.stages or []), create_steps_stage(steps=steps)])


def _without_bgp_session_checks(playbook: Playbook) -> Playbook:
    """Drop the playbooks' fixed-address session checks; the config-level one
    lists this testbed's good peers."""

    def keep(
        checks: Sequence[PointInTimeHealthCheck] | None,
    ) -> list[PointInTimeHealthCheck]:
        return [
            check
            for check in checks or []
            if check.name != hc_types.CheckName.BGP_SESSION_ESTABLISH_CHECK
        ]

    return playbook(
        prechecks=keep(playbook.prechecks), postchecks=keep(playbook.postchecks)
    )


def _scope_service_restart_check(
    check: PointInTimeHealthCheck,
) -> PointInTimeHealthCheck:
    if check.name != hc_types.CheckName.SERVICE_RESTART_CHECK:
        return check
    params = check.check_params or Params()
    payload = json.loads(params.json_params) if params.json_params else {}
    payload["services"] = [
        service
        for service in payload.get("services", _SERVICE_RESTART_SERVICES)
        if service in _SERVICE_RESTART_SERVICES
    ] or list(_SERVICE_RESTART_SERVICES)
    return check(check_params=params(json_params=json.dumps(payload)))


def _finalize_playbook(playbook: Playbook) -> Playbook:
    """Scope service checks to MP3N and accept the cores a bgpd crash leaves."""
    postchecks = [_scope_service_restart_check(c) for c in playbook.postchecks or []]
    snapshot_checks = list(playbook.snapshot_checks or [])
    if playbook.name == "test_bgp_longevity_bgpd_crash":
        postchecks = [
            create_device_core_dumps_check(
                core_dump_processes_to_ignore=_EXPECTED_BGP_CRASH_CORES
            )
            if check.name == hc_types.CheckName.DEVICE_CORE_DUMPS_CHECK
            else check
            for check in postchecks
        ]
        snapshot_checks = [
            create_core_dumps_snapshot_check(
                core_dump_processes_to_ignore=_EXPECTED_BGP_CRASH_CORES
            )
            if check.name == hc_types.CheckName.CORE_DUMPS_CHECK
            else check
            for check in snapshot_checks
        ]
    return playbook(
        prechecks=[_scope_service_restart_check(c) for c in playbook.prechecks or []],
        postchecks=postchecks,
        snapshot_checks=snapshot_checks,
    )


def _create_playbooks(
    device_name: str, stressor: NdpStressor, names: _TrafficNames
) -> list[Playbook]:
    profile = BGP_HARDENING_TIMING_PROFILES["npi"]
    ndp_regex = (
        f"^DEVICE_GROUP_D{_NDP_HANDLER_INDEX}_"
        f"{re.escape(f'{device_name}:{stressor.port.interface}'.upper())}_"
        f"{re.escape(_STRESSOR_HANDLER + stressor.tag)}$"
    )
    playbooks = get_longevity_playbooks(
        device_name=device_name,
        include_extended_bgp_hardening_playbooks=True,
        bgp_longevity_ndp_device_group_regex=ndp_regex,
    )
    if tuple(pb.name for pb in playbooks) != MP3N_BGP_PLAYBOOK_NAMES:
        raise ValueError("MP3N BGP hardening must run the 13 MP3BA BGP playbooks")
    ndp = create_bgp_longevity_ndp_device_group_toggle_playbook(
        device_group_name_regex=ndp_regex,
        expected_device_group_matches=1,
        uptime_s=900,
        downtime_s=120,
        cycles=3,
    )
    replacements = {
        "test_longevity_continuous_toggle_device_group": (
            create_longevity_continuous_toggle_device_group_playbook(
                cycles=profile["device_group_toggle_cycles"],
                state_duration_s=profile["device_group_toggle_state_s"],
                device_group_name_regex=_CONTINUOUS_TOGGLE_REGEX,
            )
        ),
        "test_bgp_longevity_ndp_device_group_toggle": ndp(
            description=(
                f"BGP longevity: toggle {stressor.count} IPv6 neighbors for 60 minutes "
                "(15m up / 2m down, then 9m up)"
            ),
            stages=[
                *(ndp.stages or []),
                create_steps_stage(
                    steps=[
                        *(ndp.cleanup_steps or []),
                        create_longevity_step(duration=540),
                    ]
                ),
            ],
        ),
    }
    windows = _fault_windows(names)
    return [
        _with_recovered_traffic_check(
            _without_bgp_session_checks(replacements.get(pb.name, pb)), windows, names
        )
        for pb in playbooks
    ]


def _memory_check(fsdb_bytes: int, sw_agent_bytes: int) -> PointInTimeHealthCheck:
    return create_memory_utilization_check(
        threshold=5 * (1024**3),
        threshold_by_service={
            "bgpd": 4.5 * (1024**3),
            "fsdb": fsdb_bytes,
            "qsfp_service": 2 * (1024**3),
            "fboss_sw_agent": sw_agent_bytes,
            "fboss_hw_agent@0": 8 * (1024**3),
            "wedge_agent": 8 * (1024**3),
        },
        start_time_jq_var="test_case_start_time",
    )


def create_mp3n_bgp_hardening_test_config(
    *,
    test_config_name: str,
    device_name: str,
    local_mac_address: str,
    downlink: Mp3nHardeningPort,
    uplink: Mp3nHardeningPort,
    peer_group_v6: str,
    downlink_roles: tuple[PeerRole, ...],
    uplink_roles: tuple[PeerRole, ...],
    ndp_stressor_port: Mp3nHardeningPort,
    ndp_stressor_count: int,
    communities: list[str],
    prefix_limit: str,
    per_peer_max_route_limit: str,
    good_mac_entry_count: int = 100,
    basset_pool: str | None = None,
) -> TestConfig:
    """Build the IPv6-only MP3N BGP hardening TestConfig.

    Args:
        downlink / uplink: IXIA ports carrying the BGP peers.
        peer_group_v6: Existing V6 peer group every IXIA peer joins. It is set
            to accept and advertise everything.
        downlink_roles / uplink_roles: Chained BGP device groups per port. The
            `NO_V6_PACKET_LOSS_EXPECTED` and `NO_PACKET_LOSS_EXPECTED` roles are
            the good peers whose sessions the config-level check requires.
        ndp_stressor_port / ndp_stressor_count: IXIA port and size of the NDP
            stressor that `test_bgp_longevity_ndp_device_group_toggle` flaps. The
            L3 stressor traffic runs between it and the uplink peers' addresses.
    """
    layouts = [_PortLayout(downlink, downlink_roles), _PortLayout(uplink, uplink_roles)]
    for layout in layouts:
        layout.validate()
    stressor = NdpStressor(
        ndp_stressor_port, "DOWNLINK_NDP_STRESSOR", ndp_stressor_count
    )
    ports = [downlink, uplink, stressor.port]
    ndp_entries = sum(layout.peer_count for layout in layouts) + stressor.count
    if ndp_entries >= _MAX_TEST_NDP_ENTRIES:
        raise ValueError(
            f"{ndp_entries} IXIA neighbors; keep them under {_MAX_TEST_NDP_ENTRIES}"
        )
    good_peer_addresses = [
        address
        for layout in layouts
        for role in layout.roles
        if role.device_group_index in (_MAIN_V6_INDEX, _PREFIX_GROUP_INDEX)
        for address in layout.peer_addresses(role)
    ]
    bgp_session_check = create_bgp_session_establish_check(
        ignore_all_prefixes_except=good_peer_addresses,
        expected_established_sessions=len(good_peer_addresses),
        verbose=True,
    )
    names = _traffic_names(device_name)
    service_restart_check = create_service_restart_check(
        services=list(_SERVICE_RESTART_SERVICES)
    )
    tc_prechecks = [
        create_systemctl_active_state_check(services=_SYSTEMCTL_SERVICES),
        _stable_traffic_check(names, clear_traffic_stats=True),
        create_prefix_limit_check(prefix_limit=prefix_limit),
        create_unclean_exit_check(),
        _memory_check(fsdb_bytes=7 * (1024**3), sw_agent_bytes=12 * (1024**3)),
        bgp_session_check,
    ]
    tc_postchecks = [
        create_systemctl_active_state_check(services=_SYSTEMCTL_SERVICES),
        create_device_core_dumps_check(),
        _stable_traffic_check(names, clear_traffic_stats=False),
        create_prefix_limit_check(prefix_limit=prefix_limit),
        bgp_session_check,
        create_unclean_exit_check(),
        _memory_check(fsdb_bytes=5 * (1024**3), sw_agent_bytes=9 * (1024**3)),
        create_cpu_utilization_check(
            threshold=400.0, start_time_jq_var="test_case_start_time"
        ),
        service_restart_check,
    ]
    playbooks = _apply_tc_checks_to_playbooks(
        playbooks=_create_playbooks(device_name, stressor, names),
        tc_prechecks=tc_prechecks,
        tc_postchecks=tc_postchecks,
        tc_snapshot_checks=[create_core_dumps_snapshot_check()],
    )
    peer_configs = [
        peer for layout in layouts for peer in _dut_peer_configs(layout, peer_group_v6)
    ]
    policy = f"PROPAGATE_EVERYTHING_{peer_group_v6}"

    def register(config_name: str, patcher_name: str, py_func_name: str, args):
        return create_coop_register_patcher_task(
            hostname=device_name,
            config_name=config_name,
            patcher_name=patcher_name,
            task_name="coop_register_patcher",
            patcher_args=args,
            py_func_name=py_func_name,
        )

    return TestConfig(
        name=test_config_name,
        ixia_protocol_verification_timeout=300,
        skip_ixia_protocol_verification=True,
        basset_pool=basset_pool,
        ixia_config_cache=taac_types.IxiaConfigCache(enabled=False),
        endpoints=[
            taac_types.Endpoint(
                name=device_name,
                ixia_ports=[port.interface for port in ports],
                dut=True,
                mac_address=local_mac_address,
                direct_ixia_connections=[
                    taac_types.DirectIxiaConnection(
                        interface=port.interface,
                        ixia_chassis_ip=port.ixia_chassis_ip,
                        ixia_port=port.ixia_port,
                    )
                    for port in ports
                ],
            ),
        ],
        setup_tasks=[
            create_coop_unregister_patchers_task(device_name),
            # Neighbors left by an earlier IXIA session can carry another MAC,
            # and the ASIC then rejects every neighbor on that port.
            create_run_commands_on_shell_task(
                hostname=device_name,
                cmds=[
                    "fboss2 clear ndp "
                    + " ".join(f"{port.network}::/64" for port in ports)
                ],
            ),
            create_coop_apply_patchers_task(hostnames=[device_name]),
            create_wait_for_agent_convergence_task([device_name]),
            register(
                "bgpcpp",
                "a_remove_bgp_peers",
                "remove_bgp_peers",
                {"delete_all": "True"},
            ),
            register(
                "bgpcpp",
                "configure_bgp_switch_limit",
                "configure_bgp_switch_limit",
                {"prefix_limit": prefix_limit},
            ),
            register(
                "agent",
                "enable_port_all_ixia_ports",
                "change_port_admin_state",
                {port.interface: "enable" for port in ports},
            ),
            *[
                register(
                    "bgpcpp",
                    f"a_add_bgp_policy_statement_{policy}_{direction}",
                    "add_bgp_policy_statement",
                    {
                        "name": f"{policy}_{direction}",
                        "description": description,
                        "policy_entries": json.dumps([_PERMIT_ALL_POLICY_TERM]),
                    },
                )
                for direction, description in (
                    ("IN", "Ingress policy - accept all prefixes"),
                    ("OUT", "Egress policy - advertise all prefixes"),
                )
            ],
            register(
                "bgpcpp",
                f"update_peer_group_patcher_{peer_group_v6}",
                "configure_bgp_peer_group",
                {
                    "name": peer_group_v6,
                    "attributes_to_update_json": json.dumps(
                        {
                            "disable_ipv4_afi": "True",
                            "v4_over_v6_nexthop": "False",
                            "is_passive": "False",
                            "is_confed_peer": "False",
                            "max_routes": per_peer_max_route_limit,
                            "ingress_policy_name": f"{policy}_IN",
                            "egress_policy_name": f"{policy}_OUT",
                        }
                    ),
                },
            ),
            register(
                "bgpcpp",
                "add_bgp_peers_ixia",
                "add_bgp_peers",
                {"peer_configs": json.dumps(peer_configs)},
            ),
            create_coop_apply_patchers_task(hostnames=[device_name]),
            create_wait_for_agent_convergence_task([device_name]),
        ],
        teardown_tasks=[create_coop_unregister_patchers_task(device_name)],
        basic_port_configs=[
            *[_port_config(device_name, layout, communities) for layout in layouts],
            _stressor_port_config(device_name, stressor),
        ],
        traffic_items_to_start=names.all,
        basic_traffic_item_configs=_traffic_items(
            device_name,
            downlink.interface,
            uplink.interface,
            stressor,
            good_mac_entry_count,
        ),
        playbooks=[_finalize_playbook(pb) for pb in playbooks],
    )


_IXIA16_CHASSIS_IP = "2401:db00:2066:304b::3004"
# MP3BA_FA002_DU001_QZA1 remote ASes; the eBGP peers sit in distinct ASes.
_DOWNLINK_AS = 64901
_UPLINK_AS = 7010

# Scale of FBOSS_BGP_HARDENING_MP3BA_FA002_DU001_QZA1, with its IPv4 roles moved
# to IPv6 (`NO_PACKET_LOSS_EXPECTED` and `ROGUE_SESSION_FLAP`). The unused,
# initially disabled `UPLINK_BGP_INDUCED_ECMP_2` group is left out so the DUT
# does not wait for 50 peers that never open (EOR_TIMER_EXPIRED).
MP3N_RTSW001_DOWNLINK_ROLES: tuple[PeerRole, ...] = (
    PeerRole(
        tag="NO_V6_PACKET_LOSS_EXPECTED",
        device_group_index=_MAIN_V6_INDEX,
        peer_count=18,
        remote_as_4byte=_DOWNLINK_AS,
        remote_as_4byte_step=1,
        prefix_count=2500,
        starting_prefix="3000:1::",
    ),
    PeerRole(
        tag="NO_PACKET_LOSS_EXPECTED",
        device_group_index=_PREFIX_GROUP_INDEX,
        peer_count=18,
        remote_as_4byte=_DOWNLINK_AS,
        remote_as_4byte_step=1,
        prefix_count=3500,
        starting_prefix="3100:1::",
    ),
)
MP3N_RTSW001_UPLINK_ROLES: tuple[PeerRole, ...] = (
    PeerRole(
        tag="NO_V6_PACKET_LOSS_EXPECTED",
        device_group_index=_MAIN_V6_INDEX,
        peer_count=4,
        remote_as_4byte=_UPLINK_AS,
        remote_as_4byte_step=0,
        prefix_count=7500,
        starting_prefix="6100:1::",
    ),
    PeerRole(
        tag="NO_PACKET_LOSS_EXPECTED",
        device_group_index=_PREFIX_GROUP_INDEX,
        peer_count=4,
        remote_as_4byte=_UPLINK_AS,
        remote_as_4byte_step=0,
        prefix_count=7500,
        starting_prefix="6200:1::",
    ),
    PeerRole(
        tag="UPLINK_BGP_INDUCED_ECMP_1",
        device_group_index=4,
        peer_count=50,
        remote_as_4byte=_UPLINK_AS,
        remote_as_4byte_step=0,
        prefix_count=1,
        starting_prefix="7000:1:f::",
        prefix_step="0:0:0:1::0",
    ),
    PeerRole(
        tag="ROGUE_PREFIX_FLAP",
        device_group_index=5,
        peer_count=25,
        remote_as_4byte=_DOWNLINK_AS,
        remote_as_4byte_step=1,
        prefix_count=3750,
        starting_prefix="6000:f::",
        prefix_flap=True,
    ),
    PeerRole(
        tag="ROGUE_SESSION_FLAP",
        device_group_index=6,
        peer_count=25,
        remote_as_4byte=_DOWNLINK_AS,
        remote_as_4byte_step=1,
        prefix_count=3750,
        starting_prefix="6300:f::",
        session_flap=True,
    ),
)

# rtsw001.l1003.c084.ash6: MINIPACK3NM, native NetOS, IXIA on ixia16. The RTSW
# has only the FTSW V6 peer group, so every IXIA peer joins it.
FBOSS_BGP_HARDENING_MP3N_RTSW001_L1003_C084_TEST_CONFIG: TestConfig = (
    create_mp3n_bgp_hardening_test_config(
        test_config_name="FBOSS_BGP_HARDENING_MP3N_RTSW001_L1003_C084",
        device_name="rtsw001.l1003.c084.ash6",
        local_mac_address="5e:40:97:19:90:83",
        downlink=Mp3nHardeningPort(
            interface="eth1/1/1",
            network="2401:db00:209e:0",
            ixia_chassis_ip=_IXIA16_CHASSIS_IP,
            ixia_port="1/13",
        ),
        uplink=Mp3nHardeningPort(
            interface="eth1/2/1",
            network="2401:db00:209e:2",
            ixia_chassis_ip=_IXIA16_CHASSIS_IP,
            ixia_port="1/15",
        ),
        peer_group_v6="PEERGROUP_RTSW_FTSW_V6",
        downlink_roles=MP3N_RTSW001_DOWNLINK_ROLES,
        uplink_roles=MP3N_RTSW001_UPLINK_ROLES,
        ndp_stressor_port=Mp3nHardeningPort(
            interface="eth1/1/5",
            network="2401:db00:209e:1",
            ixia_chassis_ip=_IXIA16_CHASSIS_IP,
            ixia_port="1/17",
        ),
        # MP3BA uses 3500 (plus 200 on its uplink); 2500 keeps the IXIA
        # neighbors (144 peers + 2500 stressor) under `_MAX_TEST_NDP_ENTRIES`.
        ndp_stressor_count=2500,
        communities=["65446:30", "65441:259", "65456:259"],
        prefix_limit="75000",
        per_peer_max_route_limit="25000",
        basset_pool="taac_netcastle_ash6",
    )
)

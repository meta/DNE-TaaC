# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Quick RDMA disruption coverage for RTSW001.L101.C084.QZA1.

The cross-pod config reuses the validated IXIA12 -> RTSW001 -> FTSW001.L101
-> STSW001 -> FTSW001.L102 -> RTSW003 -> IXIA16 route scaffold. It runs the
IcePack neighbour-uplink-flap family with one iteration, a 60-second flap
window and a 120-second recovery hold. Traffic is real RoCEv2/IB and uses a
128-byte minimum because Ethernet+IPv6+UDP+BTH cannot use the generic 72-byte
minimum safely.

The local troubleshooting config is intentionally independent of IXIA16 and
the remote QZA1 devices. It routes bidirectional RoCEv2/IB between IXIA12
ports 1/12 and 1/11 through RTSW001, warmboots the native NetOS agent, then
holds traffic for 300 seconds.
"""

import json

from ixia.ixia import types as ixia_types
from taac.health_checks.healthcheck_definitions import (
    create_bgp_session_establish_check,
    create_port_state_check,
    create_service_restart_check,
    create_systemctl_active_state_check,
)
from taac.packet_headers import DSF_RDMA_IB_PACKET_HEADERS
from taac.playbooks.playbook_definitions import (
    create_gtsw_service_restart_nbr_uplink_flap_playbook,
    create_gtsw_warmboot_nbr_uplink_flap_playbook,
    create_icepack_gtsw_warmboot_troubleshooting_playbook,
)
from taac.task_definitions import (
    create_coop_apply_patchers_task,
    create_coop_register_patcher_task,
    create_coop_unregister_patchers_task,
    create_ixia_preflight_task,
    create_wait_for_agent_convergence_task,
)
from taac.testconfigs.ai_bb.rtsw_mp3n_qza1_ixia12_16_nsf_warmboot_test_config import (
    _address,
    _policy_task,
    _port_config,
    _prefixes,
    CHASSIS,
    create_rtsw_mp3n_qza1_ixia12_16_nsf_warmboot_test_config,
    DUT,
    EDGE_GROUP,
    EDGE_PORTS,
    LOCAL_TRANSIT,
    PATCHER_NAMESPACE,
    TRAFFIC_NAMES,
    TRANSIT_PEERS,
)
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types


PLAYBOOK_ITERATIONS = 1
PER_ITERATION_FLAP_SEC = 60
LONGEVITY_SEC = 120
FSDB_SETTLE_SEC = 10
NBR_UPLINK_NEIGHBOR_PATTERN = "stsw*"

FRAME_SIZE_128_TO_9000 = ixia_types.FrameSize(
    type=ixia_types.FrameSizeType.RANDOM,
    random_min=128,
    random_max=9000,
)
FRAME_SIZE_128 = ixia_types.FrameSize(
    type=ixia_types.FrameSizeType.FIXED,
    fixed_size=128,
)
FRAME_SIZE_9000 = ixia_types.FrameSize(
    type=ixia_types.FrameSizeType.FIXED,
    fixed_size=9000,
)

# Logical service names are intentional: the TAAC health-check adapter maps
# them to the native NetOS units. This is the live-validated RTSW001 cascade.
NATIVE_SERVICES = [
    "wedge_agent",
    "fboss_sw_agent",
    "fboss_wedge_agent_nvda_0",
    "bgpd",
    "fsdb",
    "qsfp_service",
    "coop",
]
NATIVE_AGENT_WARMBOOT_CASCADE = [
    "wedge_agent",
    "fboss_sw_agent",
    "fboss_wedge_agent_nvda_0",
    "bgpd",
]

_DUT_EDGE_ROWS = [row for row in EDGE_PORTS if row[0] == DUT]
_DUT_PEERS = [_address(peer) for _, peer in TRANSIT_PEERS[DUT]] + [
    _address(row[3]) for row in _DUT_EDGE_ROWS
]


def _native_active_check():
    return create_systemctl_active_state_check(services_json=NATIVE_SERVICES)


def _native_restart_check(expected_restarted_services: list[str]):
    return create_service_restart_check(
        services=NATIVE_SERVICES,
        expected_restarted_services=expected_restarted_services,
    )


def _qza_bgp_check():
    return create_bgp_session_establish_check(
        ignore_all_prefixes_except=_DUT_PEERS,
        expected_established_sessions=len(_DUT_PEERS),
        check_scope=hc_types.Scope.DEFAULT,
        retry_count=12,
        retry_delay_seconds=5,
    )


def _frame_size_override(
    frame_size: ixia_types.FrameSize,
) -> dict[str, taac_types.TrafficItemSettings]:
    return {
        name: taac_types.TrafficItemSettings(
            line_rate=50,
            frame_size_settings=frame_size,
        )
        for name in TRAFFIC_NAMES
    }


def _warmboot_playbook(name: str, frame_size: ixia_types.FrameSize):
    return create_gtsw_warmboot_nbr_uplink_flap_playbook(
        nbr_device_name=LOCAL_TRANSIT,
        iteration=PLAYBOOK_ITERATIONS,
        nbr_uplink_neighbor_pattern=NBR_UPLINK_NEIGHBOR_PATTERN,
        per_iteration_flap_sec=PER_ITERATION_FLAP_SEC,
        longevity_sec=LONGEVITY_SEC,
        playbook_name=name,
        traffic_items_to_configure=_frame_size_override(frame_size),
        restart_service_check=_native_restart_check(NATIVE_AGENT_WARMBOOT_CASCADE),
        systemctl_active_check=_native_active_check(),
    )


def _service_restart_playbook(
    name: str,
    service: taac_types.Service,
    expected_restarted_service: str,
    convergence_services: list[taac_types.Service],
    service_label: str,
    post_restart_settle_sec: int = 0,
    extra_post_flap_checks=None,
):
    return create_gtsw_service_restart_nbr_uplink_flap_playbook(
        nbr_device_name=LOCAL_TRANSIT,
        playbook_name=name,
        service=service,
        restart_service_check=_native_restart_check([expected_restarted_service]),
        convergence_services=convergence_services,
        service_label=service_label,
        iteration=PLAYBOOK_ITERATIONS,
        nbr_uplink_neighbor_pattern=NBR_UPLINK_NEIGHBOR_PATTERN,
        per_iteration_flap_sec=PER_ITERATION_FLAP_SEC,
        longevity_sec=LONGEVITY_SEC,
        post_restart_settle_sec=post_restart_settle_sec,
        extra_post_flap_checks=extra_post_flap_checks,
        traffic_items_to_configure=_frame_size_override(FRAME_SIZE_128_TO_9000),
        systemctl_active_check=_native_active_check(),
    )


def create_rtsw_mp3n_qza1_rdma_nbr_uplink_flap_test_config():
    base = create_rtsw_mp3n_qza1_ixia12_16_nsf_warmboot_test_config()
    return base(
        name="RTSW_MP3N_QZA1_RDMA_NBR_UPLINK_FLAP",
        basic_traffic_item_configs=[
            item(
                packet_headers=DSF_RDMA_IB_PACKET_HEADERS,
                frame_size_settings=FRAME_SIZE_128_TO_9000,
            )
            for item in base.basic_traffic_item_configs
        ],
        playbooks=[
            _warmboot_playbook(
                "qza1_rdma_warmboot_nbr_uplink_flap_random_128_9000",
                FRAME_SIZE_128_TO_9000,
            ),
            _warmboot_playbook(
                "qza1_rdma_warmboot_nbr_uplink_flap_128b",
                FRAME_SIZE_128,
            ),
            _warmboot_playbook(
                "qza1_rdma_warmboot_nbr_uplink_flap_9000b",
                FRAME_SIZE_9000,
            ),
            _service_restart_playbook(
                name="qza1_rdma_qsfp_restart_nbr_uplink_flap",
                service=taac_types.Service.QSFP_SERVICE,
                expected_restarted_service="qsfp_service",
                convergence_services=[
                    taac_types.Service.QSFP_SERVICE,
                    taac_types.Service.AGENT,
                    taac_types.Service.BGP,
                ],
                service_label="qsfp_service",
                extra_post_flap_checks=[create_port_state_check()],
            ),
            _service_restart_playbook(
                name="qza1_rdma_bgp_restart_nbr_uplink_flap",
                service=taac_types.Service.BGP,
                expected_restarted_service="bgpd",
                convergence_services=[
                    taac_types.Service.BGP,
                    taac_types.Service.AGENT,
                ],
                service_label="bgpd",
                extra_post_flap_checks=[_qza_bgp_check()],
            ),
            _service_restart_playbook(
                name="qza1_rdma_fsdb_restart_nbr_uplink_flap",
                service=taac_types.Service.FSDB,
                expected_restarted_service="fsdb",
                convergence_services=[
                    taac_types.Service.AGENT,
                    taac_types.Service.BGP,
                ],
                service_label="fsdb",
                post_restart_settle_sec=FSDB_SETTLE_SEC,
            ),
        ],
    )


def _local_setup_tasks():
    tasks = [
        create_ixia_preflight_task(
            chassis_hostname=CHASSIS[DUT][0],
            test_ports=[row[2] for row in _DUT_EDGE_ROWS],
        ),
        create_wait_for_agent_convergence_task([DUT]),
        create_coop_unregister_patchers_task(
            hostnames=DUT,
            config_names=["bgpcpp"],
            regex=f"^{PATCHER_NAMESPACE}",
        ),
        _policy_task(DUT, "IN", _prefixes(DUT)),
        _policy_task(DUT, "OUT", _prefixes(DUT)),
        create_coop_register_patcher_task(
            hostname=DUT,
            config_name="bgpcpp",
            patcher_name=f"{PATCHER_NAMESPACE}c_edge_group",
            py_func_name="add_peer_group_patcher",
            patcher_args={
                "name": EDGE_GROUP,
                "description": "QZA1 local RDMA IXIA12 edges",
                "next_hop_self": "True",
                "disable_ipv4_afi": "True",
                "disable_ipv6_afi": "False",
                "is_confed_peer": "False",
                "is_passive": "False",
                "v4_over_v6_nexthop": "False",
                "ingress_policy_name": "QZA1_IXIA12_16_NSF_IXIA_IN",
                "egress_policy_name": "QZA1_IXIA12_16_NSF_IXIA_OUT",
                "bgp_peer_timers_hold_time_seconds": "30",
                "bgp_peer_timers_keep_alive_seconds": "10",
                "bgp_peer_timers_out_delay_seconds": "0",
                "bgp_peer_timers_withdraw_unprog_delay_seconds": "0",
                "peer_tag": "IXIA",
                "max_routes": "120",
                "warning_only": "False",
                "warning_limit": "0",
                "link_bandwidth_bps": "auto",
            },
        ),
    ]
    peers = []
    for row in _DUT_EDGE_ROWS:
        tasks.append(
            create_coop_register_patcher_task(
                hostname=DUT,
                config_name="bgpcpp",
                patcher_name=(
                    f"{PATCHER_NAMESPACE}a_remove_edge_{row[1].replace('/', '_')}"
                ),
                py_func_name="remove_specific_bgp_peers",
                patcher_args={"peer_attr:peer_addr": row[3]},
            )
        )
        peers.append(
            {
                "local_addr": row[4],
                "peer_addr": row[3],
                "remote_as_4_byte": str(row[5]),
                "description": f"QZA1 local RDMA IXIA12 {row[1]}",
                "peer_group_name": EDGE_GROUP,
            }
        )
    tasks.extend(
        [
            create_coop_register_patcher_task(
                hostname=DUT,
                config_name="bgpcpp",
                patcher_name=f"{PATCHER_NAMESPACE}d_edge_peers",
                py_func_name="add_bgp_peers",
                patcher_args={"peer_configs": json.dumps(peers)},
            ),
            create_coop_apply_patchers_task(
                hostnames=[DUT],
                config_name="bgpcpp",
            ),
            create_wait_for_agent_convergence_task([DUT]),
        ]
    )
    return tasks


def _local_teardown_tasks():
    return [
        create_coop_unregister_patchers_task(
            hostnames=DUT,
            config_names=["bgpcpp"],
            regex=f"^{PATCHER_NAMESPACE}",
        ),
        create_coop_apply_patchers_task(hostnames=[DUT], config_name="bgpcpp"),
        create_wait_for_agent_convergence_task([DUT]),
    ]


LOCAL_TRAFFIC_NAMES = [
    "QZA1_RTSW001_IXIA12_LOCAL_RDMA_12_TO_11",
    "QZA1_RTSW001_IXIA12_LOCAL_RDMA_11_TO_12",
]


def _local_traffic_item(name: str, src, dst):
    return taac_types.BasicTrafficItemConfig(
        name=name,
        src_endpoints=[
            taac_types.TrafficEndpoint(
                name=f"{DUT}:{src[1]}",
                device_group_index=0,
                network_group_index=0,
            )
        ],
        dest_endpoints=[
            taac_types.TrafficEndpoint(
                name=f"{DUT}:{dst[1]}",
                device_group_index=0,
                network_group_index=0,
            )
        ],
        line_rate_type=ixia_types.RateType.PERCENT_LINE_RATE,
        line_rate=50,
        traffic_type=ixia_types.TrafficType.IPV6,
        bidirectional=False,
        packet_headers=DSF_RDMA_IB_PACKET_HEADERS,
        full_mesh=False,
        src_dest_mesh=ixia_types.SrcDestMeshType.ONE_TO_ONE,
        frame_size_settings=ixia_types.FrameSize(
            type=ixia_types.FrameSizeType.FIXED,
            fixed_size=4000,
        ),
    )


def create_rtsw_mp3n_qza1_local_rdma_warmboot_test_config():
    src, dst = _DUT_EDGE_ROWS
    return taac_types.TestConfig(
        name="RTSW_MP3N_QZA1_LOCAL_RDMA_WARMBOOT_TROUBLESHOOTING",
        basset_pool="dne.test",
        basset_reservation_time_hr=288,
        endpoints=[
            taac_types.Endpoint(
                name=DUT,
                dut=True,
                ixia_needed=True,
                ixia_ports=[row[1] for row in _DUT_EDGE_ROWS],
                direct_ixia_connections=[
                    taac_types.DirectIxiaConnection(
                        interface=row[1],
                        ixia_chassis_ip=CHASSIS[DUT][1],
                        ixia_port=row[2],
                    )
                    for row in _DUT_EDGE_ROWS
                ],
            )
        ],
        ixia_config_cache=taac_types.IxiaConfigCache(enabled=False),
        basic_port_configs=[_port_config(row) for row in _DUT_EDGE_ROWS],
        basic_traffic_item_configs=[
            _local_traffic_item(LOCAL_TRAFFIC_NAMES[0], src, dst),
            _local_traffic_item(LOCAL_TRAFFIC_NAMES[1], dst, src),
        ],
        setup_tasks=_local_setup_tasks(),
        teardown_tasks=_local_teardown_tasks(),
        playbooks=[
            create_icepack_gtsw_warmboot_troubleshooting_playbook(
                name="qza1_rtsw001_local_rdma_warmboot_troubleshooting",
                traffic_item_name=LOCAL_TRAFFIC_NAMES[0],
                traffic_item_names=LOCAL_TRAFFIC_NAMES,
                longevity_duration_seconds=300,
                bgp_session_check=_qza_bgp_check(),
                systemctl_active_check=_native_active_check(),
                restart_service_check=_native_restart_check(
                    NATIVE_AGENT_WARMBOOT_CASCADE
                ),
                base_bandwidth_gbps=400,
            )
        ],
    )


RTSW_MP3N_QZA1_RDMA_NBR_UPLINK_FLAP = (
    create_rtsw_mp3n_qza1_rdma_nbr_uplink_flap_test_config()
)
RTSW_MP3N_QZA1_LOCAL_RDMA_WARMBOOT_TROUBLESHOOTING = (
    create_rtsw_mp3n_qza1_local_rdma_warmboot_test_config()
)

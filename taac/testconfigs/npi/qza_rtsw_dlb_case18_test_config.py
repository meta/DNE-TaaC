# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Bounded Spectrum-4 Case 18 DLB/ECMP flap test for RTSW001 QZA1.

This is deliberately not a TH6 capacity-profile port. Chenab source exposes a
256-group ARS ceiling, while the live agent enforces the default 75% ARS
resource percentage and a two-group make-before-break reserve. It does not
expose a defensible DLB member-table or unique-next-hop-table capacity.

The test therefore fills only the proven group dimension: 190 distinct
width-two Gold groups reach the full primary ceiling from a clean zero-group
baseline. Eight width-two Silver groups must spill to the configured
FIXED_ASSIGNMENT backup mode. Case 18 then flaps only Silver nine times in a
600-second window while checking primary/backup counters after every edge.
"""

import json
import math
import os
from dataclasses import dataclass

from ixia.ixia import types as ixia_types
from taac.health_checks.healthcheck_definitions import (
    create_bgp_session_establish_check,
    create_core_dumps_snapshot_check,
    create_ixia_packet_loss_check,
    create_systemctl_active_state_check,
)
from taac.packet_headers import DSF_RDMA_IB_PACKET_HEADERS
from taac.playbooks.playbook_definitions import (
    create_dlb_hardening_playbook,
)
from taac.steps.step_definitions import (
    create_ixia_api_step,
    create_longevity_step,
    create_run_task_step,
    create_start_traffic_step,
    create_stop_traffic_step,
)
from taac.task_definitions import (
    create_coop_apply_patchers_task,
    create_coop_register_patcher_task,
    create_coop_unregister_patchers_task,
    create_ixia_preflight_task,
    create_run_commands_on_shell_task,
    create_wait_for_agent_convergence_task,
)
from taac.testconfigs.npi.dlb_asic_profiles import NhPool
from taac.testconfigs.npi.dlb_csvs import gen_dlb_csv
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types


DEVICE = "rtsw001.l101.c084.qza1"
IXIA_CHASSIS = "ixia12.netcastle.ash6"
IXIA_CHASSIS_IP = "2401:db00:2066:304b::3003"
DOWNLINK_INTERFACE = "eth1/2/1"
ROGUE_INTERFACE = "eth1/2/5"
DOWNLINK_IXIA_PORT = "1/12"
ROGUE_IXIA_PORT = "1/11"
DOWNLINK_PEER = "2401:db00:e2d1:b70::4"
DOWNLINK_GATEWAY = "2401:db00:e2d1:b70::5"
ROGUE_PARENT = "2401:db00:e2d1:b73"
ROGUE_GATEWAY = f"{ROGUE_PARENT}::a"
GOLD_PEERS = (f"{ROGUE_PARENT}::b", f"{ROGUE_PARENT}::c")
SILVER_PEERS = (f"{ROGUE_PARENT}::d", f"{ROGUE_PARENT}::e")
GOLD_PREFIX_POOLS = ("DLB_GOLD_PREFIX_POOL_A", "DLB_GOLD_PREFIX_POOL_B")
SILVER_PREFIX_POOLS = ("DLB_SILVER_PREFIX_POOL_A", "DLB_SILVER_PREFIX_POOL_B")
PEER_GROUP = "PEERGROUP_RTSW_QZA1_CHENAB_DLB_IXIA_V6"
INGRESS_POLICY = "QZA1_CHENAB_DLB_IXIA_IN"
EGRESS_POLICY = "QZA1_CHENAB_DLB_IXIA_OUT"
PATCHER_NAMESPACE = "qza1_chenab_dlb_case18_"
TRAFFIC_NAME = "QZA1_CHENAB_CASE18_RDMA_GOLD"


@dataclass(frozen=True)
class BoundedChenabCase18Shape:
    """Only source- and live-verified resource dimensions for this run."""

    raw_ars_groups: int = 256
    ars_resource_percentage: int = 75
    make_before_break_buffer: int = 2
    baseline_primary_groups: int = 0
    silver_groups: int = 8
    group_width: int = 2
    # The checked-in shape remains the final 600-second/9-cycle case. A
    # one-cycle shape is passed explicitly for the live diagnostic gate.
    runtime_sec: int = 600
    cycle_sec: int = 65

    def __post_init__(self) -> None:
        if self.raw_ars_groups <= 0:
            raise ValueError("raw_ars_groups must be positive and source-verified")
        if not 0 < self.ars_resource_percentage <= 100:
            raise ValueError("ars_resource_percentage must be in 1..100")
        if self.make_before_break_buffer < 0:
            raise ValueError("make_before_break_buffer must be non-negative")
        if self.group_width < 2:
            raise ValueError("group_width must form a real ECMP group")
        if not 0 <= self.baseline_primary_groups < self.primary_group_ceiling:
            raise ValueError(
                "baseline_primary_groups must be below the enforced primary ceiling"
            )
        if self.silver_groups <= 0:
            raise ValueError("silver_groups must exercise backup mode")
        if self.runtime_sec < self.cycle_sec:
            raise ValueError("runtime_sec must include at least one full cycle")

    @property
    def primary_group_ceiling(self) -> int:
        return (
            math.floor(self.raw_ars_groups * self.ars_resource_percentage / 100.0)
            - self.make_before_break_buffer
        )

    @property
    def gold_groups(self) -> int:
        return self.primary_group_ceiling - self.baseline_primary_groups

    @property
    def cycle_count(self) -> int:
        return self.runtime_sec // self.cycle_sec


CASE18_SHAPE = BoundedChenabCase18Shape()

GOLD_POOL = NhPool(
    name="qza_chenab_gold",
    prefix_base="5000:dd::",
    nh_network=ROGUE_PARENT,
    nh_host_start=0x1001,
    # C(20, 2) = 190 unique sets, one more than this test needs.
    size=20,
)
SILVER_POOL = NhPool(
    name="qza_chenab_silver",
    prefix_base="5000:ee::",
    nh_network=ROGUE_PARENT,
    nh_host_start=0x2001,
    # C(5, 2) = 10 unique sets, enough for eight bounded spill groups.
    size=5,
)


def _fb303_exact_command(counter: str, expected: int) -> str:
    return (
        "value=$(fboss2 show fb303-counters --service agent "
        f"--regex=^{counter}$ | awk '$2 == \"{counter}\" {{print $3; exit}}'); "
        f'test "$value" -eq {expected} || '
        f'{{ echo "{counter}=$value expected={expected}"; exit 1; }}'
    )


def _fb303_wait_command(counter: str, expected: int, timeout_sec: int = 120) -> str:
    attempts = timeout_sec // 5
    return (
        f"for attempt in $(seq 1 {attempts}); do "
        "value=$(fboss2 show fb303-counters --service agent "
        f"--regex=^{counter}$ | awk '$2 == \"{counter}\" {{print $3; exit}}'); "
        f'test "$value" -eq {expected} && break; '
        f'test "$attempt" -eq {attempts} && '
        f'{{ echo "{counter}=$value expected={expected} after {timeout_sec}s"; exit 1; }}; '
        "sleep 5; done"
    )


def _dut_route_state_wait_command(
    expected_unique_prefixes: int,
    expected_width: int,
    timeout_sec: int = 120,
) -> str:
    """Poll authoritative DUT BGP RIB and FIB state for the Silver family."""
    attempts = timeout_sec // 5
    rib_command = (
        "(timeout 60 vtysh -c 'show bgp ipv6 unicast' 2>/dev/null || "
        "timeout 60 fboss2 show bgp table 2>/dev/null)"
    )
    unique_count = "grep -oE '5000:ee:[0-9a-f:]+/[0-9]+' | sort -u | wc -l"
    width_check = "true"
    if expected_unique_prefixes:
        prefix_checks = []
        for index in range(expected_unique_prefixes):
            prefix = f"5000:ee:0:{index:x}::/64"
            prefix_checks.append(
                'test "$(timeout 60 fboss2 show route details '
                f"{prefix} 2>/dev/null | "
                "grep -oE '2401:db00:e2d1:b73::200[1-5]' | sort -u | wc -l)\" "
                f"-eq {expected_width}"
            )
        width_check = " && ".join(prefix_checks)
    return (
        f"for attempt in $(seq 1 {attempts}); do "
        "fib_count=$(timeout 60 fboss2 show route 2>/dev/null | "
        f"{unique_count}); "
        f"rib_count=$({rib_command} | {unique_count}); "
        f'if test "$fib_count" -eq {expected_unique_prefixes} && '
        f'test "$rib_count" -eq {expected_unique_prefixes} && '
        f"{width_check}; then break; fi; "
        f'test "$attempt" -eq {attempts} && '
        f'{{ echo "Silver route state fib=$fib_count rib=$rib_count '
        f'expected={expected_unique_prefixes} width={expected_width} after {timeout_sec}s"; '
        "exit 1; }; sleep 5; done"
    )


def build_capability_preflight_commands(
    shape: BoundedChenabCase18Shape,
) -> list[str]:
    """Fail closed unless the live device matches the bounded proof."""
    return [
        (
            "fboss2 show product | awk "
            '\'$1 == "Product:" && $2 == "MINIPACK3N" {ok=1} END {exit !ok}\''
        ),
        (
            "fboss2 show config running agent | jq -e '"
            '.defaultCommandLineArgs.flowletSwitchingEnable == "true" and '
            '.defaultCommandLineArgs.enable_ecmp_resource_manager == "true" and '
            '.defaultCommandLineArgs.ecmp_width == "128" and '
            ".sw.flowletSwitchingConfig.switchingMode == 1 and "
            ".sw.flowletSwitchingConfig.backupSwitchingMode == 2' >/dev/null "
            "|| { echo 'expected PER_PACKET_QUALITY primary and "
            "FIXED_ASSIGNMENT backup'; exit 1; }"
        ),
        _fb303_exact_command(
            "primary_ecmp_groups_count", shape.baseline_primary_groups
        ),
        _fb303_exact_command("backup_ecmp_groups_count", 0),
        (
            "value=$(fboss2 show fb303-counters --service agent "
            "--regex=^l3_ecmp_groups_free$ | awk "
            "'$2 == \"l3_ecmp_groups_free\" {print $3; exit}'); "
            f'test "$value" -ge {shape.gold_groups + shape.silver_groups}'
        ),
        (
            "value=$(fboss2 show fb303-counters --service agent "
            "--regex=^l3_ecmp_group_memers_free$ | awk "
            "'$2 == \"l3_ecmp_group_memers_free\" {print $3; exit}'); "
            f'test "$value" -ge '
            f"{(shape.gold_groups + shape.silver_groups) * shape.group_width}"
        ),
    ]


def _validated_counter_step(
    shape: BoundedChenabCase18Shape,
    *,
    silver_enabled: bool,
    description: str,
) -> taac_types.Step:
    return create_run_task_step(
        task_name="run_commands_on_shell",
        params_dict={
            "hostname": DEVICE,
            "cmds": [
                _fb303_wait_command(
                    "primary_ecmp_groups_count", shape.primary_group_ceiling
                ),
                _fb303_wait_command(
                    "backup_ecmp_groups_count",
                    shape.silver_groups if silver_enabled else 0,
                ),
            ],
            "validate_output": True,
        },
        description=description,
    )


def _validated_route_state_step(
    shape: BoundedChenabCase18Shape,
    *,
    silver_enabled: bool,
    description: str,
) -> taac_types.Step:
    return create_run_task_step(
        task_name="run_commands_on_shell",
        params_dict={
            "hostname": DEVICE,
            "cmds": [
                _dut_route_state_wait_command(
                    shape.silver_groups if silver_enabled else 0,
                    shape.group_width,
                )
            ],
            "validate_output": True,
        },
        description=description,
    )


def _write_case_csvs(
    shape: BoundedChenabCase18Shape,
) -> list[tuple[str, str]]:
    output_dir = "/tmp/qza_rtsw001_chenab_case18_quick"
    os.makedirs(output_dir, exist_ok=True)
    paths = []
    for pool, groups, pool_names in (
        (GOLD_POOL, shape.gold_groups, GOLD_PREFIX_POOLS),
        (SILVER_POOL, shape.silver_groups, SILVER_PREFIX_POOLS),
    ):
        rows = gen_dlb_csv.gen_fill_for_pool(pool, groups, shape.group_width)
        for index, pool_name in enumerate(pool_names):
            path = os.path.join(output_dir, f"{pool.name}_{index}.csv")
            gen_dlb_csv.write_csv(path, rows[index::2])
            paths.append((path, pool_name))
    return paths


def _permit_all_policy_task(name: str, patcher_suffix: str):
    permit_all = {
        "name": "RULE_ACCEPT_ALL",
        "description": "Bounded QZA1 DLB test peer only",
        "policy_match_entries": {
            "name": "",
            "description": "",
            "match_logic_type": 1,
            "match_entries": [{"type": 20, "match_logic_type": 0}],
        },
    }
    return create_coop_register_patcher_task(
        hostname=DEVICE,
        config_name="bgpcpp",
        patcher_name=f"{PATCHER_NAMESPACE}{patcher_suffix}",
        py_func_name="add_bgp_policy_statement",
        patcher_args={
            "name": name,
            "description": "Bounded QZA1 Chenab DLB Case 18 policy",
            "policy_entries": json.dumps([permit_all]),
        },
    )


def _setup_tasks(shape: BoundedChenabCase18Shape) -> list[taac_types.Task]:
    peer_configs = [
        {
            "local_addr": ROGUE_GATEWAY,
            "peer_addr": peer,
            "remote_as_4_byte": str(remote_as),
            "description": f"QZA1 Chenab DLB {pool_name} {index + 1}",
            "peer_group_name": PEER_GROUP,
        }
        for pool_name, peers, remote_as in (
            ("Gold", GOLD_PEERS, 4200000211),
            ("Silver", SILVER_PEERS, 4200000212),
        )
        for index, peer in enumerate(peers)
    ]
    return [
        create_ixia_preflight_task(
            chassis_hostname=IXIA_CHASSIS,
            test_ports=[ROGUE_IXIA_PORT, DOWNLINK_IXIA_PORT],
        ),
        create_run_commands_on_shell_task(
            hostname=DEVICE,
            cmds=build_capability_preflight_commands(shape),
            validate_output=True,
        ),
        create_coop_unregister_patchers_task(
            DEVICE,
            config_names=["agent", "bgpcpp"],
            regex=f"^{PATCHER_NAMESPACE}",
        ),
        create_coop_register_patcher_task(
            hostname=DEVICE,
            config_name="agent",
            patcher_name=f"{PATCHER_NAMESPACE}a0_rogue_flowlet_profile",
            py_func_name="configure_port_flowlet_config_names",
            patcher_args={ROGUE_INTERFACE: "uplink_flowlet_config"},
        ),
        create_coop_register_patcher_task(
            hostname=DEVICE,
            config_name="agent",
            patcher_name=f"{PATCHER_NAMESPACE}a_rogue_rif",
            py_func_name="configure_interfaces_ip_addresses",
            patcher_args={
                ROGUE_INTERFACE: json.dumps(
                    {
                        "intfId": 4004,
                        "portID": 247,
                        "vlanId": 0,
                        "mtu": 9000,
                        "rif_type": 3,
                        "ip_addresses": [
                            "2401:db00:e2d1:b70::7/127",
                            f"{ROGUE_GATEWAY}/64",
                        ],
                    }
                )
            },
        ),
        _permit_all_policy_task(INGRESS_POLICY, "b_ingress_policy"),
        _permit_all_policy_task(EGRESS_POLICY, "b_egress_policy"),
        create_coop_register_patcher_task(
            hostname=DEVICE,
            config_name="bgpcpp",
            patcher_name=f"{PATCHER_NAMESPACE}c_peer_group",
            py_func_name="add_peer_group_patcher",
            patcher_args={
                "name": PEER_GROUP,
                "description": "QZA1 Chenab bounded DLB Case 18",
                "next_hop_self": "False",
                "add_path": "BOTH",
                "disable_ipv4_afi": "True",
                "disable_ipv6_afi": "False",
                "is_confed_peer": "False",
                "is_passive": "False",
                "v4_over_v6_nexthop": "False",
                "ingress_policy_name": INGRESS_POLICY,
                "egress_policy_name": EGRESS_POLICY,
                "bgp_peer_timers_hold_time_seconds": "30",
                "bgp_peer_timers_keep_alive_seconds": "10",
                "bgp_peer_timers_out_delay_seconds": "0",
                "bgp_peer_timers_withdraw_unprog_delay_seconds": "0",
                "peer_tag": "IXIA",
                "max_routes": "1000",
                "warning_only": "False",
                "warning_limit": "0",
                "link_bandwidth_bps": "auto",
            },
        ),
        create_coop_register_patcher_task(
            hostname=DEVICE,
            config_name="bgpcpp",
            patcher_name=f"{PATCHER_NAMESPACE}d_peers",
            py_func_name="add_bgp_peers",
            patcher_args={"peer_configs": json.dumps(peer_configs)},
        ),
        create_coop_apply_patchers_task(
            hostnames=[DEVICE],
            config_name="agent",
            do_warmboot=True,
        ),
        create_coop_apply_patchers_task(
            hostnames=[DEVICE],
            config_name="bgpcpp",
        ),
        create_wait_for_agent_convergence_task([DEVICE]),
        create_run_commands_on_shell_task(
            hostname=DEVICE,
            cmds=[
                (
                    "fboss2 show config running agent | jq -e '"
                    '.sw.ports[] | select(.name == "eth1/2/5") | '
                    '.flowletConfigName == "uplink_flowlet_config"\' >/dev/null'
                )
            ],
            validate_output=True,
        ),
    ]


def _rogue_device_groups() -> list[taac_types.DeviceGroupConfig]:
    def bgp_group(
        *,
        index: int,
        name: str,
        peer: str,
        local_as: int,
        network_group_name: str,
        prefix_start: str,
        nh_start: str,
    ) -> taac_types.DeviceGroupConfig:
        return taac_types.DeviceGroupConfig(
            device_group_index=index,
            device_group_name=name,
            tag_name=name,
            enable=True,
            multiplier=1,
            v6_addresses_config=taac_types.IpAddressesConfig(
                starting_ip=peer,
                increment_ip="::",
                gateway_starting_ip=ROGUE_GATEWAY,
                gateway_increment_ip="::",
                mask=64,
            ),
            v6_bgp_config=taac_types.BgpConfig(
                local_as_4_bytes=local_as,
                enable_4_byte_local_as=True,
                bgp_peer_type=ixia_types.BgpPeerType.EBGP,
                bgp_capabilities=[
                    ixia_types.BgpCapability.IpV6Unicast,
                    ixia_types.BgpCapability.Ipv6UnicastAddPath,
                ],
                hold_timer=30,
                keepalive_timer=10,
                custom_network_group_configs=[
                    ixia_types.CustomNetworkGroupConfig(
                        device_group_name=name,
                        network_group_name=network_group_name,
                        network_group_multiplier=1,
                        prefix_start_value=prefix_start,
                        prefix_length=64,
                        nexthop_start_value=nh_start,
                        nexthop_increments="::1",
                        ecmp_width=1,
                        network_group_index=0,
                    )
                ],
            ),
        )

    return [
        bgp_group(
            index=0,
            name="QZA1_CHENAB_DLB_GOLD_A",
            peer=GOLD_PEERS[0],
            local_as=4200000211,
            network_group_name=GOLD_PREFIX_POOLS[0],
            prefix_start=GOLD_POOL.prefix_base,
            nh_start=f"{GOLD_POOL.nh_network}::{GOLD_POOL.nh_host_start:x}",
        ),
        bgp_group(
            index=1,
            name="QZA1_CHENAB_DLB_GOLD_B",
            peer=GOLD_PEERS[1],
            local_as=4200000211,
            network_group_name=GOLD_PREFIX_POOLS[1],
            prefix_start=GOLD_POOL.prefix_base,
            nh_start=f"{GOLD_POOL.nh_network}::{GOLD_POOL.nh_host_start:x}",
        ),
        bgp_group(
            index=2,
            name="QZA1_CHENAB_DLB_SILVER_A",
            peer=SILVER_PEERS[0],
            local_as=4200000212,
            network_group_name=SILVER_PREFIX_POOLS[0],
            prefix_start=SILVER_POOL.prefix_base,
            nh_start=f"{SILVER_POOL.nh_network}::{SILVER_POOL.nh_host_start:x}",
        ),
        bgp_group(
            index=3,
            name="QZA1_CHENAB_DLB_SILVER_B",
            peer=SILVER_PEERS[1],
            local_as=4200000212,
            network_group_name=SILVER_PREFIX_POOLS[1],
            prefix_start=SILVER_POOL.prefix_base,
            nh_start=f"{SILVER_POOL.nh_network}::{SILVER_POOL.nh_host_start:x}",
        ),
        taac_types.DeviceGroupConfig(
            device_group_index=4,
            device_group_name="QZA1_CHENAB_GOLD_NDP",
            tag_name="QZA1_CHENAB_GOLD_NDP",
            multiplier=GOLD_POOL.size,
            v6_addresses_config=taac_types.IpAddressesConfig(
                starting_ip=f"{GOLD_POOL.nh_network}::{GOLD_POOL.nh_host_start:x}",
                increment_ip="::1",
                gateway_starting_ip=ROGUE_GATEWAY,
                gateway_increment_ip="::",
                mask=64,
            ),
        ),
        taac_types.DeviceGroupConfig(
            device_group_index=5,
            device_group_name="QZA1_CHENAB_SILVER_NDP",
            tag_name="QZA1_CHENAB_SILVER_NDP",
            multiplier=SILVER_POOL.size,
            v6_addresses_config=taac_types.IpAddressesConfig(
                starting_ip=f"{SILVER_POOL.nh_network}::{SILVER_POOL.nh_host_start:x}",
                increment_ip="::1",
                gateway_starting_ip=ROGUE_GATEWAY,
                gateway_increment_ip="::",
                mask=64,
            ),
        ),
    ]


def _playbook(shape: BoundedChenabCase18Shape) -> taac_types.Playbook:
    pool_csvs = _write_case_csvs(shape)
    gold_csvs, silver_csvs = pool_csvs[:2], pool_csvs[2:]
    setup_steps: list[taac_types.Step] = [
        create_ixia_api_step(
            api_name="apply_pool_mutations",
            args_dict={"pool_csvs": [list(row) for row in gold_csvs]},
            description="Program bounded width-two Gold groups first",
        ),
        create_longevity_step(
            duration=60,
            description="Allow bounded Chenab Gold groups to fill primary slots",
        ),
        _validated_counter_step(
            shape,
            silver_enabled=False,
            description="Assert Gold fills all 190 primary groups",
        ),
        create_ixia_api_step(
            api_name="apply_pool_mutations",
            args_dict={"pool_csvs": [list(row) for row in silver_csvs]},
            description="Program bounded width-two Silver groups after Gold",
        ),
        create_longevity_step(
            duration=60,
            description="Allow bounded Chenab Silver groups to enter backup mode",
        ),
        _validated_counter_step(
            shape,
            silver_enabled=True,
            description="Assert 190 primary and 8 backup groups before flap loop",
        ),
        _validated_route_state_step(
            shape,
            silver_enabled=True,
            description="Assert Silver routes are present in BGP RIB and width-two FIB",
        ),
    ]
    traffic_steps: list[taac_types.Step] = [create_start_traffic_step()]
    for cycle in range(shape.cycle_count):
        iteration = cycle + 1
        traffic_steps.extend(
            [
                create_ixia_api_step(
                    api_name="set_dlb_route_pools_active",
                    args_dict={
                        "pool_names": list(SILVER_PREFIX_POOLS),
                        "active": False,
                        "expected_route_cells": shape.silver_groups,
                        "settle_time_after_start": 0,
                    },
                    description=(
                        f"Case18 cycle {iteration}/{shape.cycle_count}: "
                        "atomically withdraw exact Silver route ranges"
                    ),
                ),
                _validated_route_state_step(
                    shape,
                    silver_enabled=False,
                    description=f"Case18 cycle {iteration}: assert Silver RIB/FIB absent",
                ),
                _validated_counter_step(
                    shape,
                    silver_enabled=False,
                    description=f"Case18 cycle {iteration}: assert backup=0",
                ),
                create_ixia_api_step(
                    api_name="set_dlb_route_pools_active",
                    args_dict={
                        "pool_names": list(SILVER_PREFIX_POOLS),
                        "active": True,
                        "expected_route_cells": shape.silver_groups,
                        "settle_time_after_start": 10,
                    },
                    description=(
                        f"Case18 cycle {iteration}/{shape.cycle_count}: "
                        "atomically re-advertise exact Silver route ranges"
                    ),
                ),
                _validated_route_state_step(
                    shape,
                    silver_enabled=True,
                    description=f"Case18 cycle {iteration}: assert Silver RIB/FIB restored",
                ),
                _validated_counter_step(
                    shape,
                    silver_enabled=True,
                    description=f"Case18 cycle {iteration}: assert backup={shape.silver_groups}",
                ),
            ]
        )
    traffic_steps.append(create_stop_traffic_step())

    stickiness = {
        "prefix_patterns": [GOLD_POOL.prefix_base, SILVER_POOL.prefix_base],
        "expected_counts": {
            "5000:dd prefixes": {
                "dlb": shape.gold_groups,
                "other_modes": 0,
                "total": shape.gold_groups,
                "ecmp_width": shape.group_width,
            },
            "5000:ee prefixes": {
                "dlb": 0,
                "other_modes": shape.silver_groups,
                "total": shape.silver_groups,
                "ecmp_width": shape.group_width,
            },
        },
        # The hardware snapshot parser counts every installed NHG, including
        # all fixed Silver groups. The route matrix's managed-prefix side
        # contains Gold only.
        "snapshot_expected_extra_groups": (
            shape.baseline_primary_groups + shape.silver_groups
        ),
    }
    packet_loss = create_ixia_packet_loss_check(
        thresholds=[
            hc_types.PacketLossThreshold(
                names=[TRAFFIC_NAME],
                metric=hc_types.PacketLossMetric.DURATION,
                str_value="0",
            )
        ],
        clear_traffic_stats=True,
        sleep_time=60,
    )
    playbook = create_dlb_hardening_playbook(
        name="CASE_18_DLB_ECMP_FLAP_LONGEVITY_QUICK",
        setup_steps=setup_steps,
        traffic_steps=traffic_steps,
        stickiness_json_params=stickiness,
        extra_postchecks=[packet_loss],
    )
    active = create_systemctl_active_state_check(
        services=[
            hc_types.Service.WEDGE_AGENT,
            hc_types.Service.BGPD,
            hc_types.Service.QSFP_SERVICE,
            hc_types.Service.FSDB,
            hc_types.Service.FBOSS_SW_AGENT,
            hc_types.Service.FBOSS_HW_AGENT_0,
        ]
    )
    bgp = create_bgp_session_establish_check(
        ignore_all_prefixes_except=[*GOLD_PEERS, *SILVER_PEERS],
        expected_established_sessions=4,
    )
    return playbook(
        prechecks=[active, bgp],
        postchecks=list(playbook.postchecks or []) + [active, bgp],
        snapshot_checks=[create_core_dumps_snapshot_check()],
    )


def create_qza_rtsw_dlb_case18_test_config(
    shape: BoundedChenabCase18Shape = CASE18_SHAPE,
) -> taac_types.TestConfig:
    l1 = ixia_types.L1Config(
        enable_fcoe=True,
        flow_control_config=ixia_types.FlowControlConfig(
            pfc_prority_groups_config=ixia_types.PfcPriorityGroupsConfig(
                priority0_pfc_queue=ixia_types.PfcQueue.TWO,
                priority1_pfc_queue=ixia_types.PfcQueue.ONE,
                priority2_pfc_queue=ixia_types.PfcQueue.ZERO,
                priority3_pfc_queue=ixia_types.PfcQueue.THREE,
            ),
            enable_pfc_pause_delay=False,
        ),
    )
    return taac_types.TestConfig(
        name="QZA_RTSW001_CHENAB_DLB_CASE18_QUICK",
        basset_pool="dne.test",
        basset_reservation_time_hr=288,
        ixia_config_cache=taac_types.IxiaConfigCache(enabled=False),
        endpoints=[
            taac_types.Endpoint(
                name=DEVICE,
                dut=True,
                ixia_needed=True,
                ixia_ports=[DOWNLINK_INTERFACE, ROGUE_INTERFACE],
                direct_ixia_connections=[
                    taac_types.DirectIxiaConnection(
                        interface=DOWNLINK_INTERFACE,
                        ixia_chassis_ip=IXIA_CHASSIS_IP,
                        ixia_port=DOWNLINK_IXIA_PORT,
                    ),
                    taac_types.DirectIxiaConnection(
                        interface=ROGUE_INTERFACE,
                        ixia_chassis_ip=IXIA_CHASSIS_IP,
                        ixia_port=ROGUE_IXIA_PORT,
                    ),
                ],
            )
        ],
        basic_port_configs=[
            taac_types.BasicPortConfig(
                endpoint=f"{DEVICE}:{DOWNLINK_INTERFACE}",
                l1_config=l1,
                device_group_configs=[
                    taac_types.DeviceGroupConfig(
                        device_group_index=0,
                        device_group_name="QZA1_CHENAB_CASE18_SOURCE",
                        tag_name="QZA1_CHENAB_CASE18_SOURCE",
                        multiplier=1,
                        v6_addresses_config=taac_types.IpAddressesConfig(
                            starting_ip=DOWNLINK_PEER,
                            increment_ip="::",
                            gateway_starting_ip=DOWNLINK_GATEWAY,
                            gateway_increment_ip="::",
                            mask=127,
                        ),
                    )
                ],
            ),
            taac_types.BasicPortConfig(
                endpoint=f"{DEVICE}:{ROGUE_INTERFACE}",
                l1_config=l1,
                device_group_configs=_rogue_device_groups(),
            ),
        ],
        basic_traffic_item_configs=[
            taac_types.BasicTrafficItemConfig(
                name=TRAFFIC_NAME,
                src_endpoints=[
                    taac_types.TrafficEndpoint(
                        name=f"{DEVICE}:{DOWNLINK_INTERFACE}",
                        device_group_index=0,
                    )
                ],
                dest_endpoints=[
                    taac_types.TrafficEndpoint(
                        name=f"{DEVICE}:{ROGUE_INTERFACE}",
                        device_group_index=0,
                        network_group_index=0,
                    )
                ],
                traffic_type=ixia_types.TrafficType.IPV6,
                bidirectional=False,
                merge_destinations=True,
                line_rate_type=ixia_types.RateType.PERCENT_LINE_RATE,
                line_rate=10,
                frame_size_settings=ixia_types.FrameSize(
                    type=ixia_types.FrameSizeType.FIXED,
                    fixed_size=1024,
                ),
                src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
                tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
                packet_headers=DSF_RDMA_IB_PACKET_HEADERS,
            )
        ],
        setup_tasks=_setup_tasks(shape),
        teardown_tasks=[
            create_coop_unregister_patchers_task(
                DEVICE,
                config_names=["agent", "bgpcpp"],
                regex=f"^{PATCHER_NAMESPACE}",
            )
        ],
        playbooks=[_playbook(shape)],
    )


QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG = (
    create_qza_rtsw_dlb_case18_test_config()
)

# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Strict NSF reference adaptation for IXIA12/16 across two pods.

Sole native-NetOS DUT RTSW001.l101, forwarding peer RTSW003.l102.
Five-host path, 10 SW/HW0 warmboots, two directions of 50% RDMA-class IMIX.
Scoped COOP jq patchers preserve existing RIF objects and STSW policy terms.
"""

import copy
import ipaddress
import json
import re
from typing import Any

from ixia.ixia import types as ixia_types
from taac.health_checks.healthcheck_definitions import (
    create_bgp_route_count_verification_check,
    create_bgp_session_establish_check,
    create_bgp_session_snapshot_check,
    create_core_dumps_snapshot_check,
    create_cpu_utilization_check,
    create_device_core_dumps_check,
    create_ixia_packet_loss_check,
    create_ixia_traffic_rate_check,
    create_memory_utilization_check,
    create_pfc_wd_check,
    create_port_speed_check,
    create_port_speed_snapshot_check,
    create_port_state_check,
    create_qos_dscp_tx_queue_snapshot_check,
    create_service_restart_check,
    create_systemctl_active_state_check,
    create_unclean_exit_check,
    create_wedge_agent_configured_check,
)
from taac.packet_headers import DSF_RDMA_PACKET_HEADERS
from taac.playbooks.playbook_definitions import (
    create_longevity_playbook,
    gen_endurance_playbook,
    TEST_CONTINUOUS_AGENT_WARMBOOT_PLAYBOOK,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_clear_traffic_stats_step,
    create_longevity_step,
    create_record_jq_timestamp_step,
    create_run_task_step,
    create_service_convergence_step,
    create_service_interruption_step,
    create_validation_step,
)
from taac.task_definitions import (
    create_assert_agent_warm_boot_task,
    create_assert_process_vmhwm_task,
    create_coop_apply_patchers_task,
    create_coop_register_jq_patcher_task,
    create_coop_register_patcher_task,
    create_coop_unregister_patchers_task,
    create_ixia_preflight_task,
    create_verify_selected_bgp_routes_task,
    create_verify_selected_forwarding_task,
    create_wait_for_agent_convergence_task,
)
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types

DUT = "rtsw001.l101.c084.qza1"
REMOTE = "rtsw003.l102.c084.qza1"
LOCAL_TRANSIT = "ftsw001.l101.c084.qza1"
SHARED_TRANSIT = "stsw001.s001.l201.qza1"
REMOTE_TRANSIT = "ftsw001.l102.c084.qza1"
HOSTS = [
    "rtsw001.l101.c084.qza1",
    "ftsw001.l101.c084.qza1",
    "stsw001.s001.l201.qza1",
    "ftsw001.l102.c084.qza1",
    "rtsw003.l102.c084.qza1",
]
EDGE_HOSTS = [DUT, REMOTE]
HOST_METADATA = {
    "rtsw001.l101.c084.qza1": {
        "asn": 4200000111,
        "native": True,
        "drain": "UNDRAINED",
        "agent_views": ["agent"],
        "bgp_views": ["bgpcpp"],
        "ixia_needed": True,
    },
    "ftsw001.l101.c084.qza1": {
        "asn": 4200000111,
        "native": True,
        "drain": "SOFT_DRAINED",
        "agent_views": ["agent", "agent_drain"],
        "bgp_views": ["bgpcpp", "bgpcpp_softdrain"],
        "ixia_needed": False,
    },
    "rtsw003.l102.c084.qza1": {
        "asn": 4200000111,
        "native": False,
        "drain": "UNDRAINED",
        "agent_views": ["agent"],
        "bgp_views": ["bgpcpp"],
        "ixia_needed": True,
    },
    "ftsw001.l102.c084.qza1": {
        "asn": 4200000111,
        "native": False,
        "drain": "UNDRAINED",
        "agent_views": ["agent"],
        "bgp_views": ["bgpcpp"],
        "ixia_needed": False,
    },
    "stsw001.s001.l201.qza1": {
        "asn": 4200000000,
        "native": False,
        "drain": "UNDRAINED",
        "agent_views": ["agent"],
        "bgp_views": ["bgpcpp"],
        "ixia_needed": False,
    },
}
PATCHER_NAMESPACE = "qza1_z_ixia12_16_nsf_"
EDGE_GROUP = "PEERGROUP_RTSW_QZA1_IXIA12_16_NSF_IXIA_V6"
TRAFFIC_NAMES = ["QZA1_NSF_IXIA12_TO_IXIA16", "QZA1_NSF_IXIA16_TO_IXIA12"]
PREFIX_COUNT = 50
V6_PREFIX_STEP = "0:0:0:1::"
MEMORY_HWM_BYTES = 4_300_000_000
DUT_REGEX = [rf"^{re.escape(DUT)}(?:\.tfbnw\.net)?$"]
SERVICES = ["wedge_agent", "fboss_sw_agent", "bgpd", "fsdb", "qsfp_service", "coop"]
NATIVE_RESOURCE_SERVICES = [
    "fboss_wedge_agent_nvda_0",
    "fboss_sw_agent",
    "fboss_bgp",
    "fboss_fsdb",
    "fboss_qsfp_service",
    "fboss_coop",
]
# Full addresses avoid crossing the two pod-specific address bases.
EDGE_PORTS = [
    (
        "rtsw001.l101.c084.qza1",
        "eth1/2/1",
        "1/12",
        "2401:db00:e2d1:b70::4",
        "2401:db00:e2d1:b70::5",
        4200000201,
        "2001:db8:3100::",
    ),
    (
        "rtsw001.l101.c084.qza1",
        "eth1/2/5",
        "1/11",
        "2401:db00:e2d1:b70::6",
        "2401:db00:e2d1:b70::7",
        4200000202,
        "2001:db8:3200::",
    ),
    (
        "rtsw003.l102.c084.qza1",
        "eth1/1/1",
        "1/9",
        "2401:db00:e2d1:b80::18",
        "2401:db00:e2d1:b80::19",
        4200000203,
        "2001:db8:4100::",
    ),
    (
        "rtsw003.l102.c084.qza1",
        "eth1/1/5",
        "1/10",
        "2401:db00:e2d1:b80::1a",
        "2401:db00:e2d1:b80::1b",
        4200000204,
        "2001:db8:4200::",
    ),
]
SELECTED_PORTS = {
    "rtsw001.l101.c084.qza1": ["eth1/2/1", "eth1/2/5", "eth1/33/1", "eth1/33/5"],
    "ftsw001.l101.c084.qza1": ["eth1/3/1", "eth1/3/5", "eth1/1/1", "eth1/1/5"],
    "rtsw003.l102.c084.qza1": ["eth1/1/1", "eth1/1/5", "eth1/33/1", "eth1/33/5"],
    "ftsw001.l102.c084.qza1": ["eth1/43/1", "eth1/43/5", "eth1/1/1", "eth1/1/5"],
    "stsw001.s001.l201.qza1": ["eth1/2/1", "eth1/2/5", "eth1/6/1", "eth1/6/5"],
}
CHASSIS = {
    "rtsw001.l101.c084.qza1": ("ixia12.netcastle.ash6", "2401:db00:2066:304b::3003"),
    "rtsw003.l102.c084.qza1": ("ixia16.netcastle.ash6", "2401:db00:2066:304b::3004"),
}
TRANSIT_PEERS = {
    "rtsw001.l101.c084.qza1": [
        ("2401:db00:e2d1:b70::101", "2401:db00:e2d1:b70::100"),
        ("2401:db00:e2d1:b70::105", "2401:db00:e2d1:b70::104"),
    ],
    "ftsw001.l101.c084.qza1": [
        ("2401:db00:e2d1:b70::100", "2401:db00:e2d1:b70::101"),
        ("2401:db00:e2d1:b70::104", "2401:db00:e2d1:b70::105"),
        ("2401:db00:e2d1:b04::1", "2401:db00:e2d1:b04::0"),
        ("2401:db00:e2d1:b04::3", "2401:db00:e2d1:b04::2"),
    ],
    "stsw001.s001.l201.qza1": [
        ("2401:db00:e2d1:b04::0", "2401:db00:e2d1:b04::1"),
        ("2401:db00:e2d1:b04::2", "2401:db00:e2d1:b04::3"),
        ("2401:db00:e2d1:b04::24", "2401:db00:e2d1:b04::25"),
        ("2401:db00:e2d1:b04::26", "2401:db00:e2d1:b04::27"),
    ],
    "ftsw001.l102.c084.qza1": [
        ("2401:db00:e2d1:b04::25", "2401:db00:e2d1:b04::24"),
        ("2401:db00:e2d1:b04::27", "2401:db00:e2d1:b04::26"),
        ("2401:db00:e2d1:b80::200", "2401:db00:e2d1:b80::201"),
        ("2401:db00:e2d1:b80::204", "2401:db00:e2d1:b80::205"),
    ],
    "rtsw003.l102.c084.qza1": [
        ("2401:db00:e2d1:b80::201", "2401:db00:e2d1:b80::200"),
        ("2401:db00:e2d1:b80::205", "2401:db00:e2d1:b80::204"),
    ],
}
LOCAL_TRANSIT_RTSW_PEERS = [
    ("2401:db00:e2d1:b70::100", "2401:db00:e2d1:b70::101"),
    ("2401:db00:e2d1:b70::104", "2401:db00:e2d1:b70::105"),
    ("2401:db00:e2d1:b70::102", "2401:db00:e2d1:b70::103"),
    ("2401:db00:e2d1:b70::106", "2401:db00:e2d1:b70::107"),
]
NEW_TRANSIT_RIFS = {
    "ftsw001.l101.c084.qza1": [
        {"interface_id": 2005, "port_id": 253, "ip": "2401:db00:e2d1:b70::100/127"},
        {"interface_id": 2006, "port_id": 255, "ip": "2401:db00:e2d1:b70::104/127"},
        {"interface_id": 2045, "port_id": 169, "ip": "2401:db00:e2d1:b70::102/127"},
        {"interface_id": 2046, "port_id": 171, "ip": "2401:db00:e2d1:b70::106/127"},
    ],
    "rtsw003.l102.c084.qza1": [
        {"interface_id": 2001, "port_id": 13, "ip": "2401:db00:e2d1:b80::201/127"},
        {"interface_id": 2002, "port_id": 15, "ip": "2401:db00:e2d1:b80::205/127"},
    ],
    "ftsw001.l102.c084.qza1": [
        {"interface_id": 2085, "port_id": 33, "ip": "2401:db00:e2d1:b80::200/127"},
        {"interface_id": 2086, "port_id": 35, "ip": "2401:db00:e2d1:b80::204/127"},
    ],
}
FORWARDING_NEXT_HOPS = {
    "rtsw001.l101.c084.qza1": {
        "2001:db8:3100::": [{"ip": "2401:db00:e2d1:b70::4", "interface_id": 4003}],
        "2001:db8:3200::": [{"ip": "2401:db00:e2d1:b70::6", "interface_id": 4004}],
        "2001:db8:4100::": [
            {"ip": "2401:db00:e2d1:b70::100", "interface_id": 2001},
            {"ip": "2401:db00:e2d1:b70::104", "interface_id": 2002},
        ],
        "2001:db8:4200::": [
            {"ip": "2401:db00:e2d1:b70::100", "interface_id": 2001},
            {"ip": "2401:db00:e2d1:b70::104", "interface_id": 2002},
        ],
    },
    "ftsw001.l101.c084.qza1": {
        "2001:db8:3100::": [
            {"ip": "2401:db00:e2d1:b70::101", "interface_id": 2005},
            {"ip": "2401:db00:e2d1:b70::105", "interface_id": 2006},
        ],
        "2001:db8:3200::": [
            {"ip": "2401:db00:e2d1:b70::101", "interface_id": 2005},
            {"ip": "2401:db00:e2d1:b70::105", "interface_id": 2006},
        ],
        "2001:db8:4100::": [
            {"ip": "2401:db00:e2d1:b04::0", "interface_id": 2001},
            {"ip": "2401:db00:e2d1:b04::2", "interface_id": 2002},
        ],
        "2001:db8:4200::": [
            {"ip": "2401:db00:e2d1:b04::0", "interface_id": 2001},
            {"ip": "2401:db00:e2d1:b04::2", "interface_id": 2002},
        ],
    },
    "stsw001.s001.l201.qza1": {
        "2001:db8:3100::": [
            {"ip": "2401:db00:e2d1:b04::1", "interface_id": 2003},
            {"ip": "2401:db00:e2d1:b04::3", "interface_id": 2004},
        ],
        "2001:db8:3200::": [
            {"ip": "2401:db00:e2d1:b04::1", "interface_id": 2003},
            {"ip": "2401:db00:e2d1:b04::3", "interface_id": 2004},
        ],
        "2001:db8:4100::": [
            {"ip": "2401:db00:e2d1:b04::25", "interface_id": 2011},
            {"ip": "2401:db00:e2d1:b04::27", "interface_id": 2012},
        ],
        "2001:db8:4200::": [
            {"ip": "2401:db00:e2d1:b04::25", "interface_id": 2011},
            {"ip": "2401:db00:e2d1:b04::27", "interface_id": 2012},
        ],
    },
    "ftsw001.l102.c084.qza1": {
        "2001:db8:3100::": [
            {"ip": "2401:db00:e2d1:b04::24", "interface_id": 2001},
            {"ip": "2401:db00:e2d1:b04::26", "interface_id": 2002},
        ],
        "2001:db8:3200::": [
            {"ip": "2401:db00:e2d1:b04::24", "interface_id": 2001},
            {"ip": "2401:db00:e2d1:b04::26", "interface_id": 2002},
        ],
        "2001:db8:4100::": [
            {"ip": "2401:db00:e2d1:b80::201", "interface_id": 2085},
            {"ip": "2401:db00:e2d1:b80::205", "interface_id": 2086},
        ],
        "2001:db8:4200::": [
            {"ip": "2401:db00:e2d1:b80::201", "interface_id": 2085},
            {"ip": "2401:db00:e2d1:b80::205", "interface_id": 2086},
        ],
    },
    "rtsw003.l102.c084.qza1": {
        "2001:db8:3100::": [
            {"ip": "2401:db00:e2d1:b80::200", "interface_id": 2001},
            {"ip": "2401:db00:e2d1:b80::204", "interface_id": 2002},
        ],
        "2001:db8:3200::": [
            {"ip": "2401:db00:e2d1:b80::200", "interface_id": 2001},
            {"ip": "2401:db00:e2d1:b80::204", "interface_id": 2002},
        ],
        "2001:db8:4100::": [{"ip": "2401:db00:e2d1:b80::18", "interface_id": 4001}],
        "2001:db8:4200::": [{"ip": "2401:db00:e2d1:b80::1a", "interface_id": 4002}],
    },
}
INTERFACE_PORTS = {
    "rtsw001.l101.c084.qza1": {"4003": 245, "4004": 247, "2001": 13, "2002": 15},
    "ftsw001.l101.c084.qza1": {"2005": 253, "2006": 255, "2001": 241, "2002": 243},
    "stsw001.s001.l201.qza1": {"2003": 245, "2004": 247, "2011": 229, "2012": 231},
    "ftsw001.l102.c084.qza1": {"2085": 33, "2086": 35, "2001": 241, "2002": 243},
    "rtsw003.l102.c084.qza1": {"4001": 241, "4002": 243, "2001": 13, "2002": 15},
}
# Numeric COOP JSON enums/default list fields verified by real typed serialization.
STSW_ASPATH_TERMS: list[dict[str, Any]] = [
    {
        "name": f"QZA1_IXIA12_16_NSF_ASPATH_{pool}",
        "description": "Exact NSF prefixes; preserve original STSW import policy after rewrite",
        "match_logic_type": 1,
        "policy_match_entries": {
            "name": "",
            "description": "",
            "match_logic_type": 1,
            "match_entries": [
                {
                    "type": 5,
                    "match_logic_type": 0,
                    "prefix_filters": {
                        "name": "",
                        "description": "",
                        "boolean_operator": 2,
                        "prefixes": [
                            {
                                "base_prefix": str(
                                    ipaddress.IPv6Address(
                                        int(ipaddress.IPv6Address(row[6]))
                                        + (index << 64)
                                    )
                                )
                                + "/64",
                                "prefix_len_ranges": [
                                    {"value": 64, "compare_operator": 1}
                                ],
                                "match_logic": 0,
                            }
                            for index in range(PREFIX_COUNT)
                        ],
                        "prefix_list_names": [],
                    },
                },
                {
                    "type": 3,
                    "match_logic_type": 0,
                    "communities_filter": {
                        "name": "",
                        "description": "",
                        "boolean_operator": 1,
                        "communities": ["65441:131"],
                    },
                },
                {
                    "type": 2,
                    "match_logic_type": 0,
                    "as_path_filters": {
                        "name": "",
                        "description": "",
                        "boolean_operator": 1,
                        "as_paths": [f"^4200000111_{row[5]}$"],
                        "as_path_list": [],
                    },
                },
            ],
        },
        "policy_action_entries": [
            {"type": 9, "as_path_overwrite_list": [4200000999, row[5]]},
            {"type": 7},
        ],
        "term_miss_action": 3,
    }
    for row, pool in zip(EDGE_PORTS, ["3100", "3200", "4100", "4200"])
]
CHANGED_AGENT_HOSTS = [LOCAL_TRANSIT, REMOTE, REMOTE_TRANSIT]
CHANGED_BGP_HOSTS = [DUT, LOCAL_TRANSIT, REMOTE, REMOTE_TRANSIT, SHARED_TRANSIT]
OFFPATH_EGRESS = {
    LOCAL_TRANSIT: {
        "group": "PEERGROUP_FTSW_STSW_V6",
        "expected_peer_count": 18,
        "allowed": [
            {"local": "2401:db00:e2d1:b04::1", "peer": "2401:db00:e2d1:b04::"},
            {"local": "2401:db00:e2d1:b04::3", "peer": "2401:db00:e2d1:b04::2"},
        ],
    },
    REMOTE_TRANSIT: {
        "group": "PEERGROUP_FTSW_STSW_V6",
        "expected_peer_count": 18,
        "allowed": [
            {"local": "2401:db00:e2d1:b04::25", "peer": "2401:db00:e2d1:b04::24"},
            {"local": "2401:db00:e2d1:b04::27", "peer": "2401:db00:e2d1:b04::26"},
        ],
    },
    SHARED_TRANSIT: {
        "group": "PEERGROUP_STSW_FTSW_V6",
        "expected_peer_count": 36,
        "allowed": [
            {"local": "2401:db00:e2d1:b04::", "peer": "2401:db00:e2d1:b04::1"},
            {"local": "2401:db00:e2d1:b04::2", "peer": "2401:db00:e2d1:b04::3"},
            {"local": "2401:db00:e2d1:b04::24", "peer": "2401:db00:e2d1:b04::25"},
            {"local": "2401:db00:e2d1:b04::26", "peer": "2401:db00:e2d1:b04::27"},
        ],
    },
}


def _address(address: str) -> str:
    return str(ipaddress.IPv6Address(address))


def _config_views(host: str, config_name: str) -> list[str]:
    return HOST_METADATA[host]["agent_views" if config_name == "agent" else "bgp_views"]


def _prefixes(host: str) -> list[str]:
    # Explicit /64 increment keeps all 50 routes inside each declared /48 pool.
    return [
        str(ipaddress.IPv6Address(int(ipaddress.IPv6Address(row[6])) + (index << 64)))
        + "/64"
        for row in EDGE_PORTS
        if row[0] == host
        for index in range(PREFIX_COUNT)
    ]


def _policy_task(host: str, direction: str, prefixes: list[str]):
    matches: list[dict[str, Any]] = [
        {
            "type": 5,
            "prefix_filters": {
                "name": f"QZA1_NSF_{direction}_PREFIXES",
                "version": 2,
                "boolean_operator": 2,
                "prefixes": [
                    {
                        "base_prefix": prefix,
                        "prefix_len_ranges": [{"value": 64, "compare_operator": 1}],
                    }
                    for prefix in prefixes
                ],
            },
        }
    ]
    if direction == "IN":
        matches.append(
            {
                "type": 3,
                "communities_filter": {
                    "name": "QZA1_NSF_ORIGIN",
                    "boolean_operator": 2,
                    "communities": ["65441:65"],
                },
            }
        )
    return create_coop_register_patcher_task(
        hostname=host,
        config_name="bgpcpp",
        patcher_name=f"{PATCHER_NAMESPACE}b_policy_{direction.lower()}",
        py_func_name="add_bgp_policy_statement",
        patcher_args={
            "name": f"QZA1_IXIA12_16_NSF_IXIA_{direction}",
            "description": "Only declared QZA1 NSF test prefixes",
            "policy_entries": json.dumps(
                [
                    {
                        "name": "PERMIT_SELECTED_TEST_ROUTES",
                        "policy_match_entries": {
                            "match_logic_type": 1,
                            "match_entries": matches,
                        },
                        "policy_action_entries": [{"type": 5}],
                    }
                ]
            ),
        },
    )


def _rif_secondary_jq(host: str) -> str:
    # Preserve every existing RIF field and IP order; only append managed IPs.
    changes = json.dumps(NEW_TRANSIT_RIFS[host], separators=(",", ":"))
    return (
        changes + " as $changes | "
        'if (.sw.interfaces | type) != "array" then error("Missing agent RIF array") else '
        "reduce $changes[] as $change (. ; "
        "if ([.sw.interfaces[] | select(.intfID == $change.interface_id and .portID == $change.port_id)] | length) != 1 "
        'then error("Require exactly one expected PORT RIF binding") else '
        ".sw.interfaces |= map(if .intfID == $change.interface_id and .portID == $change.port_id then "
        "if (.ipAddresses | index($change.ip)) == null then .ipAddresses += [$change.ip] else . end "
        "else . end) end) end"
    )


def _stsw_aspath_jq() -> str:
    # These new terms exactly match real COOP typed serialization.
    names = json.dumps([term["name"] for term in STSW_ASPATH_TERMS])
    terms = json.dumps(STSW_ASPATH_TERMS, separators=(",", ":"))
    return (
        terms + " as $terms | " + names + " as $names | "
        'if ([.policies.bgp_policy_statements[] | select(.name == "PROPAGATE_STSW_FTSW_IN")] | length) != 1 '
        'then error("Require exactly one original STSW inbound policy") else '
        '.policies.bgp_policy_statements |= map(if .name == "PROPAGATE_STSW_FTSW_IN" then '
        ".policy_entries = ($terms + [.policy_entries[] | .name as $name | select(($names | index($name)) == null)]) "
        "else . end) end"
    )


def _offpath_deny_terms(host: str) -> list[dict]:
    terms = copy.deepcopy(STSW_ASPATH_TERMS)
    is_stsw = host == SHARED_TRANSIT
    for term in terms:
        term["name"] = term["name"].replace("ASPATH", "OFFPATH_DENY")
        term["description"] = "Suppress exact NSF pools only on excluded FT-ST branches"
        origin = term["policy_action_entries"][0]["as_path_overwrite_list"][1]
        term["policy_action_entries"] = [{"type": 6}]
        community_filter = term["policy_match_entries"]["match_entries"][1][
            "communities_filter"
        ]
        community_filter["communities"] = (
            ["65441:131"] if is_stsw else ["65441:130", "65441:132"]
        )
        community_filter["boolean_operator"] = 1 if is_stsw else 2
        as_path_filter = term["policy_match_entries"]["match_entries"][2][
            "as_path_filters"
        ]
        as_path_filter["as_paths"] = [
            f"^4200000999_{origin}$"
            if is_stsw
            else f"^({origin}|4200000000_4200000999_{origin})$"
        ]
    return terms


def _offpath_egress_jq(host: str) -> str:
    params = {
        **OFFPATH_EGRESS[host],
        "alias_prefix": "QZA1_IXIA12_16_NSF_OFFPATH_",
    }
    return (
        json.dumps(params, separators=(",", ":"))
        + " as $p | "
        + json.dumps(_offpath_deny_terms(host), separators=(",", ":"))
        + " as $terms | "
        'if ([.peer_groups[] | select(.name == $p.group)] | length) != 1 then error("Require one FT-ST group") else '
        "([.peer_groups[] | select(.name == $p.group)][0]) as $group | "
        "$group.egress_policy_name as $base_name | ($p.alias_prefix + $base_name) as $alias | "
        'if ([.policies.bgp_policy_statements[] | select(.name == $base_name)] | length) != 1 then error("Require one original egress policy") else '
        "([.policies.bgp_policy_statements[] | select(.name == $base_name)][0]) as $base | "
        "[.peers[] | select(.peer_group_name == $p.group)] as $peers | "
        'if ($peers | length) != $p.expected_peer_count then error("FT-ST peer count changed") '
        'elif ($p.allowed | all(. as $a | ([$peers[] | select(.local_addr == $a.local and .peer_addr == $a.peer)] | length) == 1)) | not then error("Selected FT-ST peer identity changed") '
        'elif ($peers | any(. as $peer | (($p.allowed | any(.local == $peer.local_addr and .peer == $peer.peer_addr)) | not) and (.egress_policy_name != null and .egress_policy_name != $base_name and .egress_policy_name != $alias))) then error("Unexpected offpath egress override") '
        "else ($base | .name = $alias | .policy_entries = ($terms + .policy_entries)) as $new | "
        ".policies.bgp_policy_statements = ([.policies.bgp_policy_statements[] | select(.name != $alias)] + [$new]) | "
        ".peers |= map(if .peer_group_name == $p.group and ((. as $peer | $p.allowed | any(.local == $peer.local_addr and .peer == $peer.peer_addr)) | not) then .egress_policy_name = $alias else . end) end end end"
    )


def _setup_tasks():
    tasks = [
        create_ixia_preflight_task(
            chassis_hostname=CHASSIS[host][0],
            test_ports=[row[2] for row in EDGE_PORTS if row[0] == host],
        )
        for host in EDGE_HOSTS
    ]
    tasks.append(create_wait_for_agent_convergence_task(HOSTS))
    for host in HOSTS:
        tasks.append(
            create_coop_unregister_patchers_task(
                hostnames=host,
                config_names=_config_views(host, "agent")
                + _config_views(host, "bgpcpp"),
                regex=f"^{PATCHER_NAMESPACE}",
            )
        )
    for host in CHANGED_AGENT_HOSTS:
        tasks.append(
            create_coop_register_jq_patcher_task(
                hostname=host,
                config_names=_config_views(host, "agent"),
                patcher_name=f"{PATCHER_NAMESPACE}a_transit_rifs",
                jq_program=_rif_secondary_jq(host),
            )
        )
    for host in EDGE_HOSTS:
        tasks.extend(
            [
                _policy_task(host, "IN", _prefixes(host)),
                _policy_task(host, "OUT", _prefixes(REMOTE if host == DUT else DUT)),
            ]
        )
        tasks.append(
            create_coop_register_patcher_task(
                hostname=host,
                config_name="bgpcpp",
                patcher_name=f"{PATCHER_NAMESPACE}c_edge_group",
                py_func_name="add_peer_group_patcher",
                patcher_args={
                    "name": EDGE_GROUP,
                    "description": "QZA1 NSF dedicated IXIA12/16 edges",
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
            )
        )
        peers = []
        for row in EDGE_PORTS:
            if row[0] != host:
                continue
            tasks.append(
                create_coop_register_patcher_task(
                    hostname=host,
                    config_name="bgpcpp",
                    patcher_name=f"{PATCHER_NAMESPACE}a_remove_edge_{row[1].replace('/', '_')}",
                    py_func_name="remove_specific_bgp_peers",
                    patcher_args={"peer_attr:peer_addr": row[3]},
                )
            )
            peers.append(
                {
                    "local_addr": row[4],
                    "peer_addr": row[3],
                    "remote_as_4_byte": str(row[5]),
                    "description": f"QZA1 NSF IXIA {row[1]}",
                    "peer_group_name": EDGE_GROUP,
                }
            )
        tasks.append(
            create_coop_register_patcher_task(
                hostname=host,
                config_name="bgpcpp",
                patcher_name=f"{PATCHER_NAMESPACE}d_edge_peers",
                py_func_name="add_bgp_peers",
                patcher_args={"peer_configs": json.dumps(peers)},
            )
        )
    for host in [LOCAL_TRANSIT, REMOTE, REMOTE_TRANSIT]:
        peer_rows = (
            LOCAL_TRANSIT_RTSW_PEERS
            if host == LOCAL_TRANSIT
            else TRANSIT_PEERS[host]
            if host == REMOTE
            else TRANSIT_PEERS[host][2:]
        )
        config_names = (
            _config_views(host, "bgp") if host == LOCAL_TRANSIT else ["bgpcpp"]
        )
        for config_name in config_names:
            if host == REMOTE_TRANSIT:
                # These obsolete FT->RT003 peers target the selected RT IXIA gateways.
                # Replace only these two adjacencies; preserve every original RIF IP.
                for index, row in enumerate(
                    row for row in EDGE_PORTS if row[0] == REMOTE
                ):
                    tasks.append(
                        create_coop_register_patcher_task(
                            hostname=host,
                            config_name=config_name,
                            patcher_name=f"{PATCHER_NAMESPACE}a_remove_obsolete_downlink_{index}",
                            py_func_name="remove_specific_bgp_peers",
                            patcher_args={"peer_attr:peer_addr": _address(row[4])},
                        )
                    )
            for index, (_local, peer) in enumerate(peer_rows):
                tasks.append(
                    create_coop_register_patcher_task(
                        hostname=host,
                        config_name=config_name,
                        patcher_name=f"{PATCHER_NAMESPACE}a_remove_transit_{index}",
                        py_func_name="remove_specific_bgp_peers",
                        patcher_args={"peer_attr:peer_addr": _address(peer)},
                    )
                )
            tasks.append(
                create_coop_register_patcher_task(
                    hostname=host,
                    config_name=config_name,
                    patcher_name=f"{PATCHER_NAMESPACE}d_transit_peers",
                    py_func_name="add_bgp_peers",
                    patcher_args={
                        "peer_configs": json.dumps(
                            [
                                {
                                    "local_addr": local,
                                    "peer_addr": peer,
                                    "remote_as_4_byte": str(HOST_METADATA[host]["asn"]),
                                    "description": f"QZA1 NSF {'transit' if host == LOCAL_TRANSIT else 'remote transit'} {host}",
                                    "peer_group_name": "PEERGROUP_RTSW_FTSW_V6"
                                    if host == REMOTE
                                    else "PEERGROUP_FTSW_RTSW_V6",
                                }
                                for local, peer in peer_rows
                            ]
                        )
                    },
                )
            )
    tasks.append(
        create_coop_register_jq_patcher_task(
            hostname=SHARED_TRANSIT,
            config_names=["bgpcpp"],
            patcher_name=f"{PATCHER_NAMESPACE}b_stsw_aspath",
            jq_program=_stsw_aspath_jq(),
        )
    )
    for host in [LOCAL_TRANSIT, SHARED_TRANSIT, REMOTE_TRANSIT]:
        tasks.append(
            create_coop_register_jq_patcher_task(
                hostname=host,
                config_names=_config_views(host, "bgp"),
                patcher_name=f"{PATCHER_NAMESPACE}c_offpath_egress",
                jq_program=_offpath_egress_jq(host),
            )
        )
    tasks.extend(
        [
            create_coop_apply_patchers_task(
                hostnames=CHANGED_AGENT_HOSTS, config_name="agent"
            ),
            create_coop_apply_patchers_task(
                hostnames=CHANGED_BGP_HOSTS, config_name="bgpcpp"
            ),
            create_wait_for_agent_convergence_task(HOSTS),
        ]
    )
    return tasks


def _port_config(row) -> taac_types.BasicPortConfig:
    host, port, _, peer, gateway, asn, prefix = row
    return taac_types.BasicPortConfig(
        endpoint=f"{host}:{port}",
        l1_config=ixia_types.L1Config(
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
        ),
        device_group_configs=[
            taac_types.DeviceGroupConfig(
                device_group_index=0,
                multiplier=1,
                enable=True,
                device_group_name=f"QZA1_NSF_{host}_{port.replace('/', '_')}",
                v6_addresses_config=taac_types.IpAddressesConfig(
                    starting_ip=_address(peer),
                    increment_ip="::",
                    gateway_starting_ip=_address(gateway),
                    gateway_increment_ip="::",
                    mask=127,
                ),
                v6_bgp_config=taac_types.BgpConfig(
                    local_as_4_bytes=asn,
                    enable_4_byte_local_as=True,
                    bgp_peer_type=ixia_types.BgpPeerType.EBGP,
                    bgp_capabilities=[ixia_types.BgpCapability.IpV6Unicast],
                    enable_graceful_restart=True,
                    graceful_restart_timer=120,
                    advertise_end_of_rib=True,
                    hold_timer=30,
                    keepalive_timer=10,
                    route_scales=[
                        taac_types.RouteScaleSpec(
                            network_group_index=0,
                            multiplier=1,
                            v6_route_scale=taac_types.RouteScale(
                                multiplier=1,
                                prefix_count=PREFIX_COUNT,
                                prefix_length=64,
                                prefix_step=V6_PREFIX_STEP,
                                starting_prefixes=prefix,
                                prefix_name=f"QZA1_NSF_{port.replace('/', '_')}",
                                bgp_communities=["65441:65", "65441:129"],
                                ip_address_family=ixia_types.IpAddressFamily.IPV6,
                            ),
                        )
                    ],
                ),
            )
        ],
    )


def _traffic_item(name: str, source: str, destination: str):
    def endpoints(host):
        return [
            taac_types.TrafficEndpoint(
                name=f"{row[0]}:{row[1]}", device_group_index=0, network_group_index=0
            )
            for row in EDGE_PORTS
            if row[0] == host
        ]

    return taac_types.BasicTrafficItemConfig(
        name=name,
        src_endpoints=endpoints(source),
        dest_endpoints=endpoints(destination),
        traffic_type=ixia_types.TrafficType.IPV6,
        src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
        full_mesh=False,
        bidirectional=False,
        merge_destinations=True,
        line_rate=50,
        line_rate_type=ixia_types.RateType.PERCENT_LINE_RATE,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
        packet_headers=DSF_RDMA_PACKET_HEADERS,
        skip_default_l4_protocol=True,
        frame_size_settings=ixia_types.FrameSize(
            type=ixia_types.FrameSizeType.CUSTOM_IMIX,
            imix_weight={94: 1, 96: 18, 192: 3, 512: 1, 1200: 1, 4600: 76},
        ),
    )


def _task_step(task):
    return create_run_task_step(
        task_name=task.task_name,
        params_dict=json.loads(task.params.json_params),
        set_outer_hostname=True,
    )


def _host_services(host: str) -> list[str]:
    return (
        SERVICES
        if HOST_METADATA[host]["native"]
        else [service for service in SERVICES if service != "fboss_sw_agent"]
    )


def _on_device(check):
    return check(check_scope=hc_types.Scope.DEFAULT)


def _host_stage(host: str, checks, stage_id: str, extra_steps=None):
    return create_steps_stage(
        stage_id=stage_id,
        steps=[
            create_validation_step(
                point_in_time_checks=[_on_device(check) for check in checks],
                fail_on_failure=True,
            )
        ]
        + list(extra_steps or []),
    )(
        device_regexes=[rf"^{re.escape(host)}(?:\.tfbnw\.net)?$"],
        terminate_on_step_failure=True,
    )


def _forwarding_task(host: str):
    return create_verify_selected_forwarding_task(
        hostname=host,
        routes=[
            {
                "prefix": str(
                    ipaddress.IPv6Address(
                        int(ipaddress.IPv6Address(row[6])) + (index << 64)
                    )
                )
                + "/64",
                "next_hops": FORWARDING_NEXT_HOPS[host][row[6]],
            }
            for row in EDGE_PORTS
            for index in range(PREFIX_COUNT)
        ],
        interface_ports=INTERFACE_PORTS[host],
    )


def _rib_source(host: str, peer: str) -> str:
    if host == DUT:
        return REMOTE
    elif host == REMOTE:
        return DUT
    elif host == LOCAL_TRANSIT:
        return DUT if peer.startswith("2401:db00:e2d1:b70:") else REMOTE
    elif host == REMOTE_TRANSIT:
        return REMOTE if peer.startswith("2401:db00:e2d1:b80:") else DUT
    else:
        return (
            DUT
            if peer in ["2401:db00:e2d1:b04::1", "2401:db00:e2d1:b04::3"]
            else REMOTE
        )


def _rib_path_attributes(host: str, peer: str, origin: int, edge_peers: set[str]):
    if peer in edge_peers:
        return [origin], ["65441:65", "65441:129"]
    elif host in EDGE_HOSTS:
        return [4200000000, 4200000999, origin], ["65441:133"]
    elif host == SHARED_TRANSIT:
        return [4200000999, origin], ["65441:131"]
    elif peer.startswith("2401:db00:e2d1:b04:"):
        return [4200000000, 4200000999, origin], ["65441:132"]
    else:
        return [origin], ["65441:130"]


def _rib_task(host: str):
    # Scope each received-postpolicy audit to the complete selected NLRI universe.
    # This preserves unrelated native routes while requiring the exact source side.
    peer_prefixes = {}
    for _local, peer in TRANSIT_PEERS[host]:
        source = _rib_source(host, peer)
        peer_prefixes[_address(peer)] = _prefixes(source)
    for row in EDGE_PORTS:
        if row[0] == host:
            peer_prefixes[_address(row[3])] = [
                str(
                    ipaddress.IPv6Address(
                        int(ipaddress.IPv6Address(row[6])) + (index << 64)
                    )
                )
                + "/64"
                for index in range(PREFIX_COUNT)
            ]
    selected_prefixes = _prefixes(DUT) + _prefixes(REMOTE)
    # Scoped ST rewrite can expose the other source-side pools through parallel
    # transit peers. Require directional routes; permit only these known extras.
    # Strict FIB checks still require the preferred local/remote forwarding paths.
    allowed_extra_prefixes = {
        _address(peer): [
            prefix
            for prefix in selected_prefixes
            if prefix not in set(peer_prefixes[_address(peer)])
        ]
        for _local, peer in TRANSIT_PEERS[host]
    }
    origin_as = {
        str(ipaddress.IPv6Address(int(ipaddress.IPv6Address(row[6])) + (index << 64)))
        + "/64": row[5]
        for row in EDGE_PORTS
        for index in range(PREFIX_COUNT)
    }
    edge_peers = {_address(row[3]) for row in EDGE_PORTS if row[0] == host}
    path_expectations = {}
    for peer, prefixes in peer_prefixes.items():
        path_expectations[peer] = {}
        for prefix in prefixes:
            origin = origin_as[prefix]
            as_path, communities = _rib_path_attributes(host, peer, origin, edge_peers)
            path_expectations[peer][prefix] = {
                "as_path": as_path,
                "communities": communities,
                "next_hop": peer,
            }
    return create_verify_selected_bgp_routes_task(
        hostname=host,
        peer_prefixes=peer_prefixes,
        selected_prefixes=selected_prefixes,
        allowed_extra_prefixes=allowed_extra_prefixes,
        path_expectations=path_expectations,
        timeout_seconds=60,
    )


def _device_checks(host: str, after_restart: bool):
    services = _host_services(host)
    peers = [_address(peer) for _, peer in TRANSIT_PEERS[host]] + [
        _address(row[3]) for row in EDGE_PORTS if row[0] == host
    ]
    checks = [
        create_systemctl_active_state_check(services_json=services),
        create_bgp_session_establish_check(
            ignore_all_prefixes_except=peers,
            expected_established_sessions=len(peers),
            retry_count=12,
            retry_delay_seconds=5,
        ),
        create_port_state_check(
            additional_interfaces=[
                {"switch_name": host, "interface_name": port}
                for port in SELECTED_PORTS[host]
            ]
        ),
        create_port_speed_check(
            json_params={
                host: {
                    "interfaces": [
                        {"interface_name": port, "expected_speed": 400}
                        for port in SELECTED_PORTS[host]
                    ]
                }
            }
        ),
        create_wedge_agent_configured_check(),
        create_device_core_dumps_check(),
    ]
    if host in EDGE_HOSTS:
        checks.append(
            create_bgp_route_count_verification_check(
                json_params={
                    "peer_addresses_to_check": [
                        _address(row[3]) for row in EDGE_PORTS if row[0] == host
                    ],
                    "direction": "received",
                    "policy_type": "post_policy",
                    "expected_count": PREFIX_COUNT,
                }
            )
        )
    resource_services = (
        NATIVE_RESOURCE_SERVICES if HOST_METADATA[host]["native"] else services
    )
    for check, threshold, start_time in [
        (
            create_cpu_utilization_check(threshold=40),
            40,
            ".nsf_settled_at" if after_restart else ".test_case_start_time",
        ),
        (
            create_memory_utilization_check(threshold=MEMORY_HWM_BYTES),
            MEMORY_HWM_BYTES,
            ".test_case_start_time",
        ),
    ]:
        checks.append(
            check(
                check_params=taac_types.Params(
                    json_params=json.dumps(
                        {
                            "threshold": threshold,
                            "services": resource_services,
                            "sleep_timer": 0,
                        }
                    ),
                    jq_params={"start_time": start_time},
                )
            )
        )
    if after_restart:
        checks.extend(
            [
                create_unclean_exit_check(
                    services=services,
                    start_time_jq_var="nsf_cycle_start",
                    sleep_timer=0,
                ),
                create_service_restart_check(
                    services=services,
                    expected_restarted_services=[
                        "wedge_agent",
                        "fboss_sw_agent",
                        "fboss_wedge_agent_nvda_0",
                        "bgpd",
                    ]
                    if host == DUT
                    else [],
                    start_time_jq_var="nsf_cycle_start",
                    restart_start_time_jq_var="nsf_recovered_at"
                    if host == DUT
                    else None,
                ),
            ]
        )
    return checks


def _device_stages(after_restart: bool, prefix: str):
    return [
        _host_stage(
            host,
            _device_checks(host, after_restart),
            f"{prefix}_{host.replace('.', '_')}",
            extra_steps=[
                _task_step(
                    create_assert_process_vmhwm_task(
                        hostname=host,
                        services=_host_services(host),
                        threshold_bytes=MEMORY_HWM_BYTES,
                    )
                ),
                _task_step(_rib_task(host)),
                _task_step(_forwarding_task(host)),
            ],
        )
        for host in HOSTS
    ]


def create_rtsw_mp3n_qza1_ixia12_16_nsf_warmboot_test_config() -> taac_types.TestConfig:
    loss = create_ixia_packet_loss_check(
        thresholds=[
            hc_types.PacketLossThreshold(
                names=TRAFFIC_NAMES,
                metric=hc_types.PacketLossMetric.DURATION,
                str_value="0",
            )
        ],
        sleep_time=60,
    )
    rates = create_ixia_traffic_rate_check(
        thresholds=[
            hc_types.TrafficRateThreshold(
                names=[name], value=50, threshold_type=hc_types.ThresholdType.PERCENT
            )
            for name in TRAFFIC_NAMES
        ],
        base_bandwidth_gbps=800,
        rate_tolerance_percent=5,
    )
    pfc_thresholds = [
        hc_types.PfcWdThreshold(
            interfaces=[
                f"{host}:{port}"
                for host, ports in SELECTED_PORTS.items()
                for port in ports
            ],
            comparison=hc_types.ComparisonType.EQUAL_TO,
            deadlock_threshold=0,
            recovery_threshold=0,
        )
    ]
    pfc_baseline = create_pfc_wd_check(
        thresholds=pfc_thresholds, mode="snapshot", executor_device=DUT
    )
    pfc_check = create_pfc_wd_check(
        thresholds=pfc_thresholds,
        mode="check",
        max_detection_recovery_difference=0,
        executor_device=DUT,
    )
    queue_infos = [
        hc_types.TxQueueInfo(
            hostname=host,
            interface=port,
            cos_list=[],
            queue_desc_list=["queue2.rdma"],
            key_desc="out_bytes",
            val=1_000_000,
            comparison=hc_types.ComparisonType.GREATER_THAN,
            enforce_exclusivity=True,
        )
        for host, ports in SELECTED_PORTS.items()
        for port in ports
    ]
    baseline = create_longevity_playbook(
        playbook_name="qza1_ixia12_16_nsf_00_baseline",
        longevity_duration=60,
        traffic_items_to_start=TRAFFIC_NAMES,
        prechecks=[pfc_baseline],
        postchecks=[loss, rates, pfc_check],
        snapshot_checks=[
            create_core_dumps_snapshot_check()(check_scope=hc_types.Scope.TOPOLOGY),
            create_port_speed_snapshot_check(json_params={"endpoints": SELECTED_PORTS}),
            create_qos_dscp_tx_queue_snapshot_check(tx_queue_info_list=queue_infos),
        ],
    )
    baseline = baseline(
        stages=_device_stages(False, "baseline_ready")
        + list(baseline.stages)
        + _device_stages(False, "baseline_stable")
    )
    identity = {_address(peer): _address(local) for local, peer in TRANSIT_PEERS[DUT]}
    identity.update(
        {_address(row[3]): _address(row[4]) for row in EDGE_PORTS if row[0] == DUT}
    )
    endurance = gen_endurance_playbook(TEST_CONTINUOUS_AGENT_WARMBOOT_PLAYBOOK, 10)(
        name="qza1_ixia12_16_nsf_10_agent_warmboot",
        traffic_items_to_start=TRAFFIC_NAMES,
        prechecks=[loss, rates, pfc_baseline],
        postchecks=[loss, rates, pfc_check],
        stages=_device_stages(False, "cycle_ready")
        + [
            create_steps_stage(
                stage_id="cycle_start",
                steps=[
                    create_record_jq_timestamp_step(var_name="nsf_cycle_start"),
                    create_clear_traffic_stats_step(),
                ],
            ),
            create_steps_stage(
                stage_id="agent_restart_recovered",
                steps=[
                    create_service_interruption_step(
                        service=taac_types.Service.AGENT, device_regexes=DUT_REGEX
                    ),
                    create_service_convergence_step(
                        services=[taac_types.Service.AGENT, taac_types.Service.BGP],
                        device_regexes=DUT_REGEX,
                    ),
                    _task_step(
                        create_assert_agent_warm_boot_task(
                            hostname=DUT, hw_switch_indices=[0]
                        )
                    ),
                    create_record_jq_timestamp_step(var_name="nsf_recovered_at"),
                ],
            )(device_regexes=DUT_REGEX, terminate_on_step_failure=True),
            create_steps_stage(
                stage_id="post_recovery_soak",
                steps=[
                    create_longevity_step(duration=60),
                    create_record_jq_timestamp_step(var_name="nsf_settled_at"),
                    create_longevity_step(duration=60),
                ],
            ),
        ]
        + _device_stages(True, "cycle_stable"),
        snapshot_checks=[
            create_core_dumps_snapshot_check()(check_scope=hc_types.Scope.TOPOLOGY),
            create_port_speed_snapshot_check(json_params={"endpoints": SELECTED_PORTS}),
            create_bgp_session_snapshot_check(
                skip_flap_check=True,
                skip_uptime_check=True,
                assert_reconvergence=True,
                max_convergence_sec=60,
                convergence_service="bgpd",
                reconvergence_hosts=[DUT],
            ),
            create_bgp_session_snapshot_check(
                pre_snapshot_checkpoint_id="stage.agent_restart_recovered.end",
                expected_peer_identity=identity,
            ),
            create_bgp_session_snapshot_check(
                pre_snapshot_checkpoint_id="stage.agent_restart_recovered.end"
            )(check_scope=hc_types.Scope.TOPOLOGY),
            create_qos_dscp_tx_queue_snapshot_check(
                tx_queue_info_list=queue_infos,
                pre_snapshot_checkpoint_id="stage.agent_restart_recovered.end",
                post_snapshot_checkpoint_id="stage.post_recovery_soak.end",
            ),
        ],
    )
    return taac_types.TestConfig(
        name="RTSW_MP3N_QZA1_IXIA12_16_NSF_WARMBOOT",
        basset_pool="dne.test",
        basset_reservation_time_hr=288,
        endpoints=[
            taac_types.Endpoint(
                name=host,
                dut=host == DUT,
                ixia_needed=host in EDGE_HOSTS,
                ixia_ports=[row[1] for row in EDGE_PORTS if row[0] == host],
                direct_ixia_connections=[
                    taac_types.DirectIxiaConnection(
                        interface=row[1],
                        ixia_chassis_ip=CHASSIS[host][1],
                        ixia_port=row[2],
                    )
                    for row in EDGE_PORTS
                    if row[0] == host
                ],
            )
            for host in HOSTS
        ],
        basic_port_configs=[_port_config(row) for row in EDGE_PORTS],
        basic_traffic_item_configs=[
            _traffic_item(TRAFFIC_NAMES[0], DUT, REMOTE),
            _traffic_item(TRAFFIC_NAMES[1], REMOTE, DUT),
        ],
        setup_tasks=_setup_tasks(),
        teardown_tasks=[
            create_coop_unregister_patchers_task(
                hostnames=host,
                config_names=_config_views(host, "agent")
                + _config_views(host, "bgpcpp"),
                regex=f"^{PATCHER_NAMESPACE}",
            )
            for host in HOSTS
        ]
        + [
            create_coop_apply_patchers_task(
                hostnames=CHANGED_AGENT_HOSTS, config_name="agent"
            ),
            create_coop_apply_patchers_task(
                hostnames=CHANGED_BGP_HOSTS, config_name="bgpcpp"
            ),
            create_wait_for_agent_convergence_task(HOSTS),
        ],
        playbooks=[baseline, endurance],
    )


RTSW_MP3N_QZA1_IXIA12_16_NSF_WARMBOOT = (
    create_rtsw_mp3n_qza1_ixia12_16_nsf_warmboot_test_config()
)

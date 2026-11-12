# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.
"""Focused coverage for EBB full-scale topology selection."""

import json
import runpy
import typing as t
import unittest
from dataclasses import replace
from types import ModuleType, SimpleNamespace
from unittest import mock

from taac.abstractions.compatibility.legacy_ebb_topology import (
    IBGP_PEER_SCALE_PER_PLANE,
)
from taac.abstractions.physical_inventory import NRQEB009_ASH6
from taac.abstractions.topologies.ebb_full_scale import (
    EBB_AS_NUMBERS,
    EBB_FY26_SCALE,
    EBB_NEXT_HOPS_IXIA03,
    EBB_OPENR_INJECTED_START_IPV4S,
    EBB_OPENR_INJECTED_START_IPV4S_IXIA03,
    EBB_OPENR_INJECTED_START_IPV6S,
    EBB_OPENR_INJECTED_START_IPV6S_IXIA03,
    EBB_PARENT_NETWORKS,
    EBB_PARENT_NETWORKS_IXIA03,
    EBB_PEER_GROUPS,
    EBB_PORT_MAP_WITH_BGPMON,
    ebb_topology,
    EbbScaleProfile,
)
from taac.abstractions.topology.model import (
    BoundTopology,
    NextHopMode,
    OpenRInjectionPlan,
    OpenRMode,
)
from taac.abstractions.validation import TopologyValidationError
from taac.constants import (
    BgpPlusPlusProfile,
    TESTBED_ISOLATION_BYPASS_TAG,
)
from taac.testconfigs.routing import (
    adhoc_fibagent_qualification_traffic,
    cicd_ebb_int_tc,
)
from taac.testconfigs.routing.factories import (
    bgp_ebb_full_scale as factory,
)
from taac.test_as_a_config import types as taac_types


_C16_PLAYBOOK = "bgp_ebb_nexthop_group_count_threshold_playbook"
_BGP_MON_CANARY_BUILDERS = {
    "CICD-EBB-05": "get_bgp_ebb_ebgp_route_oscillation_playbook",
    "CICD-EBB-09": "get_bgp_ebb_multipath_group_oscillation_playbook",
    "CICD-EBB-12": "get_bgp_ebb_route_registry_runtime_update_playbook",
    "CICD-EBB-16": "get_bgp_ebb_nexthop_group_count_threshold_playbook",
}
_EBB_PLAYBOOK_BUILDERS = (
    "get_bgp_ebb_attribute_churn_playbook",
    "get_bgp_ebb_route_storm_playbook",
    "get_bgp_ebb_route_registry_runtime_update_playbook",
    "get_bgp_ebb_multipath_group_oscillation_playbook",
    "get_bgp_ebb_igp_pnh_metric_oscillation_playbook",
    "get_bgp_ebb_fauu_drain_undrain_playbook",
    "get_bgp_ebb_plane_drain_undrain_playbook",
    "get_bgp_ebb_longevity_playbook",
    "get_bgp_ebb_daemon_restart_playbook",
    "get_bgp_ebb_cold_start_playbook",
    "get_bgp_ebb_ebgp_session_oscillation_playbook",
    "get_bgp_ebb_ebgp_route_oscillation_playbook",
    "get_bgp_ebb_ibgp_plane_session_oscillation_playbook",
    "get_bgp_ebb_ibgp_route_oscillation_playbook",
    "get_bgp_ebb_igp_unresolvable_pnh_playbook",
    "get_bgp_ebb_nexthop_group_count_threshold_playbook",
)
_PNH_RANGE_BUILDERS = (
    "get_bgp_ebb_attribute_churn_playbook",
    "get_bgp_ebb_route_storm_playbook",
    "get_bgp_ebb_route_registry_runtime_update_playbook",
    "get_bgp_ebb_multipath_group_oscillation_playbook",
    "get_bgp_ebb_daemon_restart_playbook",
    "get_bgp_ebb_cold_start_playbook",
    "get_bgp_ebb_ebgp_session_oscillation_playbook",
    "get_bgp_ebb_ebgp_route_oscillation_playbook",
    "get_bgp_ebb_ibgp_plane_session_oscillation_playbook",
    "get_bgp_ebb_ibgp_route_oscillation_playbook",
)
_PNH_START_LIST_BUILDERS = ("get_bgp_ebb_igp_pnh_metric_oscillation_playbook",)


def _inventory() -> mock.MagicMock:
    inventory = mock.MagicMock()
    inventory.device_name = "bag012.ash6"
    inventory.basset_pool = "dne.test"
    inventory.ixia_ports = []
    return inventory


def _compiled_topology() -> mock.MagicMock:
    topology = mock.MagicMock()
    topology.bind_to_inventory.return_value.compile.return_value = SimpleNamespace(
        endpoints=[],
        host_os_type_map={},
        setup_tasks=[
            taac_types.Task(
                task_name="interface_ip_configuration",
                ixia_needed=True,
                params=taac_types.Params(json_params="{}"),
            ),
            taac_types.Task(
                task_name="arista_daemon_control",
                ixia_needed=True,
                params=taac_types.Params(
                    json_params=json.dumps(
                        {"daemon_name": "Bgpcpp", "action": "enable"}
                    )
                ),
            ),
        ],
        teardown_tasks=[],
        basic_port_configs=[
            taac_types.BasicPortConfig(
                device_group_configs=[
                    taac_types.DeviceGroupConfig(
                        device_group_index=0,
                        device_group_name="DEVICE_GROUP_IPV6_EBGP",
                    )
                ]
            )
        ],
        basic_traffic_item_configs=[],
    )
    return topology


def _bound_shape(prefix_count: int) -> BoundTopology:
    topology = factory.ebb_topology(
        scale=EBB_FY26_SCALE,
        openr_mode=factory.OpenRMode.STANDALONE,
        ebgp_prefix_count=prefix_count,
    )
    return t.cast(
        BoundTopology,
        SimpleNamespace(
            device_groups=[
                SimpleNamespace(
                    role=group.role,
                    afi=group.afi,
                    peer_count=group.peer_count,
                    prefix_advertisements=[
                        SimpleNamespace(spec=advertisement)
                        for advertisement in group.prefix_advertisements
                    ],
                )
                for group in topology.device_groups
            ]
        ),
    )


# The factory resolves one injection plan from the bound topology and threads
# it into the PNH checks and Open/R steps, so a fake bound topology has to hand
# back a real plan.
_FY26_INJECTION = OpenRInjectionPlan(
    start_ipv4s=tuple(EBB_OPENR_INJECTED_START_IPV4S),
    start_ipv6s=tuple(EBB_OPENR_INJECTED_START_IPV6S),
    count=EBB_FY26_SCALE.he_sites_per_range,
    step=EBB_FY26_SCALE.next_hop_step,
)


class BgpEbbFullScaleFactoryTest(unittest.TestCase):
    _AUTOMATION = factory._EbbAutomationContract(
        non_monitor_established_session_count=1272,
        internal_peer_group_names_by_afi={"ipv4": "IBGP-V4", "ipv6": "IBGP-V6"},
        ebgp_peer_group_names_by_afi={"ipv4": "EBGP-V4", "ipv6": "EBGP-V6"},
        ebgp_peer_item_names_by_afi={"ipv4": "PEER-V4", "ipv6": "PEER-V6"},
        ebgp_peer_counts_by_afi={"ipv4": 140, "ipv6": 140},
        ebgp_route_item_names_by_afi={
            "ipv4": "ROUTE.POOL[V4]",
            "ipv6": "ROUTE+POOL(V6)",
        },
    )

    def test_nrq_lifecycle_configs_inherit_routing_qual_pool(self) -> None:
        nrq_configs = [
            getattr(cicd_ebb_int_tc, name)
            for name in cicd_ebb_int_tc.__all__
            if name.startswith("NRQEB")
        ]

        self.assertTrue(nrq_configs)
        for config in nrq_configs:
            with self.subTest(config=config.name):
                self.assertEqual("routing.qual", config.basset_pool)

    def test_openr_mode_owns_testbed_isolation_policy(self) -> None:
        for profile, expected_bypass in (
            (BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R, True),
            (BgpPlusPlusProfile.BGP_PLUS_PLUS_WITHOUT_OPEN_R, False),
        ):
            with self.subTest(profile=profile):
                topology = _compiled_topology()
                with mock.patch.object(factory, "ebb_topology", return_value=topology):
                    config = factory.create_bgp_ebb_full_scale_test_config(
                        _inventory(),
                        name="ISOLATION_POLICY_TEST",
                        profile=profile,
                        setup_only=True,
                    )

                self.assertEqual(
                    expected_bypass,
                    TESTBED_ISOLATION_BYPASS_TAG in (config.tags or ()),
                )

    def test_all_ebb_playbooks_use_bound_bgp_mon_network(self) -> None:
        bgp_mon_parent_network = "2401:db00:e50d:44:a"
        inventory = _inventory()
        inventory.ixia_ports = [("Ethernet1",), ("Ethernet2",)]
        bound = t.cast(
            BoundTopology,
            SimpleNamespace(
                device_config=SimpleNamespace(
                    fibagent_bgp_nhg_watermark_high=1000,
                    fibagent_bgp_nhg_watermark_low=1000,
                    openr_mode=OpenRMode.STANDALONE,
                ),
                parent_networks={"bgpmon_v6": bgp_mon_parent_network},
                resolve_openr_injection_plan=lambda: _FY26_INJECTION,
            ),
        )
        builders = {
            name: mock.Mock(return_value=taac_types.Playbook(name=name))
            for name in _EBB_PLAYBOOK_BUILDERS
        }
        with (
            mock.patch.multiple(factory, **builders),
            mock.patch.object(
                factory,
                "_ebb_route_count_histogram_by_afi",
                return_value={"ipv4": {}, "ipv6": {}},
            ),
            mock.patch.object(
                factory,
                "_ebb_peer_prefix_exclusion_blocks_by_pool",
                return_value={
                    "ROUTE.POOL[V4]": [],
                    "ROUTE+POOL(V6)": [],
                },
            ),
            mock.patch.object(
                factory,
                "_ebb_automation_contract",
                return_value=self._AUTOMATION,
            ),
            mock.patch.object(factory, "_nhg_storm_ixia_items", return_value={}),
            mock.patch.object(
                factory, "ebb_ibgp_route_next_hop_starts", return_value={}
            ),
            mock.patch.object(factory, "build_expected_peer_identity", return_value={}),
            mock.patch.object(factory, "_openr_owner_kv_link", return_value={}),
            mock.patch.object(factory, "_openr_helper_kv_link", return_value={}),
        ):
            playbooks = factory._get_bgp_ebb_full_scale_playbooks(
                inventory,
                profile=factory.DEFAULT_PROFILE,
                bound=bound,
                ebgp_prefix_count=850,
                selected_tc7_playbooks=set(),
            )

        self.assertEqual(len(_EBB_PLAYBOOK_BUILDERS), len(playbooks))
        for name, builder in builders.items():
            with self.subTest(builder=name):
                self.assertEqual(
                    bgp_mon_parent_network,
                    builder.call_args.kwargs["bgp_mon_parent_network"],
                )

    def test_canary_cases_use_paired_canonical_bgp_mon_network(self) -> None:
        inventory = _inventory()
        inventory.ixia_ports = [("Ethernet1",), ("Ethernet2",)]
        canonical_pairs = (
            (
                "BAG/IXIA11",
                EBB_PARENT_NETWORKS,
                "2401:db00:e50d:22:a",
                "2401:db00:e50d:44:a",
                EBB_OPENR_INJECTED_START_IPV4S,
                EBB_OPENR_INJECTED_START_IPV6S,
            ),
            (
                "NRQ/IXIA03",
                EBB_PARENT_NETWORKS_IXIA03,
                "2401:db00:e50d:44:a",
                "2401:db00:e50d:22:a",
                EBB_OPENR_INJECTED_START_IPV4S_IXIA03,
                EBB_OPENR_INJECTED_START_IPV6S_IXIA03,
            ),
        )

        for (
            profile,
            parent_networks,
            expected,
            forbidden,
            start_ipv4s,
            start_ipv6s,
        ) in canonical_pairs:
            with self.subTest(profile=profile):
                self.assertEqual(expected, parent_networks["bgpmon_v6"])
                self.assertNotEqual(forbidden, parent_networks["bgpmon_v6"])
                bound = t.cast(
                    BoundTopology,
                    SimpleNamespace(
                        device_config=SimpleNamespace(
                            fibagent_bgp_nhg_watermark_high=1000,
                            fibagent_bgp_nhg_watermark_low=1000,
                            openr_mode=OpenRMode.STANDALONE,
                        ),
                        parent_networks=parent_networks,
                        resolve_openr_injection_plan=lambda plan=OpenRInjectionPlan(
                            start_ipv4s=tuple(start_ipv4s),
                            start_ipv6s=tuple(start_ipv6s),
                            count=EBB_FY26_SCALE.he_sites_per_range,
                            step=EBB_FY26_SCALE.next_hop_step,
                        ): plan,
                    ),
                )
                builders = {
                    name: mock.Mock(return_value=taac_types.Playbook(name=name))
                    for name in _EBB_PLAYBOOK_BUILDERS
                }
                with (
                    mock.patch.multiple(factory, **builders),
                    mock.patch.object(
                        factory,
                        "_ebb_route_count_histogram_by_afi",
                        return_value={"ipv4": {}, "ipv6": {}},
                    ),
                    mock.patch.object(
                        factory,
                        "_ebb_peer_prefix_exclusion_blocks_by_pool",
                        return_value={
                            "ROUTE.POOL[V4]": [],
                            "ROUTE+POOL(V6)": [],
                        },
                    ),
                    mock.patch.object(
                        factory,
                        "_ebb_automation_contract",
                        return_value=self._AUTOMATION,
                    ),
                    mock.patch.object(
                        factory, "_nhg_storm_ixia_items", return_value={}
                    ),
                    mock.patch.object(
                        factory, "ebb_ibgp_route_next_hop_starts", return_value={}
                    ),
                    mock.patch.object(
                        factory, "build_expected_peer_identity", return_value={}
                    ),
                    mock.patch.object(factory, "_openr_owner_kv_link", return_value={}),
                    mock.patch.object(
                        factory, "_openr_helper_kv_link", return_value={}
                    ),
                ):
                    factory._get_bgp_ebb_full_scale_playbooks(
                        inventory,
                        profile=factory.DEFAULT_PROFILE,
                        bound=bound,
                        ebgp_prefix_count=850,
                        selected_tc7_playbooks=set(),
                    )

                for catalog_id, builder_name in _BGP_MON_CANARY_BUILDERS.items():
                    with self.subTest(profile=profile, catalog_id=catalog_id):
                        configured = builders[builder_name].call_args.kwargs[
                            "bgp_mon_parent_network"
                        ]
                        self.assertEqual(expected, configured)
                        self.assertNotEqual(forbidden, configured)

                for builder_name in _PNH_RANGE_BUILDERS:
                    with self.subTest(profile=profile, builder=builder_name):
                        kwargs = builders[builder_name].call_args.kwargs
                        self.assertEqual(start_ipv4s, kwargs["ibgp_pnh_start_ipv4s"])
                        self.assertEqual(start_ipv6s, kwargs["ibgp_pnh_start_ipv6s"])

                for builder_name in _PNH_START_LIST_BUILDERS:
                    with self.subTest(profile=profile, builder=builder_name):
                        kwargs = builders[builder_name].call_args.kwargs
                        self.assertEqual(list(start_ipv4s), kwargs["start_ipv4s"])
                        self.assertEqual(list(start_ipv6s), kwargs["start_ipv6s"])

                unresolvable_kwargs = builders[
                    "get_bgp_ebb_igp_unresolvable_pnh_playbook"
                ].call_args.kwargs
                self.assertEqual([start_ipv4s[0]], unresolvable_kwargs["start_ipv4s"])
                self.assertEqual([start_ipv6s[0]], unresolvable_kwargs["start_ipv6s"])
                self.assertEqual(
                    list(start_ipv4s),
                    unresolvable_kwargs["restore_start_ipv4s"],
                )
                self.assertEqual(
                    list(start_ipv6s),
                    unresolvable_kwargs["restore_start_ipv6s"],
                )

    def test_full_scale_rejects_missing_bgp_mon_network(self) -> None:
        inventory = _inventory()
        inventory.ixia_ports = [("Ethernet1",), ("Ethernet2",)]
        bound = t.cast(
            BoundTopology,
            SimpleNamespace(
                device_config=SimpleNamespace(
                    fibagent_bgp_nhg_watermark_high=1000,
                    fibagent_bgp_nhg_watermark_low=1000,
                    openr_mode=OpenRMode.STANDALONE,
                ),
                parent_networks={},
                resolve_openr_injection_plan=lambda: _FY26_INJECTION,
            ),
        )

        with (
            mock.patch.object(
                factory,
                "_ebb_automation_contract",
                return_value=self._AUTOMATION,
            ),
            self.assertRaisesRegex(ValueError, "missing required bgpmon_v6"),
        ):
            factory._get_bgp_ebb_full_scale_playbooks(
                inventory,
                profile=factory.DEFAULT_PROFILE,
                bound=bound,
                ebgp_prefix_count=850,
                selected_tc7_playbooks=set(),
            )

    def test_canonical_route_contract_is_derived_per_afi(self) -> None:
        bound = _bound_shape(850)

        self.assertEqual(
            {
                "ipv4": {720: 50, 750: 90},
                "ipv6": {720: 50, 750: 90},
            },
            factory._ebb_route_count_histogram_by_afi(bound, 750),
        )
        self.assertEqual(
            {
                "ipv4": {816: 50, 850: 90},
                "ipv6": {816: 50, 850: 90},
            },
            factory._ebb_route_count_histogram_by_afi(bound, 850),
        )

    def test_route_histogram_unions_overlapping_exclusion_blocks(self) -> None:
        bound = _bound_shape(850)
        groups: list[t.Any] = list(bound.device_groups)
        first_uplink_index = next(
            index for index, group in enumerate(groups) if group.role == "uplink"
        )
        first_uplink = groups[first_uplink_index]
        advertisement = first_uplink.prefix_advertisements[0].spec
        groups[first_uplink_index] = SimpleNamespace(
            role=first_uplink.role,
            afi=first_uplink.afi,
            peer_count=first_uplink.peer_count,
            prefix_advertisements=[
                SimpleNamespace(
                    spec=SimpleNamespace(
                        allocation=advertisement.allocation,
                        peer_prefix_activation=SimpleNamespace(
                            exclusion_blocks=(
                                SimpleNamespace(
                                    prefix_start_index=10,
                                    prefix_count=10,
                                    peer_indices=(0,),
                                ),
                                SimpleNamespace(
                                    prefix_start_index=15,
                                    prefix_count=10,
                                    peer_indices=(0,),
                                ),
                            )
                        ),
                    )
                )
            ],
        )
        overlapping_bound = t.cast(BoundTopology, SimpleNamespace(device_groups=groups))

        histogram = factory._ebb_route_count_histogram_by_afi(overlapping_bound, 850)

        afi = "ipv4" if first_uplink.afi == "v4" else "ipv6"
        self.assertEqual({835: 1, 850: 139}, histogram[afi])

    def test_route_histogram_rejects_out_of_range_exclusion_peer(self) -> None:
        bound = _bound_shape(850)
        groups: list[t.Any] = list(bound.device_groups)
        first_uplink_index = next(
            index for index, group in enumerate(groups) if group.role == "uplink"
        )
        first_uplink = groups[first_uplink_index]
        advertisement = first_uplink.prefix_advertisements[0].spec
        groups[first_uplink_index] = SimpleNamespace(
            role=first_uplink.role,
            afi=first_uplink.afi,
            name="uplink-with-invalid-exclusion",
            peer_count=first_uplink.peer_count,
            prefix_advertisements=[
                SimpleNamespace(
                    spec=SimpleNamespace(
                        allocation=advertisement.allocation,
                        peer_prefix_activation=SimpleNamespace(
                            exclusion_blocks=(
                                SimpleNamespace(
                                    prefix_start_index=750,
                                    prefix_count=4,
                                    peer_indices=(first_uplink.peer_count,),
                                ),
                            )
                        ),
                    )
                )
            ],
        )
        invalid_bound = t.cast(BoundTopology, SimpleNamespace(device_groups=groups))

        with self.assertRaisesRegex(ValueError, "indices outside"):
            factory._ebb_route_count_histogram_by_afi(invalid_bound, 850)

    def test_canonical_exclusion_blocks_are_keyed_by_prefix_pool(self) -> None:
        blocks_by_pool = factory._ebb_peer_prefix_exclusion_blocks_by_pool(
            _bound_shape(850)
        )

        self.assertEqual(
            {"PREFIX_POOL_IPV4_EBGP", "PREFIX_POOL_IPV6_EBGP"},
            set(blocks_by_pool),
        )
        for blocks in blocks_by_pool.values():
            self.assertEqual(50, len(blocks))
            self.assertEqual(
                {
                    "prefix_start_index": 750,
                    "prefix_count": 4,
                    "peer_indices": [90, 91],
                },
                blocks[25],
            )

    def test_exclusion_blocks_reject_duplicate_prefix_pool_names(self) -> None:
        bound = _bound_shape(850)
        uplink_groups = [
            group for group in bound.device_groups if group.role == "uplink"
        ]
        first_spec = uplink_groups[0].prefix_advertisements[0].spec
        second_spec = uplink_groups[1].prefix_advertisements[0].spec
        duplicate_bound = t.cast(
            BoundTopology,
            SimpleNamespace(
                device_groups=[
                    SimpleNamespace(
                        role="uplink",
                        prefix_advertisements=[SimpleNamespace(spec=first_spec)],
                    ),
                    SimpleNamespace(
                        role="uplink",
                        prefix_advertisements=[
                            SimpleNamespace(
                                spec=SimpleNamespace(
                                    legacy_ixia_name=first_spec.legacy_ixia_name,
                                    peer_prefix_activation=(
                                        second_spec.peer_prefix_activation
                                    ),
                                )
                            )
                        ],
                    ),
                ]
            ),
        )

        with self.assertRaisesRegex(ValueError, "duplicate eBGP IXIA prefix-pool name"):
            factory._ebb_peer_prefix_exclusion_blocks_by_pool(duplicate_bound)

    def test_ebb12_oracle_keys_must_match_bound_automation_contract(self) -> None:
        histograms = {
            "ipv4": {720: 50, 750: 90},
            "ipv6": {720: 50, 750: 90},
        }
        blocks = {
            "ROUTE.POOL[V4]": [],
            "ROUTE+POOL(V6)": [],
        }
        factory._validate_ebb12_automation_oracles(
            self._AUTOMATION,
            histograms,
            histograms,
            blocks,
        )

        with self.assertRaisesRegex(ValueError, "route-count AFIs"):
            factory._validate_ebb12_automation_oracles(
                self._AUTOMATION,
                {"ipv4": histograms["ipv4"]},
                histograms,
                blocks,
            )
        with self.assertRaisesRegex(ValueError, "exclusion-block pools"):
            factory._validate_ebb12_automation_oracles(
                self._AUTOMATION,
                histograms,
                histograms,
                {"WRONG": []},
            )

    def test_setup_only_compiles_canonical_topology_without_playbooks(self) -> None:
        topology = _compiled_topology()
        with (
            mock.patch.object(
                factory, "ebb_topology", return_value=topology
            ) as topology_builder,
            mock.patch.object(
                factory, "_get_bgp_ebb_full_scale_playbooks"
            ) as playbook_builder,
        ):
            config = factory.create_bgp_ebb_full_scale_test_config(
                _inventory(),
                name="BAG012_DIVERSE_SETUP_ONLY",
                setup_only=True,
            )

        self.assertEqual([], list(config.playbooks))
        topology_builder.assert_called_once()
        playbook_builder.assert_not_called()
        self.assertEqual(750, topology_builder.call_args.kwargs["ebgp_prefix_count"])
        self.assertFalse(topology_builder.call_args.kwargs["route_storm_shards"])
        topology.bind_to_inventory.assert_called_once()

    def test_setup_only_rejects_any_playbook_selector(self) -> None:
        for selection in ([], [_C16_PLAYBOOK]):
            with self.subTest(selection=selection):
                with self.assertRaisesRegex(
                    ValueError, "setup_only requires playbooks_selected=None"
                ):
                    factory.create_bgp_ebb_full_scale_test_config(
                        _inventory(),
                        name="INVALID_SETUP_ONLY",
                        playbooks_selected=selection,
                        setup_only=True,
                    )

    def test_c16_uses_canonical_diverse_topology(self) -> None:
        topology = _compiled_topology()
        playbook = taac_types.Playbook(name=_C16_PLAYBOOK)
        with (
            mock.patch.object(
                factory, "ebb_topology", return_value=topology
            ) as topology_builder,
            mock.patch.object(
                factory,
                "_get_bgp_ebb_full_scale_playbooks",
                return_value=[playbook],
            ) as playbook_builder,
        ):
            config = factory.create_bgp_ebb_full_scale_test_config(
                _inventory(),
                name="BAG012_DIVERSE_C16",
                playbooks_selected=[_C16_PLAYBOOK],
            )

        self.assertEqual([_C16_PLAYBOOK], [item.name for item in config.playbooks])
        topology_builder.assert_called_once()
        playbook_builder.assert_called_once()
        self.assertFalse(topology_builder.call_args.kwargs["route_storm_shards"])

    def test_runtime_update_uses_canonical_850_prefix_inventory(self) -> None:
        topology = _compiled_topology()
        playbook_name = "bgp_ebb_route_registry_runtime_update_playbook"
        playbook = taac_types.Playbook(name=playbook_name)
        with (
            mock.patch.object(
                factory, "ebb_topology", return_value=topology
            ) as topology_builder,
            mock.patch.object(
                factory,
                "_get_bgp_ebb_full_scale_playbooks",
                return_value=[playbook],
            ),
        ):
            config = factory.create_bgp_ebb_full_scale_test_config(
                _inventory(),
                name="BAG010_RUNTIME_UPDATE",
                playbooks_selected=[playbook_name],
            )

        self.assertEqual([playbook_name], [item.name for item in config.playbooks])
        self.assertEqual(850, topology_builder.call_args.kwargs["ebgp_prefix_count"])


class StuckIxiaSessionRecoveryTest(unittest.TestCase):
    @staticmethod
    def _last_custom_step_name(playbook: taac_types.Playbook) -> str | None:
        step_params = (playbook.setup_steps or [])[-1].step_params
        if step_params is None:
            return None
        return json.loads(step_params.json_params or "{}").get("custom_step_name")

    def test_active_peer_cases_end_setup_with_session_recovery(self) -> None:
        """A stuck IXIA peer held back End-of-RIB and failed convergence on
        nrqeb006, so each case that starts with peers up must recover them
        after its own setup."""
        for config in (
            cicd_ebb_int_tc.NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_UG,
            cicd_ebb_int_tc.NRQEB009_STAGE1_FULL_SCALE_TEST_CONFIG_UG,
        ):
            for playbook in config.playbooks or []:
                if playbook.name == "bgp_ebb_cold_start_playbook":
                    continue
                with self.subTest(config=config.name, playbook=playbook.name):
                    step_params = (playbook.setup_steps or [])[-1].step_params
                    assert step_params is not None
                    params = json.loads(step_params.json_params or "{}")
                    self.assertEqual(
                        "bgp_ixia_session_recovery", params["custom_step_name"]
                    )
                    self.assertEqual("^BGP_PEER_", params["ixia_bgp_peer_regex"])

    def test_cold_start_skips_session_recovery(self) -> None:
        """Cold start disables every IXIA device group in setup, so requiring
        established peers there failed the case before it ran."""
        cold_start = next(
            playbook
            for playbook in cicd_ebb_int_tc.NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_UG.playbooks
            or []
            if playbook.name == "bgp_ebb_cold_start_playbook"
        )
        self.assertNotEqual(
            "bgp_ixia_session_recovery", self._last_custom_step_name(cold_start)
        )


def _json_params(params: taac_types.Params | None) -> dict[str, t.Any]:
    return json.loads((params.json_params if params else None) or "{}")


def _is_gateway_gate(params: taac_types.Params | None) -> bool:
    return (
        _json_params(params).get("api_name") == "refresh_and_verify_gateway_resolution"
    )


def _gate_device_group_names(params: taac_types.Params | None) -> list[str]:
    return json.loads(_json_params(params)["args_json"])["device_group_names"]


def _enabled_device_groups(
    config: taac_types.TestConfig,
) -> list[taac_types.DeviceGroupConfig]:
    return [
        device_group
        for port_config in config.basic_port_configs or []
        for device_group in port_config.device_group_configs or []
        if device_group.enable
    ]


def _enabled_device_group_names(config: taac_types.TestConfig) -> list[str]:
    return [
        device_group.device_group_name or ""
        for device_group in _enabled_device_groups(config)
    ]


def _bgp_peer_names(device_group: taac_types.DeviceGroupConfig) -> list[str]:
    return [
        bgp_config.bgp_peer_name or ""
        for bgp_config in (device_group.v4_bgp_config, device_group.v6_bgp_config)
        if bgp_config is not None
    ]


_COLD_START_PLAYBOOK = "bgp_ebb_cold_start_playbook"

# Every registered TestConfig the gateway gates change. The golden manifest
# skips NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_UG.
_GATED_FULL_SCALE_CONFIGS: tuple[tuple[ModuleType, str], ...] = (
    (cicd_ebb_int_tc, "NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_NO_UG"),
    (cicd_ebb_int_tc, "NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_UG"),
    (cicd_ebb_int_tc, "NRQEB007_STAGE1_FULL_SCALE_TEST_CONFIG_NO_UG"),
    (cicd_ebb_int_tc, "NRQEB007_STAGE1_FULL_SCALE_TEST_CONFIG_UG"),
    (cicd_ebb_int_tc, "NRQEB008_STAGE1_FULL_SCALE_TEST_CONFIG_NO_UG"),
    (cicd_ebb_int_tc, "NRQEB008_STAGE1_FULL_SCALE_TEST_CONFIG_UG"),
    (cicd_ebb_int_tc, "NRQEB009_STAGE1_FULL_SCALE_TEST_CONFIG_NO_UG"),
    (cicd_ebb_int_tc, "NRQEB009_STAGE1_FULL_SCALE_TEST_CONFIG_UG"),
    (
        adhoc_fibagent_qualification_traffic,
        "NRQEB009_EBB16_FIBAGENT_QUALIFICATION_TRAFFIC_UG_ADHOC",
    ),
)


def _gated_full_scale_configs() -> dict[str, taac_types.TestConfig]:
    return {name: getattr(module, name) for module, name in _GATED_FULL_SCALE_CONFIGS}


def _gateless_namespace(module: ModuleType) -> dict[str, t.Any]:
    """Re-run `module` with no device group named for either gateway gate.

    `runpy` builds the configs in a fresh namespace and leaves `sys.modules`
    untouched.
    """
    with mock.patch.object(
        factory, "_enabled_ixia_device_group_names", return_value=[]
    ):
        return runpy.run_module(module.__name__)


def _without_gateway_gates(config: taac_types.TestConfig) -> taac_types.TestConfig:
    return config(
        setup_tasks=[
            task
            for task in config.setup_tasks or []
            if not _is_gateway_gate(task.params)
        ],
        playbooks=[
            playbook
            if playbook.stages is None
            else playbook(
                stages=[
                    stage(
                        steps=[
                            step
                            for step in stage.steps
                            if not _is_gateway_gate(step.step_params)
                        ]
                    )
                    for stage in playbook.stages
                ]
            )
            for playbook in config.playbooks or []
        ],
    )


class GatewayResolutionGateTest(unittest.TestCase):
    """The setup NS precedes the DUT interface IP configuration, and cold start
    re-enables every IXIA device group, so full-scale setup and the cold-start
    enable must each re-resolve every IXIA gateway before BGP needs it."""

    def test_setup_without_ixia_device_groups_adds_no_gate(self) -> None:
        topology = _compiled_topology()
        compiled = topology.bind_to_inventory.return_value.compile.return_value
        compiled.basic_port_configs = []
        with mock.patch.object(factory, "ebb_topology", return_value=topology):
            config = factory.create_bgp_ebb_full_scale_test_config(
                _inventory(), name="NO_IXIA_DEVICE_GROUPS", setup_only=True
            )

        self.assertEqual(
            ["interface_ip_configuration", "arista_daemon_control"],
            [task.task_name for task in config.setup_tasks or []],
        )

    def test_ixia_device_groups_without_gate_anchors_fail_construction(self) -> None:
        topology = _compiled_topology()
        compiled = topology.bind_to_inventory.return_value.compile.return_value
        compiled.setup_tasks = []
        with (
            mock.patch.object(factory, "ebb_topology", return_value=topology),
            self.assertRaisesRegex(ValueError, "interface_ip_configuration"),
        ):
            factory.create_bgp_ebb_full_scale_test_config(
                _inventory(), name="MISSING_GATE_ANCHORS", setup_only=True
            )

    def test_gate_names_skip_disabled_device_groups(self) -> None:
        port_config = taac_types.BasicPortConfig(
            endpoint="bag012.ash6:Ethernet3/35/1",
            device_group_configs=[
                taac_types.DeviceGroupConfig(
                    device_group_index=0, device_group_name="DEVICE_GROUP_IPV6_EBGP"
                ),
                taac_types.DeviceGroupConfig(
                    device_group_index=1,
                    device_group_name="DEVICE_GROUP_IPV4_EBGP",
                    enable=False,
                ),
                taac_types.DeviceGroupConfig(device_group_index=2, enable=False),
            ],
        )

        self.assertEqual(
            ["DEVICE_GROUP_IPV6_EBGP"],
            factory._enabled_ixia_device_group_names([port_config]),
        )

    def test_unnamed_enabled_device_group_fails_construction(self) -> None:
        port_config = taac_types.BasicPortConfig(
            endpoint="bag012.ash6:Ethernet3/35/1",
            device_group_configs=[taac_types.DeviceGroupConfig(device_group_index=3)],
        )

        with self.assertRaisesRegex(ValueError, "device group 3 on .* has no name"):
            factory._enabled_ixia_device_group_names([port_config])

    def test_setup_gates_first_bgpcpp_enable_on_every_ixia_gateway(self) -> None:
        for name, config in _gated_full_scale_configs().items():
            with self.subTest(config=name):
                tasks = list(config.setup_tasks or [])
                gates = [
                    index
                    for index, task in enumerate(tasks)
                    if task.task_name == "invoke_ixia_api"
                    and _is_gateway_gate(task.params)
                ]
                self.assertEqual(1, len(gates))
                last_interface_ip = max(
                    index
                    for index, task in enumerate(tasks)
                    if task.task_name == "interface_ip_configuration"
                    and task.ixia_needed
                )
                first_bgpcpp_enable = next(
                    index
                    for index in range(last_interface_ip + 1, len(tasks))
                    if tasks[index].task_name == "arista_daemon_control"
                    and _json_params(tasks[index].params).get("daemon_name") == "Bgpcpp"
                    and _json_params(tasks[index].params).get("action") == "enable"
                )
                self.assertEqual(first_bgpcpp_enable - 1, gates[0])
                self.assertLess(last_interface_ip, gates[0])
                names = _gate_device_group_names(tasks[gates[0]].params)
                self.assertEqual(_enabled_device_group_names(config), names)
                self.assertTrue(
                    {
                        "DEVICE_GROUP_IPV6_EBGP",
                        "DEVICE_GROUP_IPV4_EBGP",
                        "DEVICE_GROUP_BGP_MON",
                    }
                    <= set(names)
                )
                self.assertEqual(len(names), len(set(names)))
                for device_group in _enabled_device_groups(config):
                    self.assertTrue(
                        any(
                            stack is not None and stack.gateway_starting_ip
                            for stack in (
                                device_group.v4_addresses_config,
                                device_group.v6_addresses_config,
                            )
                        ),
                        device_group.device_group_name,
                    )

    def test_session_recovery_already_requires_every_gated_device_group(
        self,
    ) -> None:
        """Every case but cold start ends setup by requiring each `^BGP_PEER_`
        IXIA session, so no gated device group is one a case leaves unused."""
        for name, config in _gated_full_scale_configs().items():
            with self.subTest(config=name):
                for device_group in _enabled_device_groups(config):
                    peer_names = _bgp_peer_names(device_group)
                    self.assertTrue(peer_names, device_group.device_group_name)
                    for peer_name in peer_names:
                        self.assertRegex(peer_name, "^BGP_PEER_")
                active_peer_cases = [
                    playbook
                    for playbook in config.playbooks or []
                    if playbook.name != _COLD_START_PLAYBOOK
                ]
                self.assertTrue(active_peer_cases)
                for playbook in active_peer_cases:
                    params = _json_params((playbook.setup_steps or [])[-1].step_params)
                    self.assertEqual(
                        "bgp_ixia_session_recovery",
                        params.get("custom_step_name"),
                        playbook.name,
                    )
                    self.assertEqual(
                        "^BGP_PEER_", params.get("ixia_bgp_peer_regex"), playbook.name
                    )

    def test_cold_start_gates_convergence_on_every_ixia_gateway(self) -> None:
        cold_start_configs = set()
        for name, config in _gated_full_scale_configs().items():
            for playbook in config.playbooks or []:
                steps = [
                    step for stage in playbook.stages or [] for step in stage.steps
                ]
                gates = [
                    index
                    for index, step in enumerate(steps)
                    if _is_gateway_gate(step.step_params)
                ]
                with self.subTest(config=name, playbook=playbook.name):
                    if playbook.name != _COLD_START_PLAYBOOK:
                        self.assertEqual([], gates)
                        continue
                    cold_start_configs.add(name)
                    self.assertEqual(1, len(gates))
                    self.assertEqual(
                        "toggle_device_groups",
                        _json_params(steps[gates[0] - 1].step_params).get("api_name"),
                    )
                    self.assertEqual(
                        "test_bgp_thread_cpu_monitor_eos_bgp_plus_plus",
                        _json_params(steps[gates[0] + 1].step_params).get(
                            "custom_step_name"
                        ),
                    )
                    # The cold-start verdict excludes auxiliary observation peers.
                    self.assertEqual(
                        [
                            device_group_name
                            for device_group_name in _enabled_device_group_names(config)
                            if device_group_name != "DEVICE_GROUP_BGP_MON"
                        ],
                        _gate_device_group_names(steps[gates[0]].step_params),
                    )
        self.assertEqual(
            {
                "NRQEB006_STAGE1_FULL_SCALE_TEST_CONFIG_UG",
                "NRQEB008_STAGE1_FULL_SCALE_TEST_CONFIG_NO_UG",
            },
            cold_start_configs,
        )


class GatewayGateScopeTest(unittest.TestCase):
    """Each gated config must differ from its gate-free build only by the
    gateway gates."""

    gated: dict[str, taac_types.TestConfig]
    gateless: dict[str, taac_types.TestConfig]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        modules = {module.__name__: module for module, _ in _GATED_FULL_SCALE_CONFIGS}
        namespaces = {
            module_name: _gateless_namespace(module)
            for module_name, module in modules.items()
        }
        cls.gated = _gated_full_scale_configs()
        cls.gateless = {
            name: namespaces[module.__name__][name]
            for module, name in _GATED_FULL_SCALE_CONFIGS
        }

    def test_gates_are_the_only_change(self) -> None:
        for name, config in self.gated.items():
            with self.subTest(config=name):
                self.assertNotEqual(self.gateless[name], config)
                self.assertEqual(self.gateless[name], _without_gateway_gates(config))


# The state D129805999 validated on NRQEB008: an 80-node FY27-era injection
# over the unchanged 62-peer FY26 fleet. It keeps 18 rows of injected
# headroom no peer advertises, which is what exposed the row-78 class of
# failure, so it stays the regression scale for that class even though the
# authoritative FY27 profile now injects exactly its advertised population.
_INJECTION_ONLY_SCALE = replace(
    EBB_FY26_SCALE,
    name="EBB_FY27_INJECTION_ONLY",
    he_sites_per_range=80,
    openr_injection_headroom=18,
)


class EbbInjectionScaleReachesEveryPnhCheckTest(unittest.TestCase):
    """Every PNH readiness check must describe the injection setup performed.

    Threading the resolved scale into two named playbooks and leaving the rest
    on the starts alone is the failure this guards: the factory builds a dozen
    playbooks that emit `startup_ibgp_pnh_verification`, and a check given
    only the range starts falls back to the runtime's own defaults of 63
    nodes at stride 2. Those equal the FY26 scale, so an unthreaded check
    passes under FY26 by coincidence of two independent defaults while
    validating 63 under every other scale, whatever setup injected. These run
    the real public factory, with a real topology and inventory, and compare
    every emitted check against the setup task's own numbers rather than
    against a literal.
    """

    # Playbooks that emit the PNH readiness check and need neither the
    # runtime-update prefix window nor route-storm sharding, so the override
    # topology below matches what the factory would have built.
    _SELECTED = [
        "bgp_ebb_attribute_churn_playbook",
        "bgp_ebb_igp_pnh_metric_oscillation_playbook",
        "bgp_ebb_igp_unresolvable_pnh_playbook",
        "bgp_ebb_ebgp_session_oscillation_playbook",
        "bgp_ebb_ibgp_route_oscillation_playbook",
    ]

    @staticmethod
    def _config(scale: EbbScaleProfile) -> taac_types.TestConfig:
        topology = ebb_topology(
            scale=scale,
            openr_mode=OpenRMode.STANDALONE,
            next_hops=EBB_NEXT_HOPS_IXIA03,
        )
        return factory.create_bgp_ebb_full_scale_test_config(
            NRQEB009_ASH6,
            name=f"PNH_SCALE_{scale.name}",
            playbooks_selected=list(
                EbbInjectionScaleReachesEveryPnhCheckTest._SELECTED
            ),
            profile=BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R,
            parent_networks=EBB_PARENT_NETWORKS_IXIA03,
            next_hops=EBB_NEXT_HOPS_IXIA03,
            topology_override=topology,
        )

    @staticmethod
    def _json_params(params: taac_types.Params | None) -> dict:
        if params is None or params.json_params is None:
            raise AssertionError("expected serialized json_params")
        return json.loads(params.json_params)

    @classmethod
    def _injection_task_params(cls, config: taac_types.TestConfig) -> dict:
        tasks = [
            cls._json_params(task.params)
            for task in (config.setup_tasks or [])
            if task.task_name == "openr_route_action"
        ]
        if len(tasks) != 1:
            raise AssertionError(f"expected one injection task, got {len(tasks)}")
        return tasks[0]

    @classmethod
    def _pnh_payloads(cls, config: taac_types.TestConfig) -> list[dict]:
        return [
            cls._json_params(check.check_params)
            for playbook in (config.playbooks or [])
            for check in (playbook.prechecks or [])
            if check.check_id == "startup_ibgp_pnh_verification"
        ]

    def _assert_every_check_matches_setup(self, scale: EbbScaleProfile) -> None:
        config = self._config(scale)
        injected = self._injection_task_params(config)
        payloads = self._pnh_payloads(config)

        self.assertEqual(scale.he_sites_per_range, injected["count"])
        self.assertEqual(scale.next_hop_step, injected["step"])
        # Several playbooks emit the check; a single one passing would not
        # show that the threading is complete.
        self.assertGreater(len(payloads), 1)
        for index, payload in enumerate(payloads):
            with self.subTest(scale=scale.name, check=index):
                self.assertEqual(injected["count"], payload["count"])
                self.assertEqual(injected["step"], payload["step"])
                self.assertEqual(
                    injected["start_ipv4s"],
                    payload["start_ipv4s"][: len(injected["start_ipv4s"])],
                )

    def test_fy26_scale_reaches_every_pnh_check(self) -> None:
        self._assert_every_check_matches_setup(EBB_FY26_SCALE)

    def test_injection_only_scale_reaches_every_pnh_check(self) -> None:
        """80 HE sites per range, through the real factory, end to end."""
        self._assert_every_check_matches_setup(_INJECTION_ONLY_SCALE)

    def test_sixty_two_node_override_reaches_every_pnh_check(self) -> None:
        """The tightest scale that still covers 62 advertised peers per plane."""
        self._assert_every_check_matches_setup(
            replace(
                EBB_FY26_SCALE,
                name="EBB_TEST_62",
                he_sites_per_range=62,
                openr_injection_headroom=0,
            )
        )

    def test_production_readiness_count_is_the_scale_not_the_peer_count(
        self,
    ) -> None:
        """63 injected nodes per range, not the 62 emulated peers.

        These two numbers differ by exactly one, and the wrong one is the
        plausible mistake: the peer count is what the topology advertises,
        while the injected count is what Open/R must make reachable, with one
        node of headroom. Threading the peer count would leave the spare node
        -- the one proving the injection has headroom -- unvalidated, and the
        check would still pass. Asserted against the production FY26 config
        the scheduled bindings use.
        """
        config = self._config(EBB_FY26_SCALE)
        payloads = self._pnh_payloads(config)

        self.assertGreater(len(payloads), 1)
        self.assertEqual(63, EBB_FY26_SCALE.he_sites_per_range)
        self.assertEqual(62, IBGP_PEER_SCALE_PER_PLANE)
        for index, payload in enumerate(payloads):
            with self.subTest(check=index):
                self.assertEqual(EBB_FY26_SCALE.he_sites_per_range, payload["count"])
                self.assertNotEqual(IBGP_PEER_SCALE_PER_PLANE, payload["count"])

    def test_every_pnh_emitting_playbook_is_covered(self) -> None:
        """No playbook emits a check the factory left without a scale.

        Guards the specific regression of threading the scale into some
        construction sites and not others: any check missing count or step
        means a builder the factory did not thread.
        """
        config = self._config(_INJECTION_ONLY_SCALE)
        missing = [
            payload
            for payload in self._pnh_payloads(config)
            if "count" not in payload or "step" not in payload
        ]
        self.assertEqual([], missing)


class EbbInjectionRangeAnchorWithRuntimeAdvertisementsTest(unittest.TestCase):
    """A plane may bind more than one advertisement and still anchor a range.

    The TC7 runtime intents add a second, next-hop-self advertisement to the
    DC planes. Counting advertisements rather than eligible injection sources
    rejected the whole UG 2.7 suite at compile time, because a SELF
    advertisement is auxiliary here: its next hops are the session addresses,
    which no injection covers. These lock the filter in place.
    """

    @staticmethod
    def _tc7_config() -> taac_types.TestConfig:
        """Compile the real UG 2.7 / TC7 topology with runtime advertisements."""
        return factory.create_bgp_ebb_full_scale_test_config(
            NRQEB009_ASH6,
            name="TC7_RUNTIME_ADVERTISEMENT_ANCHOR",
            playbooks_selected=["bgp_ug_link_flap_recovery"],
            profile=BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R,
            parent_networks=EBB_PARENT_NETWORKS_IXIA03,
            next_hops=EBB_NEXT_HOPS_IXIA03,
        )

    def test_tc7_topology_resolves_its_injection_with_runtime_advertisements(
        self,
    ) -> None:
        config = self._tc7_config()

        injections = [
            json.loads(task.params.json_params)
            for task in (config.setup_tasks or [])
            if task.task_name == "openr_route_action"
            and task.params is not None
            and task.params.json_params is not None
        ]
        self.assertEqual(1, len(injections))
        # The auxiliary SELF advertisement must not perturb the anchor: the
        # resolved range starts are the plane next hops, at the FY26 scale.
        self.assertEqual(EBB_FY26_SCALE.he_sites_per_range, injections[0]["count"])
        self.assertEqual(EBB_FY26_SCALE.next_hop_step, injections[0]["step"])
        self.assertEqual(4, len(injections[0]["start_ipv4s"]))
        self.assertEqual(4, len(injections[0]["start_ipv6s"]))

    def test_tc7_planes_really_do_bind_a_second_advertisement(self) -> None:
        """Guards the guard: without this the test above proves nothing."""
        topology = ebb_topology(
            scale=EBB_FY26_SCALE,
            openr_mode=OpenRMode.STANDALONE,
            next_hops=EBB_NEXT_HOPS_IXIA03,
            extra_advertisements=factory._tc7_runtime_intents(
                {"bgp_ug_link_flap_recovery"}
            )[1],
            extra_prefix_sets=factory._tc7_runtime_intents(
                {"bgp_ug_link_flap_recovery"}
            )[0],
        )
        multi = [
            group
            for group in topology.device_groups
            if group.openr_injection_range_ordinal is not None
            and len(group.prefix_advertisements) > 1
        ]
        self.assertTrue(multi)
        for group in multi:
            with self.subTest(group=group.name):
                self.assertTrue(
                    any(
                        advertisement.next_hop.mode is NextHopMode.SELF
                        for advertisement in group.prefix_advertisements
                    )
                )

    def _bind_with_advertisements(
        self, replacement: t.Callable[[t.Any], tuple[t.Any, ...]]
    ) -> BoundTopology:
        bound = ebb_topology(
            scale=EBB_FY26_SCALE,
            openr_mode=OpenRMode.STANDALONE,
            next_hops=EBB_NEXT_HOPS_IXIA03,
        ).bind_to_inventory(
            physical_inventory=NRQEB009_ASH6,
            port_map=EBB_PORT_MAP_WITH_BGPMON,
            parent_networks=EBB_PARENT_NETWORKS_IXIA03,
            peer_groups=EBB_PEER_GROUPS,
            as_numbers=EBB_AS_NUMBERS,
        )
        return replace(
            bound,
            device_groups=tuple(
                replace(group, prefix_advertisements=replacement(group))
                if group.name == "dg_ibgp_v4_dc_p1"
                else group
                for group in bound.device_groups
            ),
        )

    def test_zero_eligible_sources_is_rejected(self) -> None:
        """Every advertisement next-hop-self leaves nothing to anchor on."""
        bound = self._bind_with_advertisements(
            lambda group: tuple(
                replace(
                    advertisement,
                    spec=replace(
                        advertisement.spec,
                        next_hop=replace(
                            advertisement.spec.next_hop, mode=NextHopMode.SELF
                        ),
                    ),
                )
                for advertisement in group.prefix_advertisements
            )
        )

        with self.assertRaises(ValueError) as caught:
            bound.resolve_openr_injection_plan()
        message = str(caught.exception)
        self.assertIn("dg_ibgp_v4_dc_p1", message)
        self.assertIn("0 eligible of 1", message)
        self.assertIn("next-hop-self", message)

    def test_multiple_eligible_sources_are_rejected(self) -> None:
        """Two externally resolved advertisements make the anchor ambiguous."""
        bound = self._bind_with_advertisements(
            lambda group: group.prefix_advertisements * 2
        )

        with self.assertRaises(ValueError) as caught:
            bound.resolve_openr_injection_plan()
        message = str(caught.exception)
        self.assertIn("dg_ibgp_v4_dc_p1", message)
        self.assertIn("2 eligible of 2", message)
        self.assertIn("ambiguous", message)
        self.assertIn("per_peer", message)

    def _unresolvable_injection_topology(self) -> t.Any:
        """The FY26 topology with range 1 declared twice for v4."""
        logical = self._bind_with_advertisements(
            lambda group: group.prefix_advertisements
        ).logical_topology
        return replace(
            logical,
            device_groups=tuple(
                replace(group, openr_injection_range_ordinal=1)
                if group.name == "dg_ibgp_v4_dc_p2"
                else group
                for group in logical.device_groups
            ),
        )

    def test_factory_fails_closed_with_the_compilers_injection_issue(self) -> None:
        """An unresolvable range is the same topology error at either layer.

        The factory resolves the plan to build its playbooks before it compiles
        the topology, so it reaches a bad declaration first. It must fail with
        the structured issue the compiler raises, not with a bare ValueError.
        """
        duplicated = self._unresolvable_injection_topology()

        def build(*, setup_only: bool) -> taac_types.TestConfig:
            return factory.create_bgp_ebb_full_scale_test_config(
                NRQEB009_ASH6,
                name="UNRESOLVABLE_INJECTION",
                playbooks_selected=(
                    None
                    if setup_only
                    else ["bgp_ebb_igp_pnh_metric_oscillation_playbook"]
                ),
                profile=BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R,
                parent_networks=EBB_PARENT_NETWORKS_IXIA03,
                next_hops=EBB_NEXT_HOPS_IXIA03,
                setup_only=setup_only,
                topology_override=duplicated,
            )

        with self.assertRaises(TopologyValidationError) as from_factory:
            build(setup_only=False)
        with self.assertRaises(TopologyValidationError) as from_compiler:
            build(setup_only=True)

        (issue,) = from_factory.exception.issues
        self.assertEqual("device_config.openr_injection_scale", issue.path)
        self.assertEqual("unresolvable_openr_injection", issue.code)
        self.assertIn("range 1 is declared twice for v4", issue.message)
        self.assertEqual(from_compiler.exception.issues, from_factory.exception.issues)

    def test_non_standalone_binding_never_resolves_a_declared_injection(
        self,
    ) -> None:
        """Without standalone Open/R the factory ignores a stale injection scale.

        The compiler resolves the plan only for standalone Open/R. A profile
        without Open/R binds the topology in NONE mode but leaves its declared
        injection scale in place, so the factory must not resolve it either:
        an unusable declaration builds exactly the config no declaration
        builds, with no injection task and no PNH readiness check.
        """
        duplicated = self._unresolvable_injection_topology()

        def build(topology: t.Any) -> taac_types.TestConfig:
            return factory.create_bgp_ebb_full_scale_test_config(
                NRQEB009_ASH6,
                name="NON_STANDALONE_INJECTION",
                playbooks_selected=["bgp_ebb_ebgp_session_oscillation_playbook"],
                profile=BgpPlusPlusProfile.BGP_PLUS_PLUS_WITHOUT_OPEN_R,
                parent_networks=EBB_PARENT_NETWORKS_IXIA03,
                next_hops=EBB_NEXT_HOPS_IXIA03,
                topology_override=topology,
            )

        stale = build(duplicated)
        undeclared = build(
            replace(
                duplicated,
                device_config=replace(
                    duplicated.device_config, openr_injection_scale=None
                ),
            )
        )

        self.assertEqual(undeclared, stale)
        self.assertNotIn(
            "openr_route_action",
            [task.task_name for task in stale.setup_tasks or []],
        )
        self.assertEqual(
            [], EbbInjectionScaleReachesEveryPnhCheckTest._pnh_payloads(stale)
        )

    def test_readiness_checks_the_compatibility_injection_without_a_plan(
        self,
    ) -> None:
        """Standalone Open/R with no injection scale still injects a default.

        The compiler renders the compatibility injection when no plan
        resolves, so every PNH readiness check must assert that injection's
        starts, count and step, not fall back to the runtime's own defaults.
        """
        logical = self._bind_with_advertisements(
            lambda group: group.prefix_advertisements
        ).logical_topology
        unscaled = replace(
            logical,
            device_config=replace(logical.device_config, openr_injection_scale=None),
        )
        checks = EbbInjectionScaleReachesEveryPnhCheckTest
        config = factory.create_bgp_ebb_full_scale_test_config(
            NRQEB009_ASH6,
            name="UNSCALED_INJECTION",
            playbooks_selected=list(checks._SELECTED),
            profile=BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R,
            parent_networks=EBB_PARENT_NETWORKS_IXIA03,
            next_hops=EBB_NEXT_HOPS_IXIA03,
            topology_override=unscaled,
        )

        injected = checks._injection_task_params(config)
        payloads = checks._pnh_payloads(config)

        self.assertGreater(len(payloads), 1)
        for index, payload in enumerate(payloads):
            with self.subTest(check=index):
                self.assertEqual(injected["count"], payload.get("count"))
                self.assertEqual(injected["step"], payload.get("step"))
                self.assertEqual(
                    injected["start_ipv4s"],
                    payload["start_ipv4s"][: len(injected["start_ipv4s"])],
                )

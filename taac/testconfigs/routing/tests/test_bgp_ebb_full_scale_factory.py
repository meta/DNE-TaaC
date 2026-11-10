# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.
"""Focused coverage for EBB full-scale topology selection."""

import json
import runpy
import typing as t
import unittest
from types import ModuleType, SimpleNamespace
from unittest import mock

from taac.abstractions.topologies.ebb_full_scale import (
    EBB_OPENR_INJECTED_START_IPV4S,
    EBB_OPENR_INJECTED_START_IPV4S_IXIA03,
    EBB_OPENR_INJECTED_START_IPV6S,
    EBB_OPENR_INJECTED_START_IPV6S_IXIA03,
    EBB_PARENT_NETWORKS,
    EBB_PARENT_NETWORKS_IXIA03,
)
from taac.abstractions.topology.model import BoundTopology
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
    topology = factory.ebb_full_scale_topology(
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
                with mock.patch.object(
                    factory, "ebb_full_scale_topology", return_value=topology
                ):
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
                ),
                parent_networks={"bgpmon_v6": bgp_mon_parent_network},
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
                            openr_injected_start_ipv4s=start_ipv4s,
                            openr_injected_start_ipv6s=start_ipv6s,
                        ),
                        parent_networks=parent_networks,
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
                ),
                parent_networks={},
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
                factory, "ebb_full_scale_topology", return_value=topology
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
                factory, "ebb_full_scale_topology", return_value=topology
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
                factory, "ebb_full_scale_topology", return_value=topology
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
        with mock.patch.object(
            factory, "ebb_full_scale_topology", return_value=topology
        ):
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
            mock.patch.object(
                factory, "ebb_full_scale_topology", return_value=topology
            ),
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

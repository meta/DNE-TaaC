# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

import ipaddress
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from taac.test_as_a_config.types import StepName
from taac.tasks.rbb_srv6_capture_mirror_task import RbbSrv6CaptureMirrorTask
from taac.tasks.rbb_srv6_pcap_verify_task import RbbSrv6PcapVerifyTask
from taac.tasks.registry import TASK_NAME_TO_CLASS
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_wire_test_config import (
    create_rbb_srv6_wire_test_config,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology() -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="wire-r1.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="wire-r2.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/6", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


def _tasks(playbook):
    result = []
    for stage in playbook.stages or []:
        for step in stage.steps or []:
            if step.name != StepName.RUN_TASK_STEP:
                continue
            task = json.loads(step.input_json)["task"]
            result.append(
                (task["task_name"], json.loads(task["params"]["json_params"]))
            )
    return result


class RbbSrv6WireConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = create_rbb_srv6_wire_test_config(_topology())

    def test_suite_contains_three_full_independent_cases(self) -> None:
        self.assertEqual(
            [playbook.name for playbook in self.config.playbooks or []],
            [
                "rbb_p2_tc05_headend_encap_nhg_traffic",
                "rbb_p2_tc08_resolved_nhg_encap_traffic",
                "rbb_p2_tc113_usid_carrier_on_wire",
            ],
        )
        self.assertTrue(
            all("[FULL]" in playbook.description for playbook in self.config.playbooks)
        )
        self.assertEqual(
            [item.name for item in self.config.basic_traffic_item_configs or []],
            [C.TRAFFIC_ITEM_NAMED_NHG],
        )

    def test_every_run_task_is_registered(self) -> None:
        for playbook in self.config.playbooks or []:
            task_names = [name for name, _ in _tasks(playbook)]
            task_names.extend(
                json.loads(step.input_json)["task"]["task_name"]
                for step in playbook.cleanup_steps or []
                if step.name == StepName.RUN_TASK_STEP
            )
            self.assertEqual(
                sorted(set(task_names) - TASK_NAME_TO_CLASS.keys()),
                [],
                playbook.name,
            )

    def test_each_case_programs_unique_nhg_and_decodes_actual_capture(self) -> None:
        packed = C.pack_usid_container(
            SRV6_3_USIDS_PROFILE.locator, SRV6_3_USIDS_PROFILE.encap_usids
        )
        for playbook in self.config.playbooks or []:
            tasks = _tasks(playbook)
            mirror = [
                params
                for name, params in tasks
                if name == "rbb_srv6_capture_mirror"
            ]
            self.assertEqual([item["action"] for item in mirror], ["apply", "restore"])
            self.assertEqual(mirror[0]["source_interfaces"], ["eth1/1", "eth1/2"])
            self.assertEqual(mirror[0]["destination_interface"], "eth1/5")
            verify = next(
                params for name, params in tasks if name == "rbb_srv6_pcap_verify"
            )
            self.assertEqual(verify["expected_outer_destination"], packed)
            self.assertEqual(
                verify["expected_usids"], list(SRV6_3_USIDS_PROFILE.encap_usids)
            )
            self.assertEqual(
                verify["expected_inner_destination_prefix"], C.TAIL_DEST_PREFIX
            )
            cleanup = [
                json.loads(json.loads(step.input_json)["task"]["params"]["json_params"])
                for step in playbook.cleanup_steps or []
                if step.name == StepName.RUN_TASK_STEP
                and json.loads(step.input_json)["task"]["task_name"]
                == "rbb_srv6_capture_mirror"
            ]
            self.assertEqual([item["action"] for item in cleanup], ["restore"])

    def test_tc05_and_tc08_require_every_core_path_but_tc113_does_not(self) -> None:
        for index, playbook in enumerate(self.config.playbooks or []):
            correlations = [
                params
                for name, params in _tasks(playbook)
                if name == "rbb_traffic_counter_correlation"
            ]
            if index < 2:
                self.assertEqual(len(correlations), 8)
                self.assertEqual(
                    [item["action"] for item in correlations],
                    ["snapshot"] * 4 + ["assert_ixia_share"] * 4,
                )
                self.assertEqual(
                    {item["counter_interfaces"][0] for item in correlations},
                    {"eth1/1", "eth1/2"},
                )
                by_interface = {
                    item["counter_interfaces"][0]: item["fixed_ixia_multiples"]
                    for item in correlations
                }
                self.assertEqual(by_interface, {"eth1/1": 1, "eth1/2": 0})
                self.assertTrue(
                    all(item["ixia_stats_cleared"] for item in correlations)
                )
                self.assertTrue(
                    any(name == "rbb_ixia_capability" for name, _ in _tasks(playbook))
                )
            else:
                self.assertEqual(correlations, [])

    def test_wire_stats_clear_settles_while_hardware_capture_starts(self) -> None:
        for playbook in self.config.playbooks or []:
            wire_stage = next(
                stage
                for stage in playbook.stages or []
                if "capture actual SRv6 encapsulation" in stage.description
            )
            descriptions = [step.description for step in wire_stage.steps or []]
            clear_index = descriptions.index("Clear traffic statistics")
            capture_index = next(
                index
                for index, description in enumerate(descriptions)
                if "start hardware packet capture" in description
            )
            snapshot_indices = [
                index
                for index, description in enumerate(descriptions)
                if " snapshot " in description
            ]
            self.assertLess(clear_index, capture_index)
            self.assertTrue(
                all(capture_index < index for index in snapshot_indices)
            )


class RbbSrv6CaptureMirrorConfigTest(unittest.TestCase):
    def test_patch_adds_exact_local_span_and_port_bindings(self) -> None:
        raw = json.dumps(
            {
                "sw": {
                    "ports": [
                        {"name": "eth1/1", "logicalID": 1},
                        {"name": "eth1/2", "logicalID": 2},
                        {"name": "eth1/5", "logicalID": 5},
                    ],
                    "mirrors": [],
                }
            }
        )
        patched = RbbSrv6CaptureMirrorTask._patched_config(
            raw,
            "r1",
            "taac-span",
            ["eth1/1", "eth1/2"],
            "eth1/5",
        )
        self.assertEqual(
            [port.get("egressMirror") for port in patched["sw"]["ports"]],
            ["taac-span", "taac-span", None],
        )
        self.assertEqual(
            patched["sw"]["mirrors"],
            [
                {
                    "name": "taac-span",
                    "destination": {"egressPort": {"name": "eth1/5"}},
                    "dscp": 0,
                    "truncate": False,
                }
            ],
        )

    def test_patch_refuses_operator_owned_mirror_binding(self) -> None:
        raw = json.dumps(
            {
                "sw": {
                    "ports": [
                        {"name": "eth1/1", "egressMirror": "operator-span"},
                        {"name": "eth1/5"},
                    ],
                    "mirrors": [],
                }
            }
        )
        with self.assertRaisesRegex(Exception, "already has egressMirror"):
            RbbSrv6CaptureMirrorTask._patched_config(
                raw, "r1", "taac-span", ["eth1/1"], "eth1/5"
            )


def _classic_capture(frame: bytes) -> bytes:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    return global_header + record


def _srv6_frame() -> tuple[bytes, str, str]:
    outer_source = str(ipaddress.ip_interface(C.srv6_source_cidr("r1", "B")).ip)
    outer_destination = C.pack_usid_container(
        SRV6_3_USIDS_PROFILE.locator, SRV6_3_USIDS_PROFILE.encap_usids
    )
    inner_source = ipaddress.IPv6Address(C.IXIA_R1_EDGE_V6)
    inner_destination = ipaddress.ip_network(C.TAIL_DEST_PREFIX).network_address + 1
    inner = (
        bytes.fromhex("60000000")
        + struct.pack("!HBB", 0, 59, 63)
        + inner_source.packed
        + inner_destination.packed
    )
    outer = (
        bytes.fromhex("60000000")
        + struct.pack("!HBB", len(inner), 41, 64)
        + ipaddress.IPv6Address(outer_source).packed
        + ipaddress.IPv6Address(outer_destination).packed
        + inner
    )
    ethernet = bytes.fromhex("02000000000202000000000186dd") + outer
    return ethernet, outer_source, outer_destination


class RbbSrv6PcapVerifyTest(unittest.IsolatedAsyncioTestCase):
    async def test_exact_outer_and_inner_packet_passes(self) -> None:
        frame, outer_source, outer_destination = _srv6_frame()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "srv6.pcap"
            path.write_bytes(_classic_capture(frame))
            task = RbbSrv6PcapVerifyTask(logger=MagicMock())
            await task.run(
                {
                    "gate": "phase2:TC-113",
                    "pcap_path": str(path),
                    "expected_outer_source": outer_source,
                    "expected_outer_destination": outer_destination,
                    "expected_inner_source": C.IXIA_R1_EDGE_V6,
                    "expected_inner_destination_prefix": C.TAIL_DEST_PREFIX,
                    "locator": SRV6_3_USIDS_PROFILE.locator,
                    "expected_usids": list(SRV6_3_USIDS_PROFILE.encap_usids),
                    "min_packets": 1,
                }
            )

    async def test_wrong_outer_source_fails(self) -> None:
        frame, _, outer_destination = _srv6_frame()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "srv6.pcap"
            path.write_bytes(_classic_capture(frame))
            task = RbbSrv6PcapVerifyTask(logger=MagicMock())
            with self.assertRaisesRegex(Exception, "0 matching SRv6 packets"):
                await task.run(
                    {
                        "pcap_path": str(path),
                        "expected_outer_source": "2001:db8::dead",
                        "expected_outer_destination": outer_destination,
                        "expected_inner_source": C.IXIA_R1_EDGE_V6,
                        "expected_inner_destination_prefix": C.TAIL_DEST_PREFIX,
                        "locator": SRV6_3_USIDS_PROFILE.locator,
                        "expected_usids": list(SRV6_3_USIDS_PROFILE.encap_usids),
                    }
                )

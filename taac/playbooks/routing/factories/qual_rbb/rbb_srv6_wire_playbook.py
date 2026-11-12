# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Full IXIA/on-wire validation for Phase-2 TC-05, TC-08, and TC-113."""

from __future__ import annotations

import ipaddress
import re
import typing as t

from taac.playbooks.routing.factories.qual_rbb.rbb_named_nhg_playbook import (
    create_rbb_named_nhg_playbook,
)
from taac.playbooks.routing.factories.qual_rbb.rbb_srv6_playbook import (
    _traffic_loss_validation_step,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_clear_traffic_stats_step,
    create_ixia_api_step,
    create_ixia_packet_capture_step,
    create_longevity_step,
    create_run_task_step,
    create_stop_traffic_step,
)
from taac.test_as_a_config.types import Playbook, Step
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_core_ecmp_profiles import (
    MIN_PATH_TRAFFIC_SHARE_PCT,
    validate_core_ecmp_topology,
)
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_srv6_wire_profiles import (
    RbbSrv6WireProfile,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology

_TRAFFIC_SECONDS = 5
_DRAIN_SECONDS = 2


def _mirror_step(
    topology: RbbTopology,
    profile: RbbSrv6WireProfile,
    action: str,
) -> Step:
    sources = [
        member
        for port_channel in topology.r1.core_pcs
        for member in port_channel.members
    ]
    destination = topology.r1.primary_ixia_interface
    if not destination:
        raise ValueError(f"{profile.testplan_id} requires an R1 IXIA edge")
    return create_run_task_step(
        task_name="rbb_srv6_capture_mirror",
        params_dict={
            "hostname": topology.r1.hostname,
            "action": action,
            "mirror_name": (
                f"taac-rbb-{profile.testplan_id.split(':')[-1].lower()}-span"
            ),
            "source_interfaces": sources,
            "destination_interface": destination,
        },
        description=f"[{profile.testplan_id}] {action} recovery-safe core SPAN",
        start_traffic=False,
    )


def _path_counter_specs(
    topology: RbbTopology, profile: RbbSrv6WireProfile
) -> list[dict[str, t.Any]]:
    specs: list[dict[str, t.Any]] = []
    for index, (r1_pc, r2_pc) in enumerate(
        zip(topology.r1.core_pcs, topology.r2.core_pcs)
    ):
        for role, node, pc, direction in (
            ("r1", topology.r1, r1_pc, "egress"),
            ("r2", topology.r2, r2_pc, "ingress"),
        ):
            specs.append(
                {
                    "hostname": node.hostname,
                    "gate": profile.testplan_id,
                    "sample_id": (
                        f"{profile.testplan_id}:path{index}:{role}:{direction}"
                    ),
                    "counter_interfaces": list(pc.members),
                    "counter_direction": direction,
                    "counter_kind": "packets",
                    "traffic_item": C.TRAFFIC_ITEM_NAMED_NHG,
                    "ixia_counter_field": "tx_frames",
                    # This stage stops traffic and completes ClearStats before
                    # taking its DUT baselines.  The IxNetwork stats view can
                    # still expose the preceding total until traffic resumes.
                    "ixia_stats_cleared": True,
                    # The two-node carrier always traverses path 0 once more
                    # after its initial named-NHG choice. Subtract that known
                    # volume before claiming path-0 NHG distribution.
                    "fixed_ixia_multiples": 1 if index == 0 else 0,
                }
            )
    return specs


def _counter_step(spec: dict[str, t.Any], action: str) -> Step:
    params = {"action": action, **spec}
    if action == "assert_ixia_share":
        params["min_ixia_share_percent"] = MIN_PATH_TRAFFIC_SHARE_PCT
    return create_run_task_step(
        task_name="rbb_traffic_counter_correlation",
        params_dict=params,
        description=f"[{spec['gate']}] {action} {spec['sample_id']}",
        ixia_needed=True,
        start_traffic=False,
    )


def _wire_stage(
    topology: RbbTopology,
    profile: RbbSrv6WireProfile,
) -> t.Any:
    r1_interface = topology.r1.primary_ixia_interface
    if not r1_interface:
        raise ValueError(f"{profile.testplan_id} requires an R1 IXIA edge")
    suffix = profile.testplan_id.split("-")[-1].lower()
    capture_id = f"rbb-srv6-{suffix}"
    remote_name = f"rbb_srv6_{suffix}_outer.pcap"
    local_path = f"/tmp/{remote_name}"
    packed = C.pack_usid_container(
        SRV6_3_USIDS_PROFILE.locator, SRV6_3_USIDS_PROFILE.encap_usids
    )
    outer_source = str(
        ipaddress.ip_interface(C.srv6_source_cidr("r1", "B")).ip
    )
    counter_specs = (
        _path_counter_specs(topology, profile) if profile.require_distribution else []
    )
    steps: list[Step] = [
        create_stop_traffic_step(),
        # RESTPy returns from ClearStats before the refreshed zeroed view is
        # guaranteed to be observable.  Start the hardware capture after the
        # clear so its setup time also acts as the settling interval; otherwise
        # the immediately following correlation snapshot can retain the prior
        # stage's IXIA total and later report a false counter rollback.
        create_clear_traffic_stats_step(start_traffic=False),
        create_ixia_packet_capture_step(
            device_name=topology.r1.hostname,
            interface=r1_interface,
            mode="start",
            capture_filter="",
            capture_id=capture_id,
            control_plane=False,
            description=f"[{profile.testplan_id}] start hardware packet capture",
        ),
        *(_counter_step(spec, "snapshot") for spec in counter_specs),
        create_ixia_api_step(
            api_name="start_traffic_items",
            args_dict={
                "traffic_item_regex": f"^{re.escape(C.TRAFFIC_ITEM_NAMED_NHG)}$"
            },
            description=f"[{profile.testplan_id}] start only the load-bearing flow",
            start_traffic=False,
        ),
        create_longevity_step(
            duration=_TRAFFIC_SECONDS,
            description=f"[{profile.testplan_id}] collect SRv6 wire sample",
            start_traffic=False,
        ),
        _traffic_loss_validation_step(
            f"{profile.testplan_id}: lossless SRv6 forwarding",
            traffic_items=(C.TRAFFIC_ITEM_NAMED_NHG,),
            start_traffic=False,
        ),
        create_stop_traffic_step(),
        create_longevity_step(
            duration=_DRAIN_SECONDS,
            description=f"[{profile.testplan_id}] drain final counter updates",
            start_traffic=False,
        ),
        *(_counter_step(spec, "assert_ixia_share") for spec in counter_specs),
        create_ixia_packet_capture_step(
            device_name=topology.r1.hostname,
            interface=r1_interface,
            mode="stop",
            capture_id=capture_id,
            description=f"[{profile.testplan_id}] stop hardware packet capture",
        ),
        create_ixia_packet_capture_step(
            device_name=topology.r1.hostname,
            interface=r1_interface,
            mode="save",
            pcap_filename=remote_name,
            capture_id=capture_id,
            description=f"[{profile.testplan_id}] save SRv6 outer capture",
        ),
        create_ixia_packet_capture_step(
            device_name=topology.r1.hostname,
            interface=r1_interface,
            mode="download",
            pcap_filename=remote_name,
            local_pcap_path=local_path,
            capture_id=capture_id,
            description=f"[{profile.testplan_id}] download SRv6 outer capture",
        ),
        create_run_task_step(
            task_name="rbb_srv6_pcap_verify",
            params_dict={
                "gate": profile.testplan_id,
                "pcap_path": local_path,
                "expected_outer_source": outer_source,
                "expected_outer_destination": packed,
                "expected_inner_source": C.IXIA_R1_EDGE_V6,
                "expected_inner_destination_prefix": C.TAIL_DEST_PREFIX,
                "locator": SRV6_3_USIDS_PROFILE.locator,
                "expected_usids": list(SRV6_3_USIDS_PROFILE.encap_usids),
                "min_packets": 1,
            },
            description=(
                f"[{profile.testplan_id}] decode outer IPv6 and ordered uSID carrier"
            ),
            start_traffic=False,
        ),
    ]
    return create_steps_stage(
        steps=steps,
        description=(
            f"{profile.testplan_id}: capture actual SRv6 encapsulation"
            + (
                " and prove traffic on every named-NHG path"
                if profile.require_distribution
                else " and verify its uSID encoding"
            )
        ),
    )


def create_rbb_srv6_wire_playbook(
    profile: RbbSrv6WireProfile,
    *,
    topology: RbbTopology,
) -> Playbook:
    if profile.require_distribution:
        validate_core_ecmp_topology(topology)
    provisioning = profile.provisioning_profile(topology)
    base = create_rbb_named_nhg_playbook(
        provisioning,
        r1_hostname=topology.r1.hostname,
        r2_hostname=topology.r2.hostname,
        topology=topology,
        include_traffic=True,
    )
    prefix_stages = []
    if profile.require_distribution:
        prefix_stages.append(
            create_steps_stage(
                steps=[
                    create_run_task_step(
                        task_name="rbb_ixia_capability",
                        params_dict={
                            "gate": profile.testplan_id,
                            "require_variable_l4_flow_ranges": True,
                        },
                        description=(
                            f"[{profile.testplan_id}] require multi-flow hash inputs"
                        ),
                        ixia_needed=True,
                        start_traffic=False,
                    )
                ],
                description=f"{profile.testplan_id}: verify IXIA hash capability",
            )
        )
    stages = [
        *prefix_stages,
        *(base.stages or []),
        create_steps_stage(
            steps=[_mirror_step(topology, profile, "apply")],
            description=f"{profile.testplan_id}: mirror R1 core egress to IXIA",
        ),
        _wire_stage(topology, profile),
        create_steps_stage(
            steps=[_mirror_step(topology, profile, "restore")],
            description=f"{profile.testplan_id}: restore pre-test AgentConfig",
        ),
    ]
    cleanup_steps = [
        create_stop_traffic_step(),
        _mirror_step(topology, profile, "restore"),
        *(base.cleanup_steps or []),
    ]
    return Playbook(
        name=profile.playbook_name,
        description=(
            f"{profile.testplan_id} [FULL]: {profile.title}; exact RIB/FIB/NHG, "
            "loss, path counters, and decoded on-wire packet evidence"
        ),
        stages=stages,
        prechecks=list(base.prechecks or []),
        postchecks=list(base.postchecks or []),
        cleanup_steps=cleanup_steps,
        traffic_items_to_start=list(base.traffic_items_to_start or []),
        device_regexes=list(base.device_regexes or []),
    )


__all__ = ["create_rbb_srv6_wire_playbook"]

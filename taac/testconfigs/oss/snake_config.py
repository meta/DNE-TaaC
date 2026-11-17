# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Snake test config.

Topology is derived from circuit_info.csv via ConfigTopology at runtime:
  - TGEN links become the snake IXIA endpoints
  - SNAKE links are self-loopback pairs
  - DUT hostname comes from --dut CLI flag

One snake is built per lane group, so a DUT whose cages are broken out
1x800G -> 2x400G runs both of its snakes -- one traffic item each -- in a
single test.

Canonical invocation:

TAAC_SSH_USER=root TAAC_SSH_PASSWORD=root \
./docker/run_taac_docker.sh run python3 -m taac.runner.oss_entry_point \
  --test-configs /workspace/taac/testconfigs/oss/snake_config.py \
  --dut <dut> \
  --ixia-api-server <ixia> \
  --circuit-info-csv /workspace/taac/oss_topology_info/circuit_info.csv \
  --device-info-csv /workspace/taac/oss_topology_info/device_info.csv \
  --playbook test_one_min_longevity
"""

import os

from ixia.ixia import types as ixia_types
from taac.runner.testbed_topology import (
    ConfigTopology,
    LinkType,
    topology_aware,
)
from taac.testconfigs.snake.test_test_config import (
    gen_snake_test_config,
)
from taac.test_as_a_config import types as taac_types


def _lane_group(port: str) -> str:
    """Subport suffix identifying the lane group: ``eth1/31/5`` -> ``"5"``."""
    return port.rsplit("/", 1)[-1]


def _cage(port: str) -> int:
    """Cage number, so taps sort ingress-before-egress: ``eth1/31/5`` -> 31."""
    parts = port.split("/")
    return int(parts[1]) if len(parts) > 2 and parts[1].isdigit() else 0


@topology_aware
def test_config(topology: ConfigTopology):
    dut_name = (
        topology.links[0].local_host
        if topology.links
        else os.environ.get("TAAC_DUT", "switch01.example.com")
    )

    tgen_links = [link for link in topology.links if link.link_type == LinkType.TGEN]

    if len(tgen_links) < 2:
        _base = gen_snake_test_config(
            name="OSS_SNAKE",
            basset_pool="",
            hostname=dut_name,
            snake_configs=[
                taac_types.SnakeConfig(
                    source=f"{dut_name}:eth1/1/1",
                    destination=f"{dut_name}:eth1/2/1",
                    source_ip="5000:1::1/64",
                    destination_ip="5000:1::2/64",
                ),
            ],
            ixia_ports=["eth1/1/1", "eth1/2/1"],
            skip_lldp_check=True,
            include_48hr_longevity=True,
            # 48hr soak supersedes the standard 72hr soak for this config.
            playbooks_to_skip=["test_72hr_longevity"],
            use_ipv6_ping=False,
            include_utilization_checks=True,
            # Interface-toggle playbooks validate right after the re-enable step;
            # give slow-training optics time to link before failing, including a
            # qsfp_service remediation after a half-toggle.
            flap_recovery_check_retry_count=12,
            # A qsfp_util re-enable or a remediation can leave a cage training
            # past the single-shot post-test PORT_STATE check.
            postcheck_port_state_retry_count=12,
            # Ride out a wedge_agent thrift stall that outlives the driver-level
            # retry, which would otherwise surface as ERROR.
            precheck_port_state_retry_count=6,
        )
        return _base(ptp_configs=[])

    # One snake per lane group. A cage broken out 1x800G -> 2x400G presents two
    # subports (/1 = lanes 0-3, /5 = lanes 4-7), and the box stitches each into
    # its OWN L2 snake whose VLANs never meet the other's. Pairing across lane
    # groups would join two snakes that share no VLAN and forward nothing, so
    # with four taps the first two (both ingress subports of one cage) are the
    # wrong pair. A DUT with one lane group still yields exactly one snake.
    taps_by_lane = {}
    for link in tgen_links:
        taps_by_lane.setdefault(_lane_group(link.local_port), []).append(link)

    snake_configs = []
    taps_used = []
    for lane in sorted(taps_by_lane):
        taps = sorted(taps_by_lane[lane], key=lambda link: _cage(link.local_port))
        if len(taps) != 2:
            continue
        # Each snake needs its own /64 -- the traffic items run concurrently and
        # duplicate IXIA endpoint addresses would collide.
        subnet = len(snake_configs) + 1
        snake_configs.append(
            taac_types.SnakeConfig(
                source=f"{dut_name}:{taps[0].local_port}",
                destination=f"{dut_name}:{taps[1].local_port}",
                source_ip=f"5000:{subnet}::1/64",
                destination_ip=f"5000:{subnet}::2/64",
            )
        )
        taps_used.extend(taps)

    if not snake_configs:
        # No lane group held exactly two taps -- e.g. both taps on one cage
        # but in different lane groups. Keep the historical pairing so those
        # testbeds behave exactly as they did.
        taps_used = list(tgen_links[:2])
        snake_configs = [
            taac_types.SnakeConfig(
                source=f"{dut_name}:{taps_used[0].local_port}",
                destination=f"{dut_name}:{taps_used[1].local_port}",
                source_ip="5000:1::1/64",
                destination_ip="5000:1::2/64",
            )
        ]

    ixia_connections = [
        taac_types.DirectIxiaConnection(
            interface=link.local_port,
            ixia_port=link.remote_port,
            ixia_chassis_ip=link.remote_host,
        )
        for link in taps_used
    ]

    _base = gen_snake_test_config(
        name="OSS_SNAKE",
        basset_pool="",
        hostname=dut_name,
        snake_configs=snake_configs,
        direct_ixia_connections=ixia_connections,
        ixia_ports=[link.local_port for link in taps_used],
        # The qualified snake DUT is lossless at 45% with fixed 400-byte frames.
        # Smaller control-plane-sized frames overrun the gearbox packet pipeline
        # even at lower bandwidth and produce false precheck failures.
        line_rate=int(os.environ.get("TAAC_LINE_RATE", "45")),
        iteration=int(os.environ.get("TAAC_ITERATION", "1")),
        frame_size_settings=ixia_types.FrameSize(
            type=ixia_types.FrameSizeType.FIXED,
            fixed_size=400,
        ),
        include_benchmark=True,
        # Benchmark frame sizes allowed to lose their own item's packets
        # without failing (sizes the ASIC cannot forward at line rate, e.g.
        # "64,192"). Those playbooks pass on the recorded [BENCHMARK]
        # throughput report instead of a zero-loss bar. Unset or empty means nothing is allowed: every size
        # keeps the strict zero-loss postcheck.
        benchmark_allowed_loss_packet_sizes={
            int(size)
            for size in os.environ.get(
                "TAAC_BENCHMARK_ALLOWED_LOSS_SIZES", ""
            ).split(",")
            if size.strip()
        },
        include_48hr_longevity=True,
        # 48hr soak supersedes the standard 72hr soak for this config.
        playbooks_to_skip=["test_72hr_longevity"],
        include_link_flap_longevity=True,
        # Clear stats first: setup's trial traffic runs all items at once and always shows loss.
        precheck_packet_loss_clear_stats=True,
        packet_loss_sleep_time=30,
        use_ipv6_ping=False,
        include_utilization_checks=True,
        # Interface-toggle playbooks validate right after the re-enable step;
        # give slow-training optics time to link before failing, including a
        # qsfp_service remediation after a half-toggle.
        flap_recovery_check_retry_count=12,
        # A qsfp_util re-enable or a remediation can leave a cage training
        # past the single-shot post-test PORT_STATE check.
        postcheck_port_state_retry_count=12,
        # Ride out a wedge_agent thrift stall that outlives the driver-level
        # retry, which would otherwise surface as ERROR.
        precheck_port_state_retry_count=6,
    )
    # TODO: PTP disabled — IXIA chassis needs PTP license
    return _base(ptp_configs=[])

# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Minipack3BA/Tomahawk5 FADU CPU-queue qualification on fa002-du001.qza1."""

from taac.testconfigs.npi.cpu_queue_test_config import (
    create_npi_cpu_queue_test_config,
)
from taac.testconfigs.npi.minipack_cpu_queue_constants import (
    MINIPACK_CPU_QUEUE_PLAYBOOKS,
)


# IXIA ports on ixia11.netcastle.ash6 via calient03.ash6:
#   eth1/14/1 <> 1/6, eth1/15/1 <> 1/2, eth1/16/1 <> 1/8
# The DUT is AS 4290000001 in confederation 7001. Downlink SSW mimics peer as
# plain eBGP; uplink FAUU mimics peer as confed members.
MP3BA_FA002_DU001_QZA1_CPU_QUEUE_TEST_CONFIG = create_npi_cpu_queue_test_config(
    test_config_name="MP3BA_FA002_DU001_QZA1_CPU_QUEUE_TEST_CONFIG",
    device_name="fa002-du001.qza1",
    local_mac_address="5e:40:97:19:90:73",
    ixia_downlink_interface="eth1/14/1",
    ixia_uplink_interface="eth1/15/1",
    ixia_rogue_interface="eth1/16/1",
    peergroup_uplink_mimic_v6="PEERGROUP_FADU_FAUU_V6",
    peergroup_downlink_mimic_v6="PEERGROUP_FADU_SSW_V6",
    peergroup_uplink_mimic_v4="PEERGROUP_FADU_FAUU_V4",
    peergroup_downlink_mimic_v4="PEERGROUP_FADU_SSW_V4",
    peergroup_rogue_mimic_v6="PEERGROUP_FADU_FAUU_V6",
    peergroup_rogue_mimic_v4="PEERGROUP_FADU_FAUU_V4",
    route_map_uplink_ingress="PROPAGATE_FADU_FAUU_IN",
    route_map_uplink_egress="PROPAGATE_FADU_FAUU_OUT",
    route_map_downlink_ingress="PROPAGATE_FADU_SSW_IN",
    route_map_downlink_egress="PROPAGATE_FADU_SSW_OUT",
    route_map_rogue_ingress="PROPAGATE_FADU_FAUU_IN",
    route_map_rogue_egress="PROPAGATE_FADU_SSW_OUT",
    ixia_downlink_ic_parent_network_v6="2401:db00:e50d:10:8",
    ixia_uplink_ic_parent_network_v6="2401:db00:e50d:10:9",
    ixia_rogue_ic_parent_network_v6="2401:db00:e50d:10:10",
    ixia_downlink_ic_parent_network_v4="10.153.28",
    ixia_uplink_ic_parent_network_v4="10.154.28",
    ixia_rogue_ic_parent_network_v4="10.155.28",
    unique_prefix_limit="5000",
    per_peer_max_route_limit="20000",
    downlink_peer_count=8,
    uplink_peer_count=8,
    rogue_peer_count=0,
    remote_uplink_as_4byte=7010,
    remote_downlink_as_4byte=64901,
    remote_as_4_byte_step=1,
    remote_rogue_as_4byte=64901,
    is_uplink_peer_confed="True",
    is_downlink_peer_confed="False",
    is_rogue_peer_confed="True",
    ixia_downlink_prefix_count_v6=500,
    ixia_uplink_prefix_count_v6=500,
    ixia_rogue_prefix_count_v6=0,
    ixia_downlink_prefix_count_v4=500,
    ixia_uplink_prefix_count_v4=500,
    ixia_rogue_prefix_count_v4=0,
    ixia_downlink_communities=[
        "65441:132",
        "65442:133",
        "65529:26730",
    ],
    ixia_uplink_communities=[
        "65526:35724",
        "65441:134",
        "65442:135",
    ],
    uplink_peer_tag="FAUU",
    downlink_peer_tag="SSW",
    basset_pool="dne.test",
    low_queue=0,
    mid_queue=2,
    high_queue=9,
    playbooks_selected=MINIPACK_CPU_QUEUE_PLAYBOOKS,
    restore_soft_drain=False,
)


__all__ = ["MP3BA_FA002_DU001_QZA1_CPU_QUEUE_TEST_CONFIG"]

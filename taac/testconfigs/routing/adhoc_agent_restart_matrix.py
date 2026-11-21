# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

"""Ad-hoc NRQEB006 CICD-EBB-01 run with the FibAgentBgp/BGP++ restart matrix.

Run on demand with ``--test-config``. It is deliberately kept out of
``cicd_ebb_int_tc.py``, the scheduled-only module that the ``dne_routing``
Conveyor nodes draw from, so the scheduled CICD-EBB-01 keeps its single BGP++
restart. Device, profile, Update Group state and chassis addressing match the
NRQEB006 UG node that runs CICD-EBB-01.
"""

from taac.abstractions.physical_inventory import NRQEB006_ASH6
from taac.abstractions.topologies.ebb_full_scale import (
    EBB_NEXT_HOPS_IXIA03,
    EBB_PARENT_NETWORKS_IXIA03,
)
from taac.constants import BgpPlusPlusProfile
from taac.testconfigs.routing.factories.bgp_ebb_full_scale import (
    create_bgp_ebb_full_scale_test_config,
)

NRQEB006_EBB01_RESTART_MATRIX_UG_ADHOC = create_bgp_ebb_full_scale_test_config(
    NRQEB006_ASH6,
    name="NRQEB006_EBB01_RESTART_MATRIX_UG_ADHOC",
    playbooks_selected=["bgp_ebb_daemon_restart_playbook"],
    profile=BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R,
    enable_update_group=True,
    parent_networks=EBB_PARENT_NETWORKS_IXIA03,
    next_hops=EBB_NEXT_HOPS_IXIA03,
    enable_daemon_restart_matrix=True,
)

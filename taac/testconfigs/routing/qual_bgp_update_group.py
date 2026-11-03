# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.
# pyre-unsafe
"""BGP Update Group lifecycle bindings on the retained EB03 lab device."""

from taac.abstractions.physical_inventory import EB03_LAB_ASH6
from taac.testconfigs.routing.factories.qual_bgp_update_group.tc1_distribution_correctness import (
    create_bgp_ug_distribution_correctness_test_config,
)
from taac.testconfigs.routing.factories.qual_bgp_update_group.tc3_backpressure import (
    create_bgp_ug_backpressure_test_config,
)


EB03_LAB_ASH6_BGP_TEST_UPDATE_GROUP_CONFIG = (
    create_bgp_ug_distribution_correctness_test_config(EB03_LAB_ASH6)
)
EB03_LAB_ASH6_BGP_UG_BACKPRESSURE_TOPOLOGY_SMOKE_CONFIG = (
    create_bgp_ug_backpressure_test_config(EB03_LAB_ASH6, smoke_only=True)
)


__all__ = [
    "EB03_LAB_ASH6_BGP_TEST_UPDATE_GROUP_CONFIG",
    "EB03_LAB_ASH6_BGP_UG_BACKPRESSURE_TOPOLOGY_SMOKE_CONFIG",
]

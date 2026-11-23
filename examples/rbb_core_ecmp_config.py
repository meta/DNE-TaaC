# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Entry point for reversible Open/R path-selection and core-ECMP tests.

Run through ``scripts/run-rbb-srv6.sh --suite core-ecmp --with-traffic``.
TC-02 and TC-03 validate Open/R Decision plus the FBOSS RIB/FIB. TC-08 also
uses TAAC's default variable TCP port ranges to supply many ECMP hash inputs
and proves that every declared core path carries the BGP traffic item.
"""

from taac.testconfigs.routing.factories.qual_rbb.rbb_core_ecmp_test_config import (
    create_rbb_core_ecmp_test_config,
)

test_config = create_rbb_core_ecmp_test_config()

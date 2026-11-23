# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Entry point for reversible Open/R path-selection and core-ECMP tests.

Run through ``scripts/run-rbb-srv6.sh --suite core-ecmp``.
TC-02 and TC-03 validate Open/R Decision plus the FBOSS RIB/FIB using
device-only checks and reversible core-path metric overrides.
"""

from taac.testconfigs.routing.factories.qual_rbb.rbb_core_ecmp_test_config import (
    create_rbb_core_ecmp_test_config,
)

test_config = create_rbb_core_ecmp_test_config()

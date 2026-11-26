# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""OSS entrypoint for full Phase-2 TC-05/08/113 wire validation."""

from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_wire_test_config import (
    create_rbb_srv6_wire_test_config,
)

test_config = create_rbb_srv6_wire_test_config()

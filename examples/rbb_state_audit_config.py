"""OSS runner wrapper for the two-node RBB common state audits.

The default selection runs only fully covered test-plan profiles and does not
reserve IXIA. Lab wiring comes from ``--circuit-info-csv``; credentials come
from the optional secrets file or the existing ``TAAC_SSH_*`` environment
variables.

Example::

    python3 -m taac.runner.oss_entry_point \
        --test-configs examples/rbb_state_audit_config.py \
        --device-info-csv .taac/device_info.csv \
        --circuit-info-csv .taac/circuit_info.csv \
        --dut "$TAAC_RBB_R1_HOST" "$TAAC_RBB_R2_HOST"
"""

from taac.testconfigs.routing.factories.qual_rbb.rbb_state_audit_test_config import (
    create_rbb_state_audit_test_config,
)

test_config = create_rbb_state_audit_test_config()

# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

"""Apply a TAAC constants YAML onto a constants module.

When ``$TAAC_CONSTANTS_PATH`` is set, each key is written onto the
module as-is. Unset env is a no-op. A constants module opts in by
calling ``apply_overlay(globals())`` after its defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, MutableMapping

import yaml

from taac.runner.oss_exceptions import OSSConfigError

CONSTANTS_PATH_ENV = "TAAC_CONSTANTS_PATH"


def apply_overlay(namespace: MutableMapping[str, Any]) -> None:
    """Write each key from ``$TAAC_CONSTANTS_PATH`` onto ``namespace``.

    Unset → no-op.
    """
    resolved = os.environ.get(CONSTANTS_PATH_ENV)
    if not resolved:
        return

    overlay = yaml.safe_load(Path(resolved).read_text())
    if not isinstance(overlay, dict):
        raise OSSConfigError(
            f"Constants file must be a YAML mapping, got {type(overlay).__name__}"
        )
    namespace.update(overlay)

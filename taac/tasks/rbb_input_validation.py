# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Strict validation helpers for externally supplied RBB task inputs."""

from __future__ import annotations

import re


FBOSS_INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")


def validated_fboss_interface_names(value: object, field: str) -> list[str]:
    """Return exact FBOSS interface names accepted by shell-style drivers.

    Interface names can originate in user-provided topology CSV files.  Do not
    normalize whitespace: accepting a stripped value would hide malformed
    input before it reaches a driver that interpolates the name into a command.
    """
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list")
    interfaces: list[str] = []
    for item in value:
        if not isinstance(item, str) or not FBOSS_INTERFACE_NAME_RE.fullmatch(item):
            raise ValueError(
                f"{field} contains an invalid interface name: {item!r}"
            )
        if item in interfaces:
            raise ValueError(f"{field} contains duplicate interface {item!r}")
        interfaces.append(item)
    return interfaces


__all__ = ["FBOSS_INTERFACE_NAME_RE", "validated_fboss_interface_names"]

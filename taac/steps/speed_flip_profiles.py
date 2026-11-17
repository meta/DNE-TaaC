#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Default cfg.PortProfileID per platform and speed for speed-flip patchers.

Config data, not step logic: a test config that knows its own profile ids
passes ``profile_id`` to the REGISTER_SPEED_FLIP_PATCHER step and never
consults this table.

The id is a request, not a command. ``change_port_speed`` fits each port with
the wire-identical profile that port's own platform mapping offers, because
media families are assigned per cage: the two ends of a mixed-media link carry
different ids for the same signal (optical-family 23 vs copper-family 22 at
100G). One id per platform+speed can therefore satisfy only one end of such a
link on its own.
"""

import typing as t

from neteng.fboss.switch_config.thrift_mutable_types import PortSpeed

_OPTICAL_800G = "PROFILE_800G_8_PAM4_RS544X2N_OPTICAL"
_OPTICAL_400G_4 = "PROFILE_400G_4_PAM4_RS544X2N_OPTICAL"
_OPTICAL_400G_8 = "PROFILE_400G_8_PAM4_RS544X2N_OPTICAL"
_OPTICAL_200G = "PROFILE_200G_4_PAM4_RS544X2N_OPTICAL"
_OPTICAL_100G = "PROFILE_100G_4_NRZ_RS528_OPTICAL"

PLATFORM_SPEED_PROFILE_MAPPING: t.Dict[str, t.Dict[PortSpeed, str]] = {
    # 800G exists only on the /1 subport of a dual cage; flipping /1 to 800G
    # subsumes its /5 mate, which change_port_speed disables.
    "WEDGE800BNHP": {
        PortSpeed.EIGHTHUNDREDG: _OPTICAL_800G,
        PortSpeed.FOURHUNDREDG: _OPTICAL_400G_4,
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "MONTBLANC": {
        PortSpeed.EIGHTHUNDREDG: _OPTICAL_800G,
        PortSpeed.FOURHUNDREDG: _OPTICAL_400G_4,
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "MORGAN800CC": {
        PortSpeed.EIGHTHUNDREDG: _OPTICAL_800G,
        PortSpeed.FOURHUNDREDG: _OPTICAL_400G_4,
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "WEDGE400C": {
        PortSpeed.FOURHUNDREDG: _OPTICAL_400G_8,
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "WEDGE400": {
        PortSpeed.FOURHUNDREDG: _OPTICAL_400G_8,
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "ELBERT": {
        PortSpeed.FOURHUNDREDG: _OPTICAL_400G_8,
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "FUJI": {
        PortSpeed.FOURHUNDREDG: _OPTICAL_400G_8,
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "DARWIN": {
        PortSpeed.FOURHUNDREDG: _OPTICAL_400G_8,
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "YAMP": {
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
    "MINIPACK": {
        PortSpeed.TWOHUNDREDG: _OPTICAL_200G,
        PortSpeed.HUNDREDG: _OPTICAL_100G,
    },
}


def default_profile_id(hardware_type: str, speed_in_mbps: int) -> str:
    """The cfg.PortProfileID NAME this table offers, or a raise naming the gap.

    Raises rather than returning a fallback: registering a patcher with a
    profile the platform does not list programs lanes the far end cannot match,
    which surfaces much later as a link that never comes back.
    """
    # PortSpeed is a thrift-python Enum, not an IntEnum, so the table cannot be
    # indexed with raw Mbps -- it has to be converted first.
    by_speed = PLATFORM_SPEED_PROFILE_MAPPING.get(hardware_type)
    if by_speed is None:
        raise KeyError(
            f"No speed-flip profile table for platform {hardware_type!r} "
            f"(known: {sorted(PLATFORM_SPEED_PROFILE_MAPPING)}). Add its "
            f"profiles to taac/steps/speed_flip_profiles.py, or pass "
            f"profile_id in the step params."
        )
    try:
        speed = PortSpeed(speed_in_mbps)
    except ValueError as e:
        raise KeyError(f"{speed_in_mbps} Mbps is not a cfg.PortSpeed") from e
    if speed not in by_speed:
        raise KeyError(
            f"{hardware_type} has no speed-flip profile for {speed.name} "
            f"(has: {sorted(s.name for s in by_speed)})"
        )
    return by_speed[speed]

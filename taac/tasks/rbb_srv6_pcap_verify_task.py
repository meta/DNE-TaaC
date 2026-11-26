# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Decode captured RBB SRv6 outer IPv6/uSID packets without extra packages."""

from __future__ import annotations

import ipaddress
import os
import struct
import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_ETHERNET_LINKTYPE = 1
_VLAN_TYPES = frozenset((0x8100, 0x88A8, 0x9100))


def _classic_pcap_packets(data: bytes) -> t.Iterator[bytes]:
    magics = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    endian = magics.get(data[:4])
    if endian is None or len(data) < 24:
        raise ValueError("unsupported or truncated classic PCAP header")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != _ETHERNET_LINKTYPE:
        raise ValueError(f"capture link type {linktype} is not Ethernet")
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("truncated classic PCAP record header")
        captured = struct.unpack_from(endian + "I", data, offset + 8)[0]
        offset += 16
        if offset + captured > len(data):
            raise ValueError("truncated classic PCAP packet")
        yield data[offset : offset + captured]
        offset += captured


def _pcapng_packets(data: bytes) -> t.Iterator[bytes]:
    offset = 0
    endian: str | None = None
    linktypes: list[int] = []
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated PCAPNG block header")
        block_type_bytes = data[offset : offset + 4]
        if block_type_bytes == b"\x0a\x0d\x0d\x0a":
            if offset + 16 > len(data):
                raise ValueError("truncated PCAPNG section header")
            bom = data[offset + 8 : offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("invalid PCAPNG byte-order magic")
            linktypes = []
        if endian is None:
            raise ValueError("PCAPNG packet appears before a section header")
        block_type, block_length = struct.unpack_from(endian + "II", data, offset)
        if block_length < 12 or block_length % 4 or offset + block_length > len(data):
            raise ValueError("invalid PCAPNG block length")
        trailer = struct.unpack_from(
            endian + "I", data, offset + block_length - 4
        )[0]
        if trailer != block_length:
            raise ValueError("PCAPNG block length trailer mismatch")
        if block_type == 1:
            if block_length < 20:
                raise ValueError("truncated PCAPNG interface block")
            linktypes.append(struct.unpack_from(endian + "H", data, offset + 8)[0])
        elif block_type == 6:
            if block_length < 32:
                raise ValueError("truncated PCAPNG enhanced packet block")
            interface_id, captured = struct.unpack_from(
                endian + "II", data, offset + 8
            )[0], struct.unpack_from(endian + "I", data, offset + 20)[0]
            if interface_id >= len(linktypes):
                raise ValueError("PCAPNG packet references an unknown interface")
            if linktypes[interface_id] != _ETHERNET_LINKTYPE:
                raise ValueError("PCAPNG packet interface is not Ethernet")
            start = offset + 28
            if start + captured > offset + block_length - 4:
                raise ValueError("truncated PCAPNG enhanced packet")
            yield data[start : start + captured]
        elif block_type == 3:
            if not linktypes or linktypes[0] != _ETHERNET_LINKTYPE:
                raise ValueError("PCAPNG simple packet interface is not Ethernet")
            yield data[offset + 12 : offset + block_length - 4]
        offset += block_length


def captured_packets(data: bytes) -> tuple[bytes, ...]:
    """Return Ethernet frames from classic PCAP or PCAPNG bytes."""
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return tuple(_pcapng_packets(data))
    return tuple(_classic_pcap_packets(data))


def _ipv6_header(
    frame: bytes,
) -> tuple[
    ipaddress.IPv6Address, ipaddress.IPv6Address, int, int, bytes
] | None:
    if len(frame) < 14:
        return None
    offset = 14
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    while ether_type in _VLAN_TYPES:
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ether_type != 0x86DD or len(frame) < offset + 40:
        return None
    header = frame[offset : offset + 40]
    if header[0] >> 4 != 6:
        return None
    payload_length = struct.unpack_from("!H", header, 4)[0]
    if len(frame) < offset + 40 + payload_length:
        return None
    source = ipaddress.IPv6Address(header[8:24])
    destination = ipaddress.IPv6Address(header[24:40])
    return source, destination, header[6], header[7], frame[offset + 40 :]


class RbbSrv6PcapVerifyTask(BaseTask):
    """Require actual IPv6-in-IPv6 packets with the exact packed uSID DA."""

    NAME = "rbb_srv6_pcap_verify"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    async def run(self, params: dict[str, t.Any]) -> None:
        allowed = {
            "pcap_path",
            "expected_outer_source",
            "expected_outer_destination",
            "expected_inner_source",
            "expected_inner_destination_prefix",
            "locator",
            "expected_usids",
            "min_packets",
            "gate",
        }
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(f"rbb_srv6_pcap_verify unsupported fields: {unknown}")
        path = str(params.get("pcap_path") or "").strip()
        if not path or not os.path.isabs(path):
            raise ValueError("pcap_path must be an absolute path")
        try:
            outer_source = ipaddress.IPv6Address(
                str(params["expected_outer_source"])
            )
            outer_destination = ipaddress.IPv6Address(
                str(params["expected_outer_destination"])
            )
            inner_source = ipaddress.IPv6Address(
                str(params["expected_inner_source"])
            )
            inner_destination = ipaddress.IPv6Network(
                str(params["expected_inner_destination_prefix"]), strict=True
            )
            locator = ipaddress.IPv6Network(str(params["locator"]), strict=False)
        except (KeyError, ValueError) as error:
            raise ValueError(f"invalid SRv6 capture expectation: {error}") from error
        expected_usids = params.get("expected_usids")
        if not isinstance(expected_usids, list) or not expected_usids:
            raise ValueError("expected_usids must be a non-empty list")
        normalized_usids = tuple(
            ipaddress.IPv6Address(str(sid)) for sid in expected_usids
        )
        min_packets = params.get("min_packets", 1)
        if (
            isinstance(min_packets, bool)
            or not isinstance(min_packets, int)
            or min_packets < 1
        ):
            raise ValueError("min_packets must be a positive integer")
        if outer_destination not in locator:
            raise ValueError("expected outer destination is outside the locator")

        # Exact carrier equality proves locator bits, ordered 16-bit functions,
        # and zero termination.  Independently decode the function vector so a
        # malformed expectation cannot accidentally weaken the check.
        shift = 128 - locator.prefixlen - 16
        if shift < 0 or locator.prefixlen % 16:
            raise ValueError("locator must leave aligned 16-bit uSID functions")
        capacity = (128 - locator.prefixlen) // 16
        if len(normalized_usids) > capacity:
            raise ValueError("expected_usids do not fit in the locator carrier")
        trailing_mask = (1 << shift) - 1 if shift else 0
        if any(
            sid not in locator
            or (int(sid) & trailing_mask) != 0
            or ((int(sid) >> shift) & 0xFFFF) == 0
            for sid in normalized_usids
        ):
            raise ValueError(
                "each expected uSID must contain one non-zero 16-bit function "
                "inside the locator"
            )
        expected_functions = tuple(
            (int(sid) >> shift) & 0xFFFF for sid in normalized_usids
        )
        carrier_functions = tuple(
            (int(outer_destination) >> (128 - locator.prefixlen - 16 * (index + 1)))
            & 0xFFFF
            for index in range(len(expected_functions))
        )
        trailing_bits = 128 - locator.prefixlen - 16 * len(expected_functions)
        if carrier_functions != expected_functions or (
            trailing_bits > 0 and int(outer_destination) & ((1 << trailing_bits) - 1)
        ):
            raise ValueError(
                "expected outer destination is not the ordered, zero-terminated "
                "uSID carrier described by locator/expected_usids"
            )
        try:
            with open(path, "rb") as capture:
                packets = captured_packets(capture.read())
        except (OSError, ValueError) as error:
            raise TestCaseFailure(
                f"cannot read SRv6 capture {path}: {error}"
            ) from error

        matches = 0
        observations: set[tuple[str, str, int, int]] = set()
        for packet in packets:
            outer = _ipv6_header(packet)
            if outer is None:
                continue
            source, destination, next_header, hop_limit, payload = outer
            observations.add((str(source), str(destination), next_header, hop_limit))
            if (
                source != outer_source
                or destination != outer_destination
                or next_header != 41
                or hop_limit < 1
            ):
                continue
            # Reduced SRv6 encapsulation must carry the original IPv6 packet.
            if len(payload) < 40 or payload[0] >> 4 != 6:
                continue
            embedded_source = ipaddress.IPv6Address(payload[8:24])
            embedded_destination = ipaddress.IPv6Address(payload[24:40])
            if (
                embedded_source != inner_source
                or embedded_destination not in inner_destination
            ):
                continue
            matches += 1
        gate = str(params.get("gate") or self.NAME)
        if matches < min_packets:
            raise TestCaseFailure(
                f"[{gate}] capture has {matches} matching SRv6 packets; required "
                f"{min_packets}. IPv6 observations={sorted(observations)!r}"
            )
        self.logger.info(
            f"[{gate}] decoded {matches} SRv6 packets: outer SA={outer_source}, "
            f"carrier={outer_destination}, functions={expected_functions}, "
            f"inner={inner_source}->{inner_destination}"
        )


__all__ = ["RbbSrv6PcapVerifyTask", "captured_packets"]

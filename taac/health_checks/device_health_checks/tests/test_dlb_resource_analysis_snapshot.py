# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""The ECMP-snapshot cross-check fails the DLB analysis only when a DLB
ceiling is asserted; without flowlet/DLB config the snapshot is every ECMP
group on the box and says nothing about the DLB-managed pool."""

import socket
from types import SimpleNamespace

from taac.health_checks.device_health_checks.dlb_resource_analysis import analyze


def _route(prefix, nexthops):
    net, plen = prefix.split("/")
    return SimpleNamespace(
        dest=SimpleNamespace(
            ip=SimpleNamespace(addr=socket.inet_pton(socket.AF_INET6, net)),
            prefixLength=int(plen),
        ),
        nextHops=[
            SimpleNamespace(address=SimpleNamespace(addr=socket.inet_pton(socket.AF_INET6, nh)))
            for nh in nexthops
        ],
    )


def _ip_ntop(addr):
    return socket.inet_ntop(socket.AF_INET6, addr)


ROUTES = [
    _route("5000:dd::/64", ["2001:db8::1", "2001:db8::2"]),
    _route("5000:dd:1::/64", ["2001:db8::3", "2001:db8::4"]),
    _route("5000:ee::/64", ["2001:db8::5", "2001:db8::6"]),
    _route("2401::/64", ["2001:db8::7", "2001:db8::8"]),
]
PATTERNS = ["5000:dd::", "5000:ee::"]
COUNTS = {"5000:dd prefixes": {"total": 2}, "5000:ee prefixes": {"total": 1}}


def test_snapshot_mismatch_is_informational_without_a_dlb_ceiling():
    result = analyze(ROUTES, _ip_ntop, PATTERNS, COUNTS, {}, snapshot_count=4)
    assert result.passed
    assert result.snapshot_match is False
    assert "MISMATCH" in result.message


def test_snapshot_mismatch_fails_when_a_dlb_ceiling_is_asserted():
    result = analyze(ROUTES, _ip_ntop, PATTERNS, COUNTS, {"dlb": 4}, snapshot_count=4)
    assert not result.passed
    assert "Snapshot mismatch" in result.message


def test_snapshot_match_passes_either_way():
    for totals in ({}, {"dlb": 4}):
        result = analyze(ROUTES, _ip_ntop, PATTERNS, COUNTS, totals, snapshot_count=2)
        assert result.passed, totals

# Copyright (c) Meta Platforms, Inc. and affiliates.
"""verify_protocols must allow for sessions the CONFIG says never start.

A device group created with `enable=False` reports its sessions as notStarted
for the whole run, so the allowance comes from the config, per protocol row.
Rows the config does not name must be fully up. Not solved by walking the
topology, which is slower than the stat view.
"""

import os
import threading
import typing as t
import unittest
from unittest.mock import MagicMock, patch

from ixia.ixia import types as ixia_types
from taac.ixia.ixia import Ixia, IxiaOperationTimeoutError

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_IXIA_MODULE = "taac.ixia.ixia" if TAAC_OSS else "neteng.test_infra.dne.taac.ixia.ixia"

_V4 = "v4"
_V6 = "v6"
_V4_BGP = "v4_bgp"
_V6_BGP = "v6_bgp"


def _bgp(family: "ixia_types.IpAddressFamily") -> "ixia_types.BgpConfig":
    return ixia_types.BgpConfig(
        ip_address_family=family, bgp_peer_config=ixia_types.BgpPeerConfig()
    )


def _dg(
    enable: bool, multiplier: t.Optional[int], *stacks: str
) -> ixia_types.DeviceGroupConfig:
    """The runtime `ixia.ixia.types.DeviceGroupConfig` with the given stacks."""
    has_bgp = _V4_BGP in stacks or _V6_BGP in stacks
    kwargs: t.Dict[str, t.Any] = dict(
        device_group_index=0,
        enable=enable,
        ip_addresses_config=ixia_types.IpAddresses(
            ipv4_addresses_config=(
                ixia_types.IPv4AddressInfo() if _V4 in stacks else None
            ),
            ipv6_addresses_config=(
                ixia_types.IPv6AddressInfo() if _V6 in stacks else None
            ),
        ),
        bgp_config=(
            ixia_types.BgpConfigInfo(
                bgp_v4_config=(
                    _bgp(ixia_types.IpAddressFamily.IPV4) if _V4_BGP in stacks else None
                ),
                bgp_v6_config=(
                    _bgp(ixia_types.IpAddressFamily.IPV6) if _V6_BGP in stacks else None
                ),
            )
            if has_bgp
            else None
        ),
    )
    if multiplier is not None:
        kwargs["multiplier"] = multiplier
    return ixia_types.DeviceGroupConfig(**kwargs)


def _ixia_with_groups(groups: t.List[ixia_types.DeviceGroupConfig]) -> Ixia:
    obj = Ixia.__new__(Ixia)
    obj.logger = MagicMock()
    # `__new__` skips `__init__`; a real RLock so the lock path is exercised.
    obj._snapshot_lock = threading.RLock()
    obj.ixia_config = ixia_types.IxiaConfig(
        port_configs=[
            ixia_types.PortConfig(port_name="p1", device_group_configs=groups)
        ]
    )
    return obj


def _row(protocol_type: str, not_started: int = 0, down: int = 0) -> t.Dict[str, str]:
    """A Protocols Summary row. Stat-view values arrive as CSV strings."""
    return {
        "Protocol Type": protocol_type,
        "Sessions Not Started": str(not_started),
        "Sessions Down": str(down),
    }


class ExpectedNotStartedByProtocolTest(unittest.TestCase):
    def test_disabled_v6_bgp_group_excuses_only_the_v6_rows(self):
        """v6 addresses + v6 BGP, disabled, multiplier 50."""
        ix = _ixia_with_groups([_dg(False, 50, _V6, _V6_BGP)])
        self.assertEqual(
            {"BGP+ Peer": 50, "IPv6": 50}, ix._expected_not_started_by_protocol()
        )

    def test_enabled_groups_are_not_excused(self):
        ix = _ixia_with_groups([_dg(True, 50, _V6, _V6_BGP)])
        self.assertEqual({}, ix._expected_not_started_by_protocol())

    def test_disabled_v4_group_attributes_to_the_v4_rows(self):
        ix = _ixia_with_groups([_dg(False, 8, _V4, _V4_BGP)])
        self.assertEqual(
            {"BGP Peer": 8, "IPv4": 8}, ix._expected_not_started_by_protocol()
        )

    def test_multiple_disabled_groups_sum_per_protocol(self):
        ix = _ixia_with_groups(
            [
                _dg(False, 5, _V6),
                _dg(False, 7, _V6, _V6_BGP),
            ]
        )
        self.assertEqual(
            {"IPv6": 12, "BGP+ Peer": 7}, ix._expected_not_started_by_protocol()
        )

    def test_default_multiplier_is_one(self):
        ix = _ixia_with_groups([_dg(False, None, _V6)])
        self.assertEqual({"IPv6": 1}, ix._expected_not_started_by_protocol())

    def test_no_config_is_empty_not_a_crash(self):
        obj = Ixia.__new__(Ixia)
        obj.logger = MagicMock()
        obj.ixia_config = None
        self.assertEqual({}, obj._expected_not_started_by_protocol())

    def test_group_without_bgp_config_counts_only_address_rows(self):
        ix = _ixia_with_groups([_dg(False, 3, _V4, _V6)])
        self.assertEqual({"IPv4": 3, "IPv6": 3}, ix._expected_not_started_by_protocol())


class ProtocolsSummaryFailuresTest(unittest.TestCase):
    def test_healthy_rows_have_no_failures(self):
        rows = [_row("BGP Peer"), _row("IPv4"), _row("IPv6")]
        self.assertEqual([], Ixia._protocols_summary_failures(rows, {}))

    def test_not_started_within_the_allowance_passes(self):
        rows = [_row("BGP+ Peer", not_started=50)]
        self.assertEqual([], Ixia._protocols_summary_failures(rows, {"BGP+ Peer": 50}))

    def test_not_started_above_the_allowance_fails(self):
        rows = [_row("BGP+ Peer", not_started=51)]
        failures = Ixia._protocols_summary_failures(rows, {"BGP+ Peer": 50})
        self.assertEqual(1, len(failures))
        self.assertIn("BGP+ Peer", failures[0])
        self.assertIn("51", failures[0])

    def test_an_allowance_does_not_leak_to_another_protocol(self):
        """The v4 row must not be excused by a v6-only device group."""
        rows = [_row("BGP Peer", not_started=50)]
        failures = Ixia._protocols_summary_failures(rows, {"BGP+ Peer": 50})
        self.assertEqual(1, len(failures))
        self.assertIn("BGP Peer", failures[0])

    def test_any_session_down_fails(self):
        rows = [_row("IPv6", down=1)]
        failures = Ixia._protocols_summary_failures(rows, {"IPv6": 50})
        self.assertEqual(1, len(failures))
        self.assertIn("down", failures[0])

    def test_ptp_rows_are_checked(self):
        """PTP rows are checked like any other; a PTP row down is a real failure."""
        rows = [_row("PTP", down=8)]
        failures = Ixia._protocols_summary_failures(rows, {})
        self.assertEqual(1, len(failures))
        self.assertIn("PTP", failures[0])

    def test_blank_stat_values_count_as_zero(self):
        rows = [
            {"Protocol Type": "IPv6", "Sessions Not Started": "", "Sessions Down": ""}
        ]
        self.assertEqual([], Ixia._protocols_summary_failures(rows, {}))


class VerifyProtocolsTest(unittest.TestCase):
    def _ixia(self, rows_sequence: t.List[t.List[t.Dict[str, str]]]) -> Ixia:
        ix = _ixia_with_groups([_dg(False, 50, _V6, _V6_BGP)])
        ix.skip_ixia_protocol_verification = False
        ix.is_uhd_chassis = False
        ix.ixnetwork = MagicMock()
        self._snapshots = 0

        summary = MagicMock()
        remaining = list(rows_sequence)

        def _rows():
            self._snapshots += 1
            return remaining.pop(0) if len(remaining) > 1 else remaining[0]

        type(summary).Rows = property(lambda _self: _rows())
        self._summary = summary
        return ix

    def _run(self, ix: Ixia) -> None:
        with patch(f"{_IXIA_MODULE}.IxnStatViewAssistant", return_value=self._summary):
            ix.verify_protocols()

    def test_healthy_setup_passes_on_a_single_snapshot(self):
        """Every Rows access is a full CSV export (slow at scale), so the
        number of snapshots is the whole cost of this check."""
        ix = self._ixia([[_row("BGP+ Peer", not_started=50), _row("IPv4")]])
        self._run(ix)
        self.assertEqual(1, self._snapshots)

    def test_it_waits_for_sessions_to_come_up(self):
        ix = self._ixia([[_row("IPv6", down=4)], [_row("IPv6", not_started=50)]])
        with patch(f"{_IXIA_MODULE}.time.sleep"):
            self._run(ix)
        self.assertEqual(2, self._snapshots)

    def test_persistent_failure_raises_naming_the_protocol(self):
        ix = self._ixia([[_row("BGP Peer", down=3)]])
        with (
            patch(f"{_IXIA_MODULE}.time.sleep"),
            patch(f"{_IXIA_MODULE}.time.monotonic", side_effect=[0, 10_000, 20_000]),
        ):
            with self.assertRaises(IxiaOperationTimeoutError) as caught:
                self._run(ix)
        self.assertIn("BGP Peer", str(caught.exception))

    def test_skip_flag_short_circuits(self):
        ix = self._ixia([[_row("BGP Peer", down=3)]])
        ix.skip_ixia_protocol_verification = True
        ix.ixia_protocol_verification_timeout = 0
        self._run(ix)
        self.assertEqual(0, self._snapshots)


if __name__ == "__main__":
    unittest.main()

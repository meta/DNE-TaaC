# Copyright (c) Meta Platforms, Inc. and affiliates.

import itertools
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from taac.ixia.ixia import (
    _is_resolved_gateway_mac,
    Ixia,
    IxiaOperationStateError,
)
from parameterized import parameterized

_IXIA_TIME = "neteng.test_infra.dne.taac.ixia.ixia.time"
_MAC = "00:1c:73:aa:bb:cc"
_UNRESOLVED = "Unresolved"


def _ixia() -> Ixia:
    with patch.object(Ixia, "__init__", lambda self: None):
        instance = Ixia()
    instance.logger = MagicMock()
    instance.ixnetwork = MagicMock()
    instance.ixnetwork.Globals.AppErrors.find.return_value.Error.find.return_value = []
    return instance


def _stack(name: str, *reads: list[object]) -> MagicMock:
    """An IP stack whose ResolvedGatewayMac changes only on refresh(), like restpy.

    The first read is the state before the gate re-sends ARP/NS; the last read
    repeats for every later poll.
    """
    stack = MagicMock(name=name)
    stack.Count = len(reads[0])
    stack.ResolvedGatewayMac = [_UNRESOLVED] * len(reads[0])
    fresh = itertools.chain(reads, itertools.repeat(reads[-1]))

    def refresh() -> MagicMock:
        stack.ResolvedGatewayMac = next(fresh)
        return stack

    stack.refresh.side_effect = refresh
    return stack


def _device_group(
    name: str,
    ipv4: list[MagicMock] | None = None,
    ipv6: list[MagicMock] | None = None,
) -> MagicMock:
    ethernet = MagicMock()
    ethernet.Ipv4.find.return_value = ipv4 or []
    ethernet.Ipv6.find.return_value = ipv6 or []
    device_group = MagicMock()
    device_group.Name = name
    device_group.Ethernet.find.return_value = [ethernet]
    return device_group


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class RefreshAndVerifyGatewayResolutionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.ixia = _ixia()
        self.logger = MagicMock()
        self.ixia.logger = self.logger
        self.clock = _FakeClock()
        patcher = patch(
            _IXIA_TIME,
            MagicMock(monotonic=self.clock.monotonic, sleep=self.clock.sleep),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _use_device_groups(self, *device_groups: MagicMock) -> None:
        self.ixia.find_device_groups = MagicMock(return_value=list(device_groups))

    def _verify(self, *names: str) -> None:
        self.ixia.refresh_and_verify_gateway_resolution(
            device_group_names=list(names), timeout_seconds=9
        )

    def test_all_resolved_sends_arp_and_ns_once_without_waiting(self) -> None:
        ipv6 = _stack("ipv6", [_MAC, _MAC])
        ipv4 = _stack("ipv4", [_MAC, _MAC])
        self._use_device_groups(
            _device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]),
            _device_group("DEVICE_GROUP_IPV4_IBGP", ipv4=[ipv4]),
        )

        self._verify("DEVICE_GROUP_IPV6_IBGP", "DEVICE_GROUP_IPV4_IBGP")

        ipv6.SendNs.assert_called_once_with()
        ipv4.SendArp.assert_called_once_with()
        ipv6.SendArp.assert_not_called()
        ipv4.SendNs.assert_not_called()
        self.assertEqual([], self.clock.sleeps)
        self.logger.warning.assert_not_called()

    def test_logs_gateways_unresolved_before_refresh(self) -> None:
        ipv6 = _stack("ipv6", [_UNRESOLVED, _MAC, ""], [_MAC, _MAC, _MAC])
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        self._verify("DEVICE_GROUP_IPV6_IBGP")

        self.logger.warning.assert_called_once()
        self.assertIn(
            "DEVICE_GROUP_IPV6_IBGP IPv6 2/3 [1;3]",
            self.logger.warning.call_args.args[0],
        )
        ipv6.SendNs.assert_called_once_with()
        self.assertEqual([], self.clock.sleeps)

    def test_reads_gateway_state_before_and_after_refresh(self) -> None:
        events: list[str] = []
        ipv6 = _stack("ipv6", [_UNRESOLVED], [_MAC])
        refresh = ipv6.refresh.side_effect

        def recording_refresh() -> MagicMock:
            events.append("refresh")
            return refresh()

        ipv6.refresh.side_effect = recording_refresh
        ipv6.SendNs.side_effect = lambda: events.append("send")
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        self._verify("DEVICE_GROUP_IPV6_IBGP")

        self.assertEqual(["refresh", "send", "refresh"], events)

    def test_waits_for_late_resolution_without_resending(self) -> None:
        ipv6 = _stack(
            "ipv6",
            [_UNRESOLVED] * 3,
            [_UNRESOLVED, _MAC, "00:00:00:00:00:00"],
            [_MAC, _MAC, "00:00:00:00:00:00"],
            [_MAC, _MAC, _MAC],
        )
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        self._verify("DEVICE_GROUP_IPV6_IBGP")

        ipv6.SendNs.assert_called_once_with()
        self.assertEqual([3, 3], self.clock.sleeps)

    def test_partial_resolution_times_out_with_diagnostics(self) -> None:
        ipv6 = _stack("ipv6", [_MAC, _UNRESOLVED, _MAC, ""])
        ipv6.Address.Values = ["2001:db8::11", "2001:db8::13", "2001:db8::15", "x"]
        ipv6.GatewayIp.Values = ["2001:db8::10", "2001:db8::12", "2001:db8::14", "y"]
        ipv6.SessionStatus = ["up", "down", "up", "down"]
        ipv6.SessionInfo = ["none", "resolveMacFailed", "none", "resolveMacFailed"]
        ipv4 = _stack("ipv4", [_MAC, _MAC])
        self._use_device_groups(
            _device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]),
            _device_group("DEVICE_GROUP_IPV4_IBGP", ipv4=[ipv4]),
        )

        with self.assertRaises(IxiaOperationStateError) as raised:
            self._verify("DEVICE_GROUP_IPV6_IBGP", "DEVICE_GROUP_IPV4_IBGP")

        message = str(raised.exception)
        self.assertIn("DEVICE_GROUP_IPV6_IBGP IPv6: 2/4 unresolved [2;4]", message)
        self.assertIn("Address=['2001:db8::13', 'x']", message)
        self.assertIn("GatewayIp=['2001:db8::12', 'y']", message)
        self.assertIn("ResolvedGatewayMac=['Unresolved', '']", message)
        self.assertIn("SessionStatus={'down': 2}", message)
        self.assertIn("SessionInfo={'resolveMacFailed': 2}", message)
        self.assertIn("Ixia server errors: []", message)
        self.assertNotIn("DEVICE_GROUP_IPV4_IBGP IPv4", message)
        ipv6.SendNs.assert_called_once_with()
        ipv4.SendArp.assert_called_once_with()
        self.assertGreaterEqual(self.clock.now, 9)

    def test_sessions_that_never_start_fail_closed_before_sending(self) -> None:
        ipv6 = _stack("ipv6", [_UNRESOLVED, _MAC])
        ipv6.SessionStatus = ["notStarted", "up"]
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        with self.assertRaisesRegex(
            IxiaOperationStateError,
            r"IP sessions not started 9s into the gateway check: "
            r"DEVICE_GROUP_IPV6_IBGP IPv6 1/2 notStarted \[1\]",
        ):
            self._verify("DEVICE_GROUP_IPV6_IBGP")

        ipv6.SendNs.assert_not_called()
        self.assertEqual([3, 3, 3], self.clock.sleeps)

    def test_waits_for_ip_sessions_to_start_before_sending(self) -> None:
        events: list[str] = []
        ipv6 = _stack("ipv6", [_UNRESOLVED] * 2, [_UNRESOLVED] * 2, [_MAC] * 2)
        statuses = itertools.chain(
            [["notStarted", "notStarted"]], itertools.repeat(["up", "up"])
        )
        refresh = ipv6.refresh.side_effect

        def starting_refresh() -> MagicMock:
            events.append("refresh")
            ipv6.SessionStatus = next(statuses)
            return refresh()

        ipv6.refresh.side_effect = starting_refresh
        ipv6.SendNs.side_effect = lambda: events.append("send")
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        self._verify("DEVICE_GROUP_IPV6_IBGP")

        self.assertEqual(["refresh", "refresh", "send", "refresh"], events)
        self.assertEqual([3], self.clock.sleeps)
        self.assertIn(
            "Waiting for IP sessions to start before ARP/NS: "
            "DEVICE_GROUP_IPV6_IBGP IPv6 2/2 notStarted [1-2]",
            self.logger.info.call_args_list[0].args[0],
        )
        self.assertIn(
            "DEVICE_GROUP_IPV6_IBGP IPv6 2/2 [1-2]",
            self.logger.warning.call_args.args[0],
        )

    def test_short_value_lists_degrade_per_session(self) -> None:
        ipv6 = _stack("ipv6", [_MAC, _UNRESOLVED, _MAC, ""])
        ipv6.Address.Values = ["2001:db8::11", "2001:db8::13"]
        ipv6.GatewayIp.Values = ["2001:db8::10"]
        ipv6.SessionStatus = ["up", "down", "up"]
        ipv6.SessionInfo = []
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        with self.assertRaises(IxiaOperationStateError) as raised:
            self._verify("DEVICE_GROUP_IPV6_IBGP")

        message = str(raised.exception)
        self.assertIn("2/4 unresolved [2;4]", message)
        self.assertIn("Address=['2001:db8::13', 'missing']", message)
        self.assertIn("GatewayIp=['2001:db8::10', '2001:db8::10']", message)
        self.assertIn("ResolvedGatewayMac=['Unresolved', '']", message)
        self.assertIn("SessionStatus={'down': 1, 'missing': 1}", message)
        self.assertIn("SessionInfo={'missing': 2}", message)

    def test_unreadable_diagnostic_keeps_its_error_message(self) -> None:
        ipv6 = _stack("ipv6", [_UNRESOLVED])
        # Readable while the gate waits for sessions to start, unreadable when
        # the failure diagnostics read it again.
        type(ipv6).SessionStatus = PropertyMock(
            side_effect=[["up"], RuntimeError("session gone")]
        )
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        with self.assertRaisesRegex(
            IxiaOperationStateError,
            r"SessionStatus=unavailable \(RuntimeError: session gone\)",
        ):
            self._verify("DEVICE_GROUP_IPV6_IBGP")

    def test_missing_sessions_in_mac_list_count_as_unresolved(self) -> None:
        ipv6 = _stack("ipv6", [_MAC])
        ipv6.Count = 3
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        with self.assertRaisesRegex(IxiaOperationStateError, r"2/3 unresolved \[2-3\]"):
            self._verify("DEVICE_GROUP_IPV6_IBGP")

    def test_missing_device_group_fails_before_sending(self) -> None:
        ipv6 = _stack("ipv6", [_MAC])
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        with self.assertRaisesRegex(
            IxiaOperationStateError,
            "one device group named DEVICE_GROUP_IPV4_IBGP, found 0",
        ):
            self._verify("DEVICE_GROUP_IPV6_IBGP", "DEVICE_GROUP_IPV4_IBGP")

        ipv6.SendNs.assert_not_called()

    def test_duplicate_device_group_name_fails_closed(self) -> None:
        first = _stack("a", [_MAC])
        second = _stack("b", [_MAC])
        self._use_device_groups(
            _device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[first]),
            _device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[second]),
        )

        with self.assertRaisesRegex(IxiaOperationStateError, "found 2"):
            self._verify("DEVICE_GROUP_IPV6_IBGP")

        first.SendNs.assert_not_called()
        second.SendNs.assert_not_called()

    def test_device_group_without_ip_stack_fails_closed(self) -> None:
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP"))

        with self.assertRaisesRegex(IxiaOperationStateError, "no IPv4 or IPv6 stack"):
            self._verify("DEVICE_GROUP_IPV6_IBGP")

    def test_empty_device_group_names_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one device group"):
            self._verify()

    def test_send_error_propagates_before_any_wait(self) -> None:
        ipv6 = _stack("ipv6", [_MAC])
        ipv6.SendNs.side_effect = RuntimeError("operation failed")
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        with self.assertRaisesRegex(RuntimeError, "operation failed"):
            self._verify("DEVICE_GROUP_IPV6_IBGP")

        self.assertEqual(1, ipv6.refresh.call_count)
        self.assertEqual([], self.clock.sleeps)

    def test_read_error_while_polling_propagates_unwrapped(self) -> None:
        ipv6 = _stack("ipv6", [_UNRESOLVED])
        reads = iter([None, RuntimeError("connection reset by peer")])

        def refresh() -> MagicMock:
            error = next(reads)
            if error is not None:
                raise error
            return ipv6

        ipv6.refresh.side_effect = refresh
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        with self.assertRaisesRegex(RuntimeError, "connection reset by peer"):
            self._verify("DEVICE_GROUP_IPV6_IBGP")

        ipv6.SendNs.assert_called_once_with()

    def test_interrupt_during_wait_propagates_unwrapped(self) -> None:
        ipv6 = _stack("ipv6", [_UNRESOLVED])
        self._use_device_groups(_device_group("DEVICE_GROUP_IPV6_IBGP", ipv6=[ipv6]))

        def interrupted_sleep(_seconds: float) -> None:
            raise KeyboardInterrupt

        with patch(
            _IXIA_TIME,
            MagicMock(monotonic=self.clock.monotonic, sleep=interrupted_sleep),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self._verify("DEVICE_GROUP_IPV6_IBGP")

        ipv6.SendNs.assert_called_once_with()


class ResolvedGatewayMacTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("colon", "00:1c:73:aa:bb:cc"),
            ("upper_dash", "00-1C-73-AA-BB-CC"),
            ("dotted", "001c.73aa.bbcc"),
        ]
    )
    def test_mac_counts_as_resolved(self, _name: str, value: str) -> None:
        self.assertTrue(_is_resolved_gateway_mac(value))

    @parameterized.expand(
        [
            ("placeholder", _UNRESOLVED),
            ("zero", "00:00:00:00:00:00"),
            ("empty", ""),
            ("none", None),
            ("short", "00:1c:73:aa:bb"),
        ]
    )
    def test_value_counts_as_unresolved(self, _name: str, value: object) -> None:
        self.assertFalse(_is_resolved_gateway_mac(value))

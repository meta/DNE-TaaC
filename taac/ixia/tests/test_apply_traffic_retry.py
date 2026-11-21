# Copyright (c) Meta Platforms, Inc. and affiliates.

import os
import unittest
from unittest.mock import MagicMock, patch

from ixnetwork_restpy.errors import BadRequestError
from taac.ixia.ixia import Ixia

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_LIB_UTILS_MODULE = (
    "taac.utils.oss_taac_lib_utils"
    if TAAC_OSS
    else "neteng.test_infra.dne.taac.utils.oss_taac_lib_utils"
)


def _make_ixia() -> Ixia:
    ixia = object.__new__(Ixia)
    ixia.ixnetwork = MagicMock()
    traffic_item = MagicMock()
    traffic_item.Enabled = True
    ixia.ixnetwork.Traffic.TrafficItem.find.return_value = [traffic_item]
    ixia.logger = MagicMock()
    return ixia


@patch(f"{_LIB_UTILS_MODULE}.time.sleep")
class ApplyTrafficRetryTest(unittest.TestCase):
    def test_retries_transient_apply_rejection(self, _sleep: MagicMock) -> None:
        ixia = _make_ixia()
        ixia.ixnetwork.Traffic.Apply.side_effect = [
            BadRequestError(" Error in L2/L3 Traffic Apply", 400),
            None,
        ]

        ixia.apply_traffic()

        self.assertEqual(ixia.ixnetwork.Traffic.Apply.call_count, 2)

    def test_raises_after_retries_exhausted(self, _sleep: MagicMock) -> None:
        ixia = _make_ixia()
        ixia.ixnetwork.Traffic.Apply.side_effect = BadRequestError(
            " Error in L2/L3 Traffic Apply", 400
        )

        with self.assertRaises(BadRequestError):
            ixia.apply_traffic()

        self.assertEqual(ixia.ixnetwork.Traffic.Apply.call_count, 3)

    def test_does_not_retry_other_errors(self, _sleep: MagicMock) -> None:
        ixia = _make_ixia()
        ixia.ixnetwork.Traffic.Apply.side_effect = RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            ixia.apply_traffic()

        self.assertEqual(ixia.ixnetwork.Traffic.Apply.call_count, 1)

    def test_skips_apply_when_no_items_enabled(self, _sleep: MagicMock) -> None:
        ixia = _make_ixia()
        ixia.ixnetwork.Traffic.TrafficItem.find.return_value[0].Enabled = False

        ixia.apply_traffic()

        ixia.ixnetwork.Traffic.Apply.assert_not_called()


def _app_error(level: str, name: str, description: str, modified: str) -> MagicMock:
    error = MagicMock()
    error.ErrorLevel = level
    error.Name = name
    error.Description = description
    error.LastModified = modified
    return error


# The entries IxNetwork reports when Apply cannot build any stream because the
# destination MACs do not resolve.
_UNRESOLVED_DESTINATION_ERRORS = [
    _app_error(
        "kWarning",
        "Not all the Packets could be Generated",
        "One or more destination MACs or VPNs are invalid or unreachable and "
        "the packets configured to be sent to them were not created",
        "01/01/2024 00:00:01",
    ),
    _app_error(
        "kError",
        "No Flow Groups",
        "Cannot apply traffic because there are no flow groups after removing "
        "failed destination MAC addresses.",
        "01/01/2024 00:00:09",
    ),
]


@patch(f"{_LIB_UTILS_MODULE}.time.sleep")
class ApplyTrafficUnresolvedDestinationsTest(unittest.TestCase):
    def _ixia(self, app_errors) -> Ixia:
        ixia = _make_ixia()
        ixia.ixnetwork.Globals.AppErrors.find.return_value.Error.find.return_value = (
            app_errors
        )
        ixia.ixnetwork.Traffic.IsTrafficRunning = False
        ixia._send_arp_and_ns = MagicMock()
        ixia._generate_traffic_items = MagicMock()
        return ixia

    def _rejection(self) -> BadRequestError:
        return BadRequestError(" Error in L2/L3 Traffic Apply", 400)

    def test_resolves_destinations_before_the_next_attempt(
        self, _sleep: MagicMock
    ) -> None:
        ixia = self._ixia(_UNRESOLVED_DESTINATION_ERRORS)
        order = MagicMock()
        order.attach_mock(ixia.ixnetwork.Traffic.Apply, "apply")
        order.attach_mock(ixia._send_arp_and_ns, "send_arp_and_ns")
        order.attach_mock(ixia._generate_traffic_items, "generate")
        ixia.ixnetwork.Traffic.Apply.side_effect = [self._rejection(), None]

        ixia.apply_traffic()

        self.assertEqual(
            [c[0] for c in order.mock_calls],
            ["apply", "send_arp_and_ns", "generate", "apply"],
        )

    def test_other_rejections_are_plain_retries(self, _sleep: MagicMock) -> None:
        ixia = self._ixia([])
        ixia.ixnetwork.Traffic.Apply.side_effect = [self._rejection(), None]

        ixia.apply_traffic()

        ixia._send_arp_and_ns.assert_not_called()
        ixia._generate_traffic_items.assert_not_called()

    def test_stale_message_level_errors_do_not_trigger_it(
        self, _sleep: MagicMock
    ) -> None:
        ixia = self._ixia(
            [_app_error("kMessage", "No Flow Groups", "invalid or unreachable", "x")]
        )
        ixia.ixnetwork.Traffic.Apply.side_effect = [self._rejection(), None]

        ixia.apply_traffic()

        ixia._send_arp_and_ns.assert_not_called()

    def test_unreadable_app_errors_fall_back_to_a_plain_retry(
        self, _sleep: MagicMock
    ) -> None:
        ixia = self._ixia([])
        ixia.ixnetwork.Globals.AppErrors.find.side_effect = RuntimeError("gone")
        ixia.ixnetwork.Traffic.Apply.side_effect = [self._rejection(), None]

        ixia.apply_traffic()

        ixia._send_arp_and_ns.assert_not_called()

    def test_raises_when_resolving_does_not_help(self, _sleep: MagicMock) -> None:
        ixia = self._ixia(_UNRESOLVED_DESTINATION_ERRORS)
        ixia.ixnetwork.Traffic.Apply.side_effect = self._rejection()

        with self.assertRaises(BadRequestError):
            ixia.apply_traffic()

        self.assertEqual(ixia.ixnetwork.Traffic.Apply.call_count, 3)
        self.assertEqual(ixia._send_arp_and_ns.call_count, 2)
        self.assertEqual(ixia._generate_traffic_items.call_count, 2)

    def test_stale_warning_does_not_trigger_it(self, _sleep: MagicMock) -> None:
        ixia = self._ixia(
            [
                _UNRESOLVED_DESTINATION_ERRORS[0],
                _app_error("kError", "Other", "unrelated", "01/01/2024 00:06:00"),
            ]
        )
        ixia.ixnetwork.Traffic.Apply.side_effect = [self._rejection(), None]

        ixia.apply_traffic()

        ixia._send_arp_and_ns.assert_not_called()
        ixia._generate_traffic_items.assert_not_called()
        _sleep.assert_called_once_with(5.0)

    def test_stale_no_flow_groups_does_not_trigger_it(self, _sleep: MagicMock) -> None:
        ixia = self._ixia(
            [
                _UNRESOLVED_DESTINATION_ERRORS[1],
                _app_error("kError", "Other", "unrelated", "01/01/2024 00:06:00"),
            ]
        )
        ixia.ixnetwork.Traffic.Apply.side_effect = [self._rejection(), None]

        ixia.apply_traffic()

        ixia._send_arp_and_ns.assert_not_called()
        ixia._generate_traffic_items.assert_not_called()

    def test_running_traffic_gets_a_plain_retry(self, _sleep: MagicMock) -> None:
        ixia = self._ixia(_UNRESOLVED_DESTINATION_ERRORS)
        ixia.ixnetwork.Traffic.IsTrafficRunning = True
        ixia.ixnetwork.Traffic.Apply.side_effect = [self._rejection(), None]

        ixia.apply_traffic()

        ixia._send_arp_and_ns.assert_not_called()
        ixia._generate_traffic_items.assert_not_called()
        self.assertEqual(ixia.ixnetwork.Traffic.Apply.call_count, 2)

    def test_recovery_failure_still_retries(self, _sleep: MagicMock) -> None:
        ixia = self._ixia(_UNRESOLVED_DESTINATION_ERRORS)
        ixia._send_arp_and_ns.side_effect = RuntimeError("topology gone")
        ixia.ixnetwork.Traffic.Apply.side_effect = [self._rejection(), None]

        ixia.apply_traffic()

        self.assertEqual(ixia.ixnetwork.Traffic.Apply.call_count, 2)


if __name__ == "__main__":
    unittest.main()


class GenerateTrafficItemsTest(unittest.TestCase):
    def test_skips_disabled_items(self) -> None:
        ixia = _make_ixia()
        enabled, disabled = MagicMock(Enabled=True), MagicMock(Enabled=False)
        with patch.object(Ixia, "get_traffic_items", return_value=[enabled, disabled]):
            ixia._generate_traffic_items()
        enabled.Generate.assert_called_once_with()
        disabled.Generate.assert_not_called()

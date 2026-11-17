# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Deferred routed traffic: every item must be enabled when it is generated.

Deferred items are created disabled. IxNetwork accepts Generate on a disabled
item but leaves its high-level streams at the defaults they were created with
(64 B, 10% line rate), so a stream generated while disabled and enabled later
transmits the defaults instead of its configured frame size and rate.
"""

import logging
import threading
from unittest.mock import MagicMock, patch

from taac.ixia.ixia import Ixia
from taac.ixia.taac_ixia import TaacIxia


class _FakeTrafficItem:
    """Records whether it was enabled when Generate ran, as IxNetwork's result
    depends on exactly that."""

    def __init__(self, name: str) -> None:
        self.Name = name
        self.Enabled = False
        self.generated_while_enabled = None

    def Generate(self) -> None:
        self.generated_while_enabled = self.Enabled


def _deferred_ixia(items, regexes):
    ixia = TaacIxia.__new__(TaacIxia)
    ixia.logger = logging.getLogger("test")
    ixia._tracer = None
    ixia._snapshot_lock = threading.RLock()
    ixia.ixnetwork = MagicMock()
    ixia.ixnetwork.Traffic.TrafficItem.find.return_value = items
    ixia.has_traffic_items = lambda: True
    ixia._traffic_preparation_pending = True
    ixia._deferred_traffic_generation_complete = False
    ixia._traffic_start_pending = False
    ixia._traffic_view_readiness_pending = False
    ixia._pending_traffic_regexes = regexes
    ixia._deferred_traffic_item_replacements = []
    ixia.wait_for_view_assistants_ready = MagicMock()
    running = {"value": False}
    ixia.is_traffic_running = lambda: running["value"]
    return ixia, running


def _start(ixia, running):
    def base_start(self, regenerate_traffic_items=False):
        running["value"] = True

    with patch.object(Ixia, "start_traffic", base_start):
        ixia.start_traffic()


def test_items_are_generated_enabled_then_the_selection_applies():
    items = [
        _FakeTrafficItem("SELECTED_TRAFFIC"),
        _FakeTrafficItem("UNSELECTED_TRAFFIC"),
        _FakeTrafficItem("OTHER_TRAFFIC"),
    ]
    ixia, running = _deferred_ixia(items, ["SELECTED_TRAFFIC"])

    _start(ixia, running)

    assert [i.generated_while_enabled for i in items] == [True, True, True]
    assert [i.Enabled for i in items] == [True, False, False]


def test_retained_item_superseded_by_a_replacement_is_not_generated():
    # A retained session keeps the old generated item under the real name
    # until finalize swaps in the replacement and removes the old one.
    retained = _FakeTrafficItem("SELECTED_TRAFFIC")
    replacement = _FakeTrafficItem(
        "SELECTED_TRAFFIC__taac_replacement_ab12"
    )
    other = _FakeTrafficItem("UNSELECTED_TRAFFIC")
    items = [retained, replacement, other]
    ixia, running = _deferred_ixia(items, ["^SELECTED_TRAFFIC$"])
    ixia._deferred_traffic_item_replacements = [
        ("SELECTED_TRAFFIC", replacement.Name)
    ]

    def finalize():
        items.remove(retained)
        replacement.Name = "SELECTED_TRAFFIC"

    ixia.finalize_deferred_traffic_item_replacements = finalize

    _start(ixia, running)

    assert retained.generated_while_enabled is False
    assert replacement.generated_while_enabled is True
    assert other.generated_while_enabled is True
    assert {i.Name: i.Enabled for i in items} == {
        "SELECTED_TRAFFIC": True,
        "UNSELECTED_TRAFFIC": False,
    }

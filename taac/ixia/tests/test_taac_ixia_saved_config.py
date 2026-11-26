# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""The runner exports before the test case uuid exists, so the uuid is no key."""

import logging

import pytest

from taac.ixia.taac_ixia import TaacIxia


def _bare_ixia(monkeypatch, exported):
    ixia = TaacIxia.__new__(TaacIxia)
    ixia.logger = logging.getLogger("test")
    ixia.saved_config = None
    ixia.test_case_uuid = None
    imported = []
    monkeypatch.setattr(ixia, "export_json_config", lambda: exported)
    monkeypatch.setattr(ixia, "import_json_config", imported.append)
    return ixia, imported


def test_restore_uses_the_config_saved_before_the_uuid_was_known(monkeypatch):
    ixia, imported = _bare_ixia(monkeypatch, {"cfg": 1})
    ixia.export_and_save_config()
    ixia.test_case_uuid = "uuid-1"
    ixia.import_saved_config()
    assert imported == [{"cfg": 1}]


def test_restore_after_the_next_test_case_export_uses_the_newest_config(monkeypatch):
    ixia, imported = _bare_ixia(monkeypatch, {"cfg": 1})
    ixia.export_and_save_config()
    ixia.test_case_uuid = "uuid-1"
    ixia.import_saved_config()
    monkeypatch.setattr(ixia, "export_json_config", lambda: {"cfg": 2})
    ixia.export_and_save_config()
    ixia.test_case_uuid = "uuid-2"
    ixia.import_saved_config()
    assert imported == [{"cfg": 1}, {"cfg": 2}]


def test_restore_without_a_save_fails_with_a_clear_error(monkeypatch):
    ixia, _ = _bare_ixia(monkeypatch, {"cfg": 1})
    with pytest.raises(RuntimeError):
        ixia.import_saved_config()


def test_failed_export_does_not_leave_an_older_config(monkeypatch):
    ixia, imported = _bare_ixia(monkeypatch, {"cfg": 1})
    ixia.export_and_save_config()

    def failing_export():
        raise ConnectionError("no session")

    monkeypatch.setattr(ixia, "export_json_config", failing_export)
    with pytest.raises(ConnectionError):
        ixia.export_and_save_config()
    with pytest.raises(RuntimeError):
        ixia.import_saved_config()
    assert imported == []

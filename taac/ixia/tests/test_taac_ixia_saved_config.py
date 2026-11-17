# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""backup_and_restore_ixia_config: the runner exports before begin_test_case
sets the test-case uuid, so the saved config must not be keyed by it."""

import logging

import pytest

from taac.ixia.taac_ixia import TaacIxia


def _bare_ixia(monkeypatch, exported):
    ixia = TaacIxia.__new__(TaacIxia)
    ixia.logger = logging.getLogger("test")
    # saved_config is deliberately NOT set here: TaacIxia's own default has to
    # be what import_saved_config reads, or a fixture that pre-seeds it hides
    # a missing initialisation.
    ixia.test_case_uuid = None
    imported = []
    monkeypatch.setattr(ixia, "export_json_config", lambda: exported)
    monkeypatch.setattr(ixia, "import_json_config", imported.append)
    return ixia, imported


def test_restore_uses_the_config_saved_before_the_uuid_was_known(monkeypatch):
    ixia, imported = _bare_ixia(monkeypatch, {"cfg": 1})
    ixia.export_and_save_config()  # runner: async_test_case_setUp, uuid unset
    ixia.test_case_uuid = "0" * 32  # begin_test_case
    ixia.import_saved_config()  # runner: _end_ixia_test_case
    assert imported == [{"cfg": 1}]


def test_restore_without_a_save_fails_loudly(monkeypatch):
    ixia, _ = _bare_ixia(monkeypatch, {"cfg": 1})
    with pytest.raises(RuntimeError):
        ixia.import_saved_config()

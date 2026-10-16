# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""``TAAC_LOG_DIR`` moves the ``async_log_to_file_oss`` file out of /tmp."""

import os
import tempfile
import unittest
from unittest.mock import patch

from taac.utils.common import async_log_to_file_oss


class TestLogToFileOss(unittest.IsolatedAsyncioTestCase):
    async def test_writes_to_taac_log_dir_when_set(self) -> None:
        with tempfile.TemporaryDirectory() as target:
            with patch.dict(os.environ, {"TAAC_LOG_DIR": target}):
                path = await async_log_to_file_oss("evidence", prefix="taac_everpaste")
            self.assertEqual(os.path.dirname(path), target)
            with open(path) as handle:
                self.assertEqual(handle.read(), "evidence")

    async def test_creates_a_missing_log_dir(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            target = os.path.join(parent, "nested", "logs")
            with patch.dict(os.environ, {"TAAC_LOG_DIR": target}):
                path = await async_log_to_file_oss("evidence")
            self.assertEqual(os.path.dirname(path), target)

    async def test_falls_back_when_the_log_dir_cannot_be_created(self) -> None:
        # makedirs fails under a plain file, even as root.
        with tempfile.TemporaryDirectory() as parent:
            blocker = os.path.join(parent, "blocker")
            with open(blocker, "w"):
                pass
            with patch.dict(os.environ, {"TAAC_LOG_DIR": f"{blocker}/logs"}):
                path = await async_log_to_file_oss("evidence")
            self.addCleanup(os.remove, path)
            self.assertEqual(os.path.dirname(path), tempfile.gettempdir())

    async def test_falls_back_when_the_log_dir_is_unwritable(self) -> None:
        real_open = open

        def fail_in_target(file, *args, **kwargs):
            if str(file).startswith(target):
                raise PermissionError(13, "Permission denied")
            return real_open(file, *args, **kwargs)

        with tempfile.TemporaryDirectory() as target:
            with patch.dict(os.environ, {"TAAC_LOG_DIR": target}):
                with patch("builtins.open", fail_in_target):
                    path = await async_log_to_file_oss("evidence")
            self.addCleanup(os.remove, path)
            self.assertEqual(os.path.dirname(path), tempfile.gettempdir())

    async def test_falls_back_to_the_temp_dir(self) -> None:
        # An empty TAAC_LOG_DIR must fall back too; abspath("") is the cwd.
        for value in ({}, {"TAAC_LOG_DIR": ""}):
            with self.subTest(env=value):
                with patch.dict(os.environ, value, clear=False):
                    if not value:
                        os.environ.pop("TAAC_LOG_DIR", None)
                    self.assertEqual(
                        os.environ.get("TAAC_LOG_DIR"), value.get("TAAC_LOG_DIR")
                    )
                    # The file name hashes the content, so each pass needs its own.
                    path = await async_log_to_file_oss(f"evidence {value}")
                self.addCleanup(os.remove, path)
                self.assertEqual(os.path.dirname(path), tempfile.gettempdir())

    async def test_the_log_dir_is_made_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as target:
            self.addCleanup(os.chdir, os.getcwd())
            os.chdir(target)
            with patch.dict(os.environ, {"TAAC_LOG_DIR": "."}):
                path = await async_log_to_file_oss("evidence")
            self.assertEqual(os.path.dirname(path), os.path.realpath(target))


if __name__ == "__main__":
    unittest.main()

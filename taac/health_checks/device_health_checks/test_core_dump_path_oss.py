# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Under TAAC_OSS, core-dump checks list both FBOSS core directories.

Some OSS FBOSS images pipe kernel.core_pattern to systemd-coredump, which
stores cores in /var/lib/systemd/coredump/ instead of /var/tmp/cores/. The
listing command runs in a local shell here against temp directories.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock

from taac.utils import health_check_utils as hcu

# Relative to the temp working directory, so a random temp path never matches
# a critical-process keyword.
CORES = "cores/"
SYSTEMD = "coredump/"


class TestOssCoreDumpDirs(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name, value in (
            ("TAAC_OSS", True),
            ("FBOSS_CORE_DUMP_PATH", CORES),
            ("FBOSS_SYSTEMD_CORE_DUMP_PATH", SYSTEMD),
        ):
            patcher = mock.patch.object(hcu, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _core(self, rel_path, mtime):
        path = self.root / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        os.utime(path, (mtime, mtime))

    async def _find(self):
        def run(cmd):
            return subprocess.run(
                ["sh", "-c", cmd],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            ).stdout

        driver = AsyncMock()
        driver.async_run_cmd_on_shell = AsyncMock(side_effect=lambda cmd: run(cmd))
        with mock.patch.object(
            hcu, "async_get_device_driver", AsyncMock(return_value=driver)
        ):
            return await hcu.async_find_critical_core_dumps("dut1")

    async def test_systemd_coredump_only(self):
        self._core(
            f"{SYSTEMD}core.fboss_sw_agent.0.abcd.1111.2000000000000000.zst", 2000000000
        )
        self._core(
            f"{SYSTEMD}core.fw_util.1000.abcd.2222.2000000100000000.zst", 2000000100
        )
        self.assertEqual(
            await self._find(),
            {"core.fboss_sw_agent.0.abcd.1111.2000000000000000.zst": 2000000000},
        )

    async def test_var_tmp_cores_only_keeps_packaged_keys(self):
        self._core(f"{CORES}fboss_sw_agent_1234_fboss_sw_agent_1/core", 2000000000)
        self.assertEqual(
            await self._find(),
            {"fboss_sw_agent_1234_fboss_sw_agent_1/core": 2000000000},
        )

    async def test_both_directories_are_listed(self):
        self._core(f"{CORES}bgpd_77_bgpd_1/core", 2000000000)
        self._core(f"{SYSTEMD}core.fsdb.0.abcd.3333.2000000200000000.zst", 2000000200)
        self.assertEqual(
            await self._find(),
            {
                "bgpd_77_bgpd_1/core": 2000000000,
                "core.fsdb.0.abcd.3333.2000000200000000.zst": 2000000200,
            },
        )

    async def test_empty_directory_is_no_cores(self):
        (self.root / SYSTEMD).mkdir()
        self.assertEqual(await self._find(), {})

    async def test_neither_directory_raises(self):
        with self.assertRaisesRegex(RuntimeError, "No core dump directory"):
            await self._find()

# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Under TAAC_OSS, core-dump checks read the directory systemd-coredump writes.

Some FBOSS images pipe core_pattern to systemd-coredump, which stores cores
in /var/lib/systemd/coredump/; /var/tmp/cores does not exist there. Reading the
wrong directory comes back empty and would pass as "no new core dumps".
"""

import unittest
from unittest import mock
from unittest.mock import AsyncMock

from taac.utils import health_check_utils as hcu

CORE_DIR = "/var/lib/systemd/coredump/"


class TestOssCoreDumpPath(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        patcher = mock.patch.object(hcu, "TAAC_OSS", True)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def _find(self, device_output):
        driver = AsyncMock()
        driver.async_run_cmd_on_shell = AsyncMock(return_value=device_output)
        with mock.patch.object(hcu, "async_get_device_driver", AsyncMock(return_value=driver)):
            return await hcu.async_find_critical_core_dumps("dut1")

    async def test_oss_reads_the_systemd_coredump_directory(self):
        path, _ = await hcu.async_get_core_dump_config("dut1")
        self.assertEqual(path, CORE_DIR)

    async def test_systemd_coredump_names_are_matched_to_critical_processes(self):
        cores = await self._find(
            f"2000000000.5 {CORE_DIR}core.fboss_sw_agent.0.abcd.1111.2000000000000000.zst\n"
            f"2000000100.1 {CORE_DIR}core.fw_util.1000.abcd.2222.2000000100000000.zst\n"
        )

        self.assertEqual(
            cores, {"core.fboss_sw_agent.0.abcd.1111.2000000000000000.zst": 2000000000}
        )

    async def test_missing_core_directory_raises_instead_of_reporting_none(self):
        with self.assertRaisesRegex(RuntimeError, CORE_DIR):
            await self._find(f"find: '{CORE_DIR}': No such file or directory\n")

    async def test_empty_directory_is_no_cores(self):
        self.assertEqual(await self._find(""), {})

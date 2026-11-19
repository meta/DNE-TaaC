# pyre-unsafe

import contextlib
import io
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from taac.runner import topology_inspector
from taac.runner.oss_exceptions import OSSConfigError
from taac.runner.oss_return_code import OSSReturnCode
from taac.runner.testbed_topology import CircuitLink, ConfigTopology, LinkType

_HEADER = """
from taac.test_as_a_config import types as t
from taac.runner.testbed_topology import topology_aware

def make(name, endpoints=(), playbooks=()):
    return t.TestConfig(
        name=name, playbooks=list(playbooks), endpoints=list(endpoints),
        host_os_type_map={}, startup_checks=[],
    )
"""

_SINGLE = """
test_config = make(
    "single",
    endpoints=[t.Endpoint(name="d1", dut=True)],
    playbooks=[t.Playbook(name="pb_on", stages=[]),
               t.Playbook(name="pb_off", stages=[], enabled=False)],
)
"""

_IXIA = """
@topology_aware
def test_config(topology):
    return make("ixia", endpoints=[
        t.Endpoint(name="d1", dut=True, ixia_ports=["1/1", "1/2"]),
        t.Endpoint(name="d2", ixia_ports=["1/3"]),
        t.Endpoint(name="d1", dut=True, ixia_ports=["1/1", "1/2"]),
    ])
"""

_FROM_TOPOLOGY = """
@topology_aware
def test_config(topology):
    duts = sorted(topology.dut_ports)
    if len(duts) < 2:
        raise ValueError(f"needs 2 DUTs, found {len(duts)}")
    return make("pair", endpoints=[t.Endpoint(name=d, dut=True) for d in duts])
"""

_MULTI = """
FIRST = make("first", endpoints=[t.Endpoint(name="d1", dut=True)])
SECOND = make("second", endpoints=[
    t.Endpoint(name="d1", dut=True), t.Endpoint(name="d2"),
])
_HIDDEN = make("hidden")
"""


class TopologyInspectorTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)

    def _write(self, rel: str, body: str, header: bool = True) -> str:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text((_HEADER if header else "") + textwrap.dedent(body))
        return str(path)

    def _main(self, *argv: str):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = topology_inspector.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def _names(self, loaded):
        return [(lc.config.name, lc.test_name) for lc in loaded]

    def test_default_lookup_matches_runner(self):
        # Kept local: oss_entry_point needs the full runner import chain.
        from taac.runner import oss_entry_point

        for body in (_SINGLE, _IXIA):
            path = self._write("cfg.py", body)
            [loaded] = topology_inspector.load_configs(path)
            expected = oss_entry_point.load_test_config(path, topology=ConfigTopology())
            self.assertEqual(loaded.config, expected)
            self.assertIsNone(loaded.test_name)

    def test_topology_aware_results_are_tagged(self):
        [plain] = topology_inspector.load_configs(self._write("a.py", _SINGLE))
        [aware] = topology_inspector.load_configs(self._write("b.py", _IXIA))
        self.assertFalse(plain.empty_topology)
        self.assertTrue(aware.empty_topology)
        rc, out, _ = self._main("--dir", str(self.root))
        self.assertEqual(rc, OSSReturnCode.SUCCESS)
        self.assertIn("\nixia  (empty topology)\n", out)
        self.assertIn("\nsingle\n", out)

    def test_topology_aware_failure_has_hint(self):
        path = self._write("pair.py", _FROM_TOPOLOGY)
        rc, _, err = self._main("--test-configs", path)
        self.assertEqual(rc, OSSReturnCode.CONFIG_ERROR)
        self.assertIn("needs 2 DUTs, found 0", err)
        self.assertIn("empty topology; pass --duts", err)

    def test_duts_builds_the_topology(self):
        from taac.runner import oss_entry_point

        links = tuple(
            CircuitLink(a, "eth1/1/1", z, "eth1/1/1", LinkType.DUT)
            for a, z in (("d1", "d2"), ("d2", "d1"))
        )
        path = self._write("pair.py", _FROM_TOPOLOGY)
        with patch.object(
            oss_entry_point,
            "build_testbed_topology",
            return_value=ConfigTopology(links=links),
        ) as build:
            rc, out, err = self._main("--test-configs", path, "--duts", "d1", "d2")
        self.assertEqual(rc, OSSReturnCode.SUCCESS, err)
        build.assert_called_once_with(["d1", "d2"])
        self.assertIn("\npair\n", out)
        self.assertIn("Devices (2):  d1, d2", out)

    def test_duts_without_runner_imports_is_config_error(self):
        path = self._write("single.py", _SINGLE)
        with patch.dict(sys.modules, {"taac.runner.oss_entry_point": None}):
            rc, _, err = self._main("--test-configs", path, "--duts", "d1")
        self.assertEqual(rc, OSSReturnCode.CONFIG_ERROR)
        self.assertIn("Cannot build the topology for --duts", err)

    def test_first_default_name_wins(self):
        path = self._write(
            "cfg.py", 'CONFIG = make("upper")\ntest_config = make("lower")\n'
        )
        self.assertEqual(
            self._names(topology_inspector.load_configs(path)), [("lower", None)]
        )

    def test_default_name_not_a_testconfig_is_error(self):
        path = self._write("cfg.py", "config = {}\n")
        with self.assertRaises(OSSConfigError):
            topology_inspector.load_configs(path)

    def test_named_constants_listed_without_default_name(self):
        path = self._write("multi.py", _MULTI)
        self.assertEqual(
            self._names(topology_inspector.load_configs(path)),
            [("first", "FIRST"), ("second", "SECOND")],
        )

    def test_test_name_selects_one_config(self):
        path = self._write("multi.py", _MULTI + 'test_config = make("default")\n')
        self.assertEqual(
            self._names(topology_inspector.load_configs(path, test_name="SECOND")),
            [("second", "SECOND")],
        )

    def test_test_name_calls_factory(self):
        path = self._write("cfg.py", _IXIA)
        [loaded] = topology_inspector.load_configs(path, test_name="test_config")
        self.assertEqual(loaded.config.name, "ixia")

    def test_missing_test_name(self):
        path = self._write("multi.py", _MULTI)
        with self.assertRaisesRegex(OSSConfigError, "TYPO"):
            topology_inspector.load_configs(path, test_name="TYPO")
        self.assertEqual(
            topology_inspector.load_configs(path, test_name="TYPO", discovered=True),
            [],
        )

    def test_file_without_configs(self):
        path = self._write("helper.py", "X = 1\n")
        with self.assertRaises(OSSConfigError):
            topology_inspector.load_configs(path)
        self.assertEqual(topology_inspector.load_configs(path, discovered=True), [])

    def test_dir_discovery_and_grouping(self):
        self._write("a/single.py", _SINGLE)
        self._write("a/b/ixia.py", _IXIA)
        self._write("a/multi.py", _MULTI)
        self._write("a/helper.py", "X = 1\n", header=False)
        self._write("a/__init__.py", "raise RuntimeError('not imported')\n", False)
        rc, out, err = self._main("--dir", str(self.root / "a"), "--verbose")
        self.assertEqual(rc, OSSReturnCode.SUCCESS, err)
        headers = [line for line in out.splitlines() if line.startswith("─")]
        self.assertEqual(len(headers), 3)
        self.assertIn("1 device, no Ixia", headers[0])
        self.assertIn("2 devices, no Ixia", headers[1])
        self.assertIn("2 devices, 3 Ixia ports", headers[2])
        self.assertLess(out.index("\nfirst  [FIRST]"), out.index("\nsingle\n"))
        self.assertIn("DUT Ixia (2):  d1:1/1  d1:1/2", out)
        self.assertIn("Non-DUT Ixia (1):  d2:1/3", out)
        self.assertIn("    - pb_on", out)
        self.assertIn("(1 disabled: pb_off)", out)
        self.assertIn("Configs shown: 4", out)

    def test_device_and_ixia_filters(self):
        self._write("single.py", _SINGLE)
        self._write("ixia.py", _IXIA)
        self._write("multi.py", _MULTI)
        rc, out, _ = self._main("--dir", str(self.root), "--devices", "2")
        self.assertEqual(rc, OSSReturnCode.SUCCESS)
        self.assertIn("\nsecond  [SECOND]", out)
        self.assertIn("\nixia  (empty topology)\n", out)
        self.assertNotIn("\nsingle\n", out)
        self.assertNotIn("\nfirst", out)

        rc, out, _ = self._main(
            "--dir", str(self.root), "--devices", "2", "--ixia-ports", "3"
        )
        self.assertIn("\nixia  (empty topology)\n", out)
        self.assertNotIn("\nsecond", out)
        self.assertIn("Configs shown: 1", out)

        rc, out, _ = self._main("--dir", str(self.root), "--ixia-ports", "9")
        self.assertEqual(rc, OSSReturnCode.SUCCESS)
        self.assertIn("No configs matched", out)

    def test_test_name_with_dir(self):
        self._write("single.py", _SINGLE)
        self._write("multi.py", _MULTI)
        rc, out, _ = self._main("--dir", str(self.root), "--test-name", "FIRST")
        self.assertEqual(rc, OSSReturnCode.SUCCESS)
        self.assertIn("Configs shown: 1", out)
        rc, _, err = self._main("--dir", str(self.root), "--test-name", "TYPO")
        self.assertEqual(rc, OSSReturnCode.CONFIG_ERROR)
        self.assertIn("No file defines 'TYPO'", err)

    def test_broken_file_is_config_error(self):
        good = self._write("single.py", _SINGLE)
        bad = self._write("broken.py", "def oops(:\n", header=False)
        rc, out, err = self._main("--test-configs", good, bad)
        self.assertEqual(rc, OSSReturnCode.CONFIG_ERROR)
        self.assertIn("\nsingle\n", out)
        self.assertIn(bad, err)
        rc, _, err = self._main("--test-configs", str(self.root / "missing.py"))
        self.assertEqual(rc, OSSReturnCode.CONFIG_ERROR)
        self.assertIn("not found", err)

    def test_csv_flags_set_env(self):
        path = self._write("single.py", _SINGLE)
        self._main(
            "--test-configs",
            path,
            "--device-info-csv",
            "dev.csv",
            "--circuit-info-csv",
            "circ.csv",
        )
        self.assertEqual(
            os.environ["TAAC_DEVICE_INFO_PATH"], os.path.abspath("dev.csv")
        )
        self.assertEqual(
            os.environ["TAAC_CIRCUIT_INFO_PATH"], os.path.abspath("circ.csv")
        )


if __name__ == "__main__":
    unittest.main()

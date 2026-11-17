#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

"""
TAAC topology inspector.

Loads one or more test configs and prints their hardware requirements
(DUTs, Ixia ports, playbooks) without connecting to any devices.

Usage:
    python3 -m taac.runner.inspect --test-configs <config.py> [<config2.py> ...]
    python3 -m taac.runner.inspect --dir taac/testconfigs/fboss_solution_tests/
    python3 -m taac.runner.inspect --dir taac/testconfigs/ --devices 2 --ixia-ports 4
    python3 -m taac.runner.inspect --test-configs <config.py> --verbose
"""

import argparse
import importlib.util
import itertools
import os
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from taac.runner.constants_loader import CONSTANTS_PATH_ENV
from taac.runner.oss_exceptions import OSSConfigError
from taac.runner.oss_return_code import OSSReturnCode
from taac.runner.topology_inspector import print_topology_requirements


def _load_configs_from_file(config_path: str) -> list:
    """Load all TestConfig instances from a Python file.

    Returns a list — empty means no configs found (silently skip the file),
    multiple means a multi-config file (show all). Raises OSSConfigError for
    genuine load failures (syntax errors, missing imports, bad path, etc.).
    """
    path = Path(config_path)
    if not path.exists():
        raise OSSConfigError(f"Test config file not found: {config_path}")
    if not path.is_file():
        raise OSSConfigError(f"Test config path is not a file: {config_path}")
    if path.suffix != ".py":
        raise OSSConfigError(f"Test config file must be a .py file: {config_path}")

    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise OSSConfigError(f"Failed to load module spec from: {config_path}")

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise OSSConfigError(f"Failed to load test config from '{config_path}': {e}")

    from taac.test_as_a_config import (
        thrift_types as _taac_thrift_types,
        types as _taac_types,
    )
    _testconfig_classes = (_taac_thrift_types.TestConfig, _taac_types.TestConfig)

    # Try standard names first so factory functions (def test_config(): ...) work.
    for attr_name in ["test_config", "TEST_CONFIG", "config", "CONFIG"]:
        if hasattr(module, attr_name):
            val = getattr(module, attr_name)
            if callable(val) and not isinstance(val, _testconfig_classes):
                if getattr(val, "_accepts_topology", False):
                    from taac.runner.testbed_topology import ConfigTopology
                    val = val(topology=ConfigTopology())
                else:
                    val = val()
            if isinstance(val, _testconfig_classes):
                return [val]

    # Fall back: return every module-level TestConfig instance (0, 1, or many).
    # Also unwrap lists/tuples of TestConfig instances.
    results = []
    for _, val in vars(module).items():
        if isinstance(val, _testconfig_classes):
            results.append(val)
        elif isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, _testconfig_classes):
                    results.append(item)
    return results


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="taac-inspect",
        description="Print topology requirements for TAAC test configs (no devices contacted).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Sources — at least one required, both may be combined
    parser.add_argument(
        "--test-configs",
        nargs="+",
        metavar="FILE",
        help="Explicit path(s) to Python test config files",
    )
    parser.add_argument(
        "--dir",
        nargs="+",
        metavar="DIR",
        help="Directory/directories to search recursively for test config files",
    )

    # Filters
    parser.add_argument(
        "--devices",
        type=int,
        metavar="N",
        help="Only show configs involving N devices (DUT + non-DUT)",
    )
    parser.add_argument(
        "--ixia-ports",
        type=int,
        metavar="N",
        help="Only show configs with exactly N Ixia ports total",
    )

    # Output
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full playbook list and non-DUT endpoints",
    )

    # Topology CSVs
    parser.add_argument(
        "--device-info-csv",
        help="Path to device_info.csv (sets TAAC_DEVICE_INFO_PATH for OSS topology loader)",
    )
    parser.add_argument(
        "--circuit-info-csv",
        help="Path to circuit_info.csv (sets TAAC_CIRCUIT_INFO_PATH for OSS topology loader)",
    )
    parser.add_argument(
        "--constants",
        help=(
            f"Path to a constants YAML file (sets {CONSTANTS_PATH_ENV}). Only "
            "affects constants modules that call apply_overlay(globals())."
        ),
    )

    args = parser.parse_args(argv)

    if not args.test_configs and not args.dir:
        parser.error("at least one of --test-configs or --dir is required")

    return args


def _discover(dirs: List[str]) -> List[Path]:
    """Return sorted .py paths found recursively under each dir."""
    paths = []
    for d in dirs:
        paths.extend(sorted(Path(d).rglob("*.py")))
    return paths


def _topology_key(config) -> Tuple[int, int]:
    """Return (num_devices, num_ixia_ports) for grouping/sorting."""
    seen: set = set()
    endpoints = []
    for ep in (config.endpoints or []):
        if ep.name not in seen:
            seen.add(ep.name)
            endpoints.append(ep)
    num_devices = len(endpoints)
    num_ixia = sum(len(list(ep.ixia_ports)) for ep in endpoints if ep.ixia_ports)
    return (num_devices, num_ixia)


def _passes_filters(config, devices: Optional[int], ixia_ports: Optional[int]) -> bool:
    seen: set = set()
    endpoints = []
    for ep in (config.endpoints or []):
        if ep.name not in seen:
            seen.add(ep.name)
            endpoints.append(ep)
    if devices is not None:
        if len(endpoints) != devices:
            return False
    if ixia_ports is not None:
        total = sum(len(list(ep.ixia_ports)) for ep in endpoints if ep.ixia_ports)
        if total != ixia_ports:
            return False
    return True


def main(argv: Optional[List[str]] = None) -> int:
    os.environ["TAAC_OSS"] = "1"
    args = _parse_args(argv)

    if args.device_info_csv:
        os.environ["TAAC_DEVICE_INFO_PATH"] = os.path.abspath(args.device_info_csv)
    if args.circuit_info_csv:
        os.environ["TAAC_CIRCUIT_INFO_PATH"] = os.path.abspath(args.circuit_info_csv)
    if args.constants:
        os.environ[CONSTANTS_PATH_ENV] = os.path.abspath(args.constants)

    # Collect all candidate paths
    paths: List[str] = list(args.test_configs or [])
    paths += [str(p) for p in _discover(args.dir or [])]

    errors: List[str] = []
    all_configs = []

    for config_path in paths:
        try:
            configs_to_show = _load_configs_from_file(config_path)
        except OSSConfigError as e:
            errors.append(f"  {config_path}: {e}")
            continue

        for config in configs_to_show:
            if not _passes_filters(config, args.devices, args.ixia_ports):
                continue
            all_configs.append(config)

    all_configs.sort(key=lambda c: (_topology_key(c), (c.name or "").casefold()))

    for (n_devs, n_ixia), group in itertools.groupby(all_configs, key=_topology_key):
        ixia_str = f"{n_ixia} Ixia port{'s' if n_ixia != 1 else ''}" if n_ixia else "no Ixia"
        header = f"  {n_devs} device{'s' if n_devs != 1 else ''}, {ixia_str}  "
        print(f"\n{'─' * 4}{header}{'─' * max(0, 60 - len(header))}")
        for config in group:
            print_topology_requirements(config, verbose=args.verbose)

    shown = len(all_configs)

    if errors:
        errMsg = f"\nCould not load {len(errors)} file(s):"
        if not args.verbose:
            errMsg += " use --verbose to see details"
        print(errMsg)
        if args.verbose:
            for msg in errors:
                print(msg)

    if shown == 0 and not errors:
        print("No configs matched the given filters.")

    if shown:
        print(f"\nCount of displayed configs: {shown}")
        print("\n*** Note: device-to-device connections are not shown here; "
              "they are resolved at runtime from circuit_info.csv.")
        print("*** DUT = device under test (the switch being validated); "
              "Non-DUT = supporting device in the topology (peer switch, upstream router) "
              "that is present but not itself the test target.")

    return OSSReturnCode.CONFIG_ERROR if errors else OSSReturnCode.SUCCESS


if __name__ == "__main__":
    sys.exit(main())

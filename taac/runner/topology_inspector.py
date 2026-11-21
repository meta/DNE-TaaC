# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

"""
TAAC topology inspector.

Loads test configs and prints what hardware each one needs (devices, DUT and
non-DUT Ixia ports, playbooks) without contacting any device.

A file's config is picked the way ``taac.runner.oss_entry_point`` picks it:
the first of ``test_config`` / ``TEST_CONFIG`` / ``config`` / ``CONFIG``
defined in the module, calling it if it is a factory. ``@topology_aware``
factories get an empty ``ConfigTopology`` unless ``--duts`` is given (the
runner builds it from its DUTs and the circuit CSV), and their results are
tagged "(empty topology)": they may show placeholder devices or fail to build.
``--test-name NAME`` picks attribute ``NAME`` instead. A module with none of
the default names has each public module-level TestConfig listed under its
attribute name.

Usage:
    python3 -m taac.runner.topology_inspector --test-configs <config.py> [...]
    python3 -m taac.runner.topology_inspector --dir <dir> [--devices N] [--ixia-ports N]
    python3 -m taac.runner.topology_inspector --test-configs <config.py> --test-name NAME
    python3 -m taac.runner.topology_inspector --test-configs <config.py> \
        --circuit-info-csv <circuit_info.csv> --duts <dut> [<dut> ...]
"""

import argparse
import importlib.util
import itertools
import os
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional, Tuple

from taac.runner.oss_exceptions import OSSConfigError
from taac.runner.oss_return_code import OSSReturnCode
from taac.runner.testbed_topology import ConfigTopology

DEFAULT_CONFIG_NAMES = ("test_config", "TEST_CONFIG", "config", "CONFIG")


class LoadedConfig(NamedTuple):
    config: object
    # Module attribute the config came from, when it is not a default name.
    test_name: Optional[str]
    # Built by a @topology_aware factory from a topology with no links.
    empty_topology: bool = False


def _testconfig_classes() -> tuple:
    from taac.test_as_a_config import thrift_types, types

    return (thrift_types.TestConfig, types.TestConfig)


def _resolve(
    module,
    attr: str,
    config_path: str,
    classes: tuple,
    test_name: Optional[str],
    topology: Optional[ConfigTopology],
) -> LoadedConfig:
    val = getattr(module, attr)
    empty_topology = False
    try:
        if callable(val) and not isinstance(val, classes):
            if getattr(val, "_accepts_topology", False):
                topology = topology or ConfigTopology()
                empty_topology = not topology.links
                val = val(topology=topology)
            else:
                val = val()
    except Exception as e:
        hint = (
            " (it is @topology_aware and got an empty topology; pass --duts "
            "and --circuit-info-csv to build one)"
            if empty_topology
            else ""
        )
        raise OSSConfigError(
            f"Failed to build '{attr}' from '{config_path}': {e}{hint}"
        ) from e
    if not isinstance(val, classes):
        raise OSSConfigError(f"'{attr}' in '{config_path}' is not a TestConfig")
    return LoadedConfig(val, test_name, empty_topology)


def load_configs(
    config_path: str,
    test_name: Optional[str] = None,
    discovered: bool = False,
    topology: Optional[ConfigTopology] = None,
) -> List[LoadedConfig]:
    """Return the configs found in ``config_path``.

    ``discovered`` marks a file found by ``--dir``: such a file with no
    matching config yields ``[]`` instead of raising. ``topology`` is passed
    to ``@topology_aware`` factories (an empty one when not given).

    Raises:
        OSSConfigError: the file cannot be imported or its config cannot be
            built, or an explicitly given file has no matching config.
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
        raise OSSConfigError(
            f"Failed to load test config from '{config_path}': {e}"
        ) from e

    classes = _testconfig_classes()
    if test_name is not None:
        if hasattr(module, test_name):
            return [
                _resolve(module, test_name, config_path, classes, test_name, topology)
            ]
        if discovered:
            return []
        raise OSSConfigError(
            f"Test config attribute '{test_name}' not found in {config_path}"
        )

    for attr in DEFAULT_CONFIG_NAMES:
        if hasattr(module, attr):
            return [_resolve(module, attr, config_path, classes, None, topology)]

    named = [
        LoadedConfig(val, attr)
        for attr, val in vars(module).items()
        if not attr.startswith("_") and isinstance(val, classes)
    ]
    if named or discovered:
        return named
    raise OSSConfigError(
        f"No test config found in {config_path}. Expected one of: "
        f"{', '.join(DEFAULT_CONFIG_NAMES)}, or a module-level TestConfig"
    )


def _unique_endpoints(config) -> list:
    seen = set()
    endpoints = []
    for ep in config.endpoints or []:
        if ep.name not in seen:
            seen.add(ep.name)
            endpoints.append(ep)
    return endpoints


def topology_key(config) -> Tuple[int, int]:
    """Return (device count, Ixia port count) of ``config``."""
    endpoints = _unique_endpoints(config)
    return len(endpoints), sum(len(ep.ixia_ports or []) for ep in endpoints)


def print_topology_requirements(
    config,
    verbose: bool = False,
    test_name: Optional[str] = None,
    empty_topology: bool = False,
) -> None:
    endpoints = _unique_endpoints(config)
    duts = [ep for ep in endpoints if ep.dut]
    non_duts = [ep for ep in endpoints if not ep.dut]

    def _ixia_pairs(eps) -> List[str]:
        return [f"{ep.name}:{port}" for ep in eps for port in ep.ixia_ports or []]

    dut_ixia = _ixia_pairs(duts)
    non_dut_ixia = _ixia_pairs(non_duts)
    playbooks = list(config.playbooks or [])
    enabled = [pb for pb in playbooks if pb.enabled]
    disabled = [pb for pb in playbooks if not pb.enabled]

    print(
        f"\n{config.name}"
        + (f"  [{test_name}]" if test_name else "")
        + ("  (empty topology)" if empty_topology else "")
    )
    names = [ep.name for ep in duts + non_duts]
    print(f"  Devices ({len(names)}):  " + ", ".join(names))
    if dut_ixia:
        print(f"  DUT Ixia ({len(dut_ixia)}):  " + "  ".join(dut_ixia))
    if non_dut_ixia:
        print(f"  Non-DUT Ixia ({len(non_dut_ixia)}):  " + "  ".join(non_dut_ixia))
    if not dut_ixia and not non_dut_ixia:
        print("  Ixia:  no")

    if verbose:
        print(f"  Playbooks ({len(enabled)} enabled):")
        for pb in enabled:
            print(f"    - {pb.name}")
        if disabled:
            names = ", ".join(pb.name for pb in disabled)
            print(f"    ({len(disabled)} disabled: {names})")
    else:
        print(f"  Playbooks: {len(enabled)} enabled  (--verbose to list)")


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python3 -m taac.runner.topology_inspector",
        description=(
            "Print topology requirements for TAAC test configs "
            "(no devices contacted)."
        ),
    )
    parser.add_argument(
        "--test-configs",
        nargs="+",
        metavar="FILE",
        help="Python test config file(s)",
    )
    parser.add_argument(
        "--dir",
        nargs="+",
        metavar="DIR",
        help=(
            "Directory/directories searched recursively for .py files; "
            "files without a matching config are skipped"
        ),
    )
    parser.add_argument(
        "--test-name",
        metavar="NAME",
        help=(
            "Inspect module attribute NAME (a TestConfig or a factory "
            "returning one) instead of the default lookup "
            f"({', '.join(DEFAULT_CONFIG_NAMES)}). A config is tagged '[NAME]' "
            "when it came from attribute NAME rather than the default lookup."
        ),
    )
    parser.add_argument(
        "--devices",
        type=int,
        metavar="N",
        help="Only show configs with exactly N distinct endpoints (DUT + non-DUT)",
    )
    parser.add_argument(
        "--ixia-ports",
        type=int,
        metavar="N",
        help="Only show configs with exactly N Ixia ports in total",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="List enabled and disabled playbooks",
    )
    parser.add_argument(
        "--device-info-csv",
        help="Path to a device_info.csv file (sets TAAC_DEVICE_INFO_PATH)",
    )
    parser.add_argument(
        "--circuit-info-csv",
        help=(
            "Path to a circuit_info.csv file. Only sets TAAC_CIRCUIT_INFO_PATH; "
            "@topology_aware configs get a topology built from it only with --duts"
        ),
    )
    parser.add_argument(
        "--duts",
        nargs="+",
        metavar="DUT",
        help=(
            "Build the topology passed to @topology_aware configs from these "
            "DUTs and the circuit CSV, as the runner does"
        ),
    )
    args = parser.parse_args(argv)
    if not args.test_configs and not args.dir:
        parser.error("at least one of --test-configs or --dir is required")
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    if args.device_info_csv:
        os.environ["TAAC_DEVICE_INFO_PATH"] = os.path.abspath(args.device_info_csv)
    if args.circuit_info_csv:
        os.environ["TAAC_CIRCUIT_INFO_PATH"] = os.path.abspath(args.circuit_info_csv)

    topology = None
    if args.duts:
        try:
            # Imported only here: it needs the full runner import chain.
            from taac.runner.oss_entry_point import build_testbed_topology

            topology = build_testbed_topology(args.duts)
        except Exception as e:
            print(f"Cannot build the topology for --duts: {e}", file=sys.stderr)
            return int(OSSReturnCode.CONFIG_ERROR)

    errors: List[str] = []
    sources = [(path, False) for path in args.test_configs or []]
    for d in args.dir or []:
        if not Path(d).is_dir():
            errors.append(f"{d}: not a directory")
            continue
        sources += [
            (str(p), True)
            for p in sorted(Path(d).rglob("*.py"))
            if p.name != "__init__.py"
        ]

    found = False
    shown: List[LoadedConfig] = []
    for path, discovered in sources:
        try:
            loaded = load_configs(path, args.test_name, discovered, topology)
        except OSSConfigError as e:
            errors.append(f"{path}: {e}")
            continue
        found = found or bool(loaded)
        for lc in loaded:
            n_devs, n_ixia = topology_key(lc.config)
            if args.devices is not None and n_devs != args.devices:
                continue
            if args.ixia_ports is not None and n_ixia != args.ixia_ports:
                continue
            shown.append(lc)

    if args.test_name is not None and not found and not errors:
        errors.append(f"No file defines '{args.test_name}'")

    shown.sort(
        key=lambda lc: (topology_key(lc.config), (lc.config.name or "").casefold())
    )
    for (n_devs, n_ixia), group in itertools.groupby(
        shown, key=lambda lc: topology_key(lc.config)
    ):
        ixia = (
            f"{n_ixia} Ixia port{'s' if n_ixia != 1 else ''}" if n_ixia else "no Ixia"
        )
        header = f"  {n_devs} device{'s' if n_devs != 1 else ''}, {ixia}  "
        print(f"\n{'─' * 4}{header}{'─' * max(0, 60 - len(header))}")
        for lc in group:
            print_topology_requirements(
                lc.config, args.verbose, lc.test_name, lc.empty_topology
            )

    if shown:
        print(f"\nConfigs shown: {len(shown)}")
        print(
            "Device-to-device links are not shown; the runner resolves them "
            "from circuit_info.csv."
        )
        if any(lc.empty_topology for lc in shown):
            print(
                "(empty topology): built by a @topology_aware factory from an "
                "empty topology, so devices and ports may be placeholders; "
                "pass --duts to build the topology the runner would."
            )
    elif not errors:
        print("No configs matched the given filters.")

    if errors:
        print(f"\nErrors ({len(errors)}):", file=sys.stderr)
        for msg in errors:
            print(f"  {msg}", file=sys.stderr)
        return int(OSSReturnCode.CONFIG_ERROR)
    return int(OSSReturnCode.SUCCESS)


if __name__ == "__main__":
    sys.exit(main())

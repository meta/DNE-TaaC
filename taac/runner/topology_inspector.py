# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

"""
Topology requirements inspector for TAAC test configs.

Pure extraction from a TestConfig struct — no network calls, no TaacRunner.
Used by ``python3 -m taac.runner.inspect`` to show what hardware a config
needs before running it.
"""

from taac.test_as_a_config.thrift_types import TestConfig


def print_topology_requirements(
    config: TestConfig,
    verbose: bool = False,
) -> None:
    seen: set = set()
    endpoints = []
    for ep in (config.endpoints or []):
        if ep.name not in seen:
            seen.add(ep.name)
            endpoints.append(ep)

    dut_eps = [ep for ep in endpoints if ep.dut]
    peer_eps = [ep for ep in endpoints if not ep.dut and not ep.ixia_ports]
    non_dut_ixia_eps = [ep for ep in endpoints if not ep.dut and ep.ixia_ports]

    dut_ixia_links: dict = {}
    for ep in dut_eps:
        ports = list(ep.ixia_ports) if ep.ixia_ports else []
        if ports:
            dut_ixia_links[ep.name] = ports

    non_dut_ixia_links: dict = {}
    for ep in non_dut_ixia_eps:
        non_dut_ixia_links[ep.name] = list(ep.ixia_ports)

    ixia_needed = bool(dut_ixia_links or non_dut_ixia_links)

    playbooks = list(config.playbooks) if config.playbooks else []
    enabled_pbs = [pb for pb in playbooks if pb.enabled]
    disabled_pbs = [pb for pb in playbooks if not pb.enabled]

    all_device_names = (
        [ep.name for ep in dut_eps]
        + [ep.name for ep in peer_eps]
        + list(non_dut_ixia_links.keys())
    )
    print(f"\n{config.name}")
    print(f"  Devices ({len(all_device_names)}):  " + ", ".join(all_device_names))

    if ixia_needed:
        if dut_ixia_links:
            dut_pairs = [f"{ep}:{p}" for ep, ports in dut_ixia_links.items() for p in ports]
            print(f"  DUT Ixia ({len(dut_pairs)}):  " + "  ".join(dut_pairs))
        if non_dut_ixia_links:
            non_dut_pairs = [f"{ep}:{p}" for ep, ports in non_dut_ixia_links.items() for p in ports]
            print(f"  Non-DUT Ixia ({len(non_dut_pairs)}):  " + "  ".join(non_dut_pairs))
    else:
        print("  Ixia:  no")

    if verbose:
        print(f"  Playbooks ({len(enabled_pbs)} enabled):")
        for pb in enabled_pbs:
            print(f"    - {pb.name}")
        if disabled_pbs:
            print(f"    ({len(disabled_pbs)} disabled: {', '.join(pb.name for pb in disabled_pbs)})")
    else:
        print(f"  Playbooks: {len(enabled_pbs)} enabled  (--verbose to list)")

    print()

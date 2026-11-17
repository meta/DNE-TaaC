# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""OSS-specific TestConfig wrappers.

Distinct from the Meta-internal solution-test subdirectories
(``fboss_solution_tests``, ``ai_bb``, etc.) — modules in this package
are tailored for the open-source TAAC runtime: parameters are
populated from ``oss_topology_info`` CSV fixtures (with env-var
overrides where applicable), and wiring is restricted to what the
OSS slice ships.
"""

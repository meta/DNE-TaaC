# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

"""Prepare the release-installed stack for the nrqeb010 IxANVL runner.

Use Netcastle --setup-only --skip-ixia-setup --skip-testbed-isolation, and
omit --update-packages to retain the image-installed RPMs. EOS deployment
precedes every setup task. This profile retains valid existing config and the
release launcher, enables only the five required daemons, and leaves them
available to the subsequent suites.
The discovery playbook only checks readiness; it is not a conformance test.
"""

from __future__ import annotations

import base64
import json
import shlex
from importlib import resources

from taac.abstractions.compatibility.eos_bgpcpp_compatibility import (
    BGPCPP_DAEMONS,
)
from taac.abstractions.physical_inventory import (
    NRQEB010_ASH6,
    PhysicalInventory,
)
from taac.constants import ARISTA_DAEMON_EXEC_SCRIPTS
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import create_run_task_step
from taac.task_definitions import (
    create_arista_daemon_control_task,
    create_run_commands_on_shell_task,
)
from taac.test_as_a_config import types as taac_types

# The same no-OpenR projection used by DICE's control-plane recipe.
DAEMONS = tuple(name for name in BGPCPP_DAEMONS if name != "Openr")


def device_command(phase: str) -> str:
    if phase not in ("prepare", "verify"):
        raise ValueError(f"Unknown IxANVL setup phase: {phase}")
    script = (
        resources.files(__package__)
        .joinpath("ixanvl_setup_device.txt")
        .read_text(encoding="utf-8")
    )
    payload = json.dumps(
        {
            "phase": phase,
            "daemon_execs": {
                name: ARISTA_DAEMON_EXEC_SCRIPTS[name] for name in DAEMONS
            },
        }
    )
    script += f"\nmain({payload!r})\n"
    encoded = base64.b64encode(script.encode()).decode()
    return f"bash printf %s {shlex.quote(encoded)} | base64 -d | sudo python3 -"


def create_ixanvl_setup_config(
    inventory: PhysicalInventory, basset_pool: str | None = None
) -> taac_types.TestConfig:
    hostname = inventory.device_name
    prepare = device_command("prepare")
    verify = device_command("verify")
    return taac_types.TestConfig(
        name=f"{hostname.replace('.', '_').upper()}_IXANVL_SETUP",
        basset_pool=basset_pool or inventory.basset_pool,
        endpoints=[taac_types.Endpoint(name=hostname, dut=True)],
        host_os_type_map={hostname: taac_types.DeviceOsType.ARISTA_OS},
        host_driver_args=inventory.host_driver_args,
        oss_mock_device_data=inventory.oss_mock_device_data,
        startup_checks=[],
        setup_tasks=[
            create_run_commands_on_shell_task(
                hostname,
                [prepare],
                set_outer_hostname=True,
                ixia_needed=True,
                validate_output=True,
            ),
            *(
                create_arista_daemon_control_task(
                    hostname, daemon_name=name, action="enable", ixia_needed=True
                )
                for name in DAEMONS
            ),
            create_run_commands_on_shell_task(
                hostname,
                [verify],
                set_outer_hostname=True,
                ixia_needed=True,
                validate_output=True,
            ),
        ],
        teardown_tasks=[],
        playbooks=[
            taac_types.Playbook(
                name="ixanvl_setup_readiness",
                enabled=True,
                stages=[
                    create_steps_stage(
                        steps=[
                            create_run_task_step(
                                task_name="run_commands_on_shell",
                                params_dict={
                                    "hostname": hostname,
                                    "cmds": [verify],
                                    "validate_output": True,
                                },
                                start_traffic=False,
                                description="Check the installed IxANVL DUT stack without traffic",
                            )
                        ]
                    )
                ],
            )
        ],
    )


NRQEB010_ASH6_IXANVL_SETUP = create_ixanvl_setup_config(
    NRQEB010_ASH6, basset_pool="routing.qual"
)

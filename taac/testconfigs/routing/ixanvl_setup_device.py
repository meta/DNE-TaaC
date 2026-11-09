# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

"""DUT-only prerequisite/bootstrap and readiness probes, executed on EOS.

No package, launcher, ACL, daemon, or startup-config changes are made here.
Only a missing bgpcpp config may be bootstrapped; an existing invalid file is
refused rather than replaced. Daemon enables belong to the standard TAAC task.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping

CONFIG_PATH = "/mnt/flash/bgpcpp_config"
VALIDATOR = "/usr/sbin/bgp_config_validator"
EXECUTABLES = (
    "/usr/sbin/bgpcpp",
    "/usr/sbin/run_bgpcpp.sh",
    VALIDATOR,
    "/usr/bin/EosSdkRpc",
    "/usr/bin/AristaFibAgent",
)
INPUTS = (
    "/mnt/fb/agent_configs/fib_agent.conf",
    "/mnt/fb/agent_configs/fib_agent_bgp.conf",
    "/usr/facebook/thrift_acls/FibAgent.json",
)
CERTIFICATE_KEYS = frozenset(
    (
        "x509_ca_path",
        "x509_cert_path",
        "x509_key_path",
        "mtls_cert",
        "mtls_ca",
        "net_static_file_acl",
    )
)
BOOTSTRAP = {
    "router_id": "1.17.3.3",
    "local_as_4_byte": 64981,
    "listen_addr": "::",
    "listen_port": 179,
    "peers": [],
    "peer_groups": [],
    "networks4": [],
    "networks6": [],
}


def _command(argv: list[str], timeout: float = 30) -> str:
    # Only installed, fixed executables are invoked; never execute an exec
    # string read from EOS config or a shell string supplied by the caller.
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode or re.search(r"^\s*%", output, re.MULTILINE):
        raise RuntimeError(
            f"{argv[0]} failed (exit {result.returncode}): {output[-1000:]}"
        )
    return output


def _cli(command: str, timeout: float = 30) -> str:
    allowed = {
        "show running-config section daemon",
        "show running-config section router bgp",
        "show bgpcpp summary",
    }
    if command not in allowed and not re.fullmatch(
        r"show daemon [A-Za-z][A-Za-z0-9_]*", command
    ):
        raise ValueError("IxANVL setup permits read-only, fixed EOS commands only")
    return _command(["FastCli", "-p15", "-c", command], timeout=timeout)


def _blocks(text: str, prefix: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line == line.lstrip():
            if line.startswith(prefix):
                blocks.append([line.strip()])
            else:
                blocks.append([])
        elif blocks and blocks[-1]:
            blocks[-1].append(line)
    return [block for block in blocks if block]


def check_ownership(
    daemon_text: str, router_text: str, execs: Mapping[str, str]
) -> set[str]:
    if not execs or "Bgpcpp" not in execs or "Bgp" in execs:
        raise ValueError("IxANVL setup requires the canonical Bgpcpp daemon chain")
    configured = set()
    for block in _blocks(daemon_text, "daemon "):
        name = block[0].removeprefix("daemon ")
        if name == "Bgp":
            raise RuntimeError("Refusing to remove or rename existing daemon Bgp")
        if name not in execs:
            if any(
                line.strip().startswith(f"exec {script}")
                for line in block[1:]
                for script in execs.values()
            ):
                raise RuntimeError(
                    f"Refusing required-stack exec under unexpected daemon {name}"
                )
            continue
        actual = [
            line.strip() for line in block[1:] if line.strip().startswith("exec ")
        ]
        if actual != [f"exec {execs[name]}"]:
            raise RuntimeError(f"Refusing conflicting daemon {name}: unexpected exec")
        configured.add(name)
    for block in _blocks(router_text, "router bgp"):
        indent = min((len(line) - len(line.lstrip()) for line in block[1:]), default=0)
        if not any(
            line.strip() == "shutdown" and len(line) - len(line.lstrip()) == indent
            for line in block[1:]
        ):
            raise RuntimeError(f"Refusing active native {block[0]}")
    return configured


def _check_referenced_files(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in CERTIFICATE_KEYS and child:
                if not isinstance(child, str) or not os.path.isfile(child):
                    raise RuntimeError(f"Missing installed input referenced by {key}")
            _check_referenced_files(child)
    elif isinstance(value, list):
        for child in value:
            _check_referenced_files(child)


def check_inputs() -> None:
    for path in EXECUTABLES:
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            raise RuntimeError(f"Required installed executable missing: {path}")
    if shutil.which("FastCli") is None:
        raise RuntimeError("Required installed executable missing: FastCli")
    for path in INPUTS:
        try:
            with open(path) as source:
                contents = json.load(source)
        except OSError as error:
            raise RuntimeError(
                f"Required installed input unavailable: {path}"
            ) from error
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Required installed input is not valid JSON: {path}"
            ) from error
        _check_referenced_files(contents)
    owners = _command(["rpm", "-qf", *EXECUTABLES[:3]]).splitlines()
    if (
        len(owners) != 3
        or len(set(owners)) != 1
        or not owners[0].startswith("fb-bgpcpp-")
    ):
        raise RuntimeError(
            "bgpcpp, launcher and validator must belong to the same installed fb-bgpcpp RPM"
        )
    print(f"Installed bgpcpp RPM retained: {owners[0]}")


def validate_config(path: str) -> None:
    with open(path) as source:
        config = json.load(source)
    if not isinstance(config, dict):
        raise RuntimeError("bgpcpp config must be a JSON object")
    _check_referenced_files(config)
    output = _command([VALIDATOR, "--config", path])
    if "[PASS]" not in output or "[FAIL]" in output or "[ERROR]" in output:
        raise RuntimeError(
            f"bgp_config_validator did not confirm validity: {output[-1000:]}"
        )


def ensure_config(config_path: str, running: bool) -> None:
    if os.path.lexists(config_path):
        if os.path.islink(config_path) or not os.path.isfile(config_path):
            raise RuntimeError("Refusing non-regular or symlink bgpcpp config")
        validate_config(config_path)
        return
    if running:
        raise RuntimeError(
            "Running Bgpcpp has no config file; refusing to bootstrap beneath it"
        )
    stage = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=os.path.dirname(config_path),
            prefix=".ixanvl-bootstrap-",
            delete=False,
        ) as target:
            stage = target.name
            json.dump(BOOTSTRAP, target)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(stage, 0o644)
        validate_config(stage)
        # A concurrent writer must not be overwritten between absence check
        # and installation. Both files are on /mnt/flash.
        try:
            os.link(stage, config_path)
        except FileExistsError:
            if os.path.islink(config_path) or not os.path.isfile(config_path):
                raise RuntimeError("Refusing non-regular or symlink bgpcpp config")
            validate_config(config_path)
    finally:
        if stage is not None:
            os.unlink(stage)


def is_running(output: str, name: str | None = None) -> bool:
    expected = re.escape(name) if name is not None else r"\S+"
    return bool(
        re.search(
            rf"^(?:Process|Agent):\s+{expected}\s+\(running(?:\s+with\s+PID\s+\d+)?\)",
            output,
            re.IGNORECASE | re.MULTILINE,
        )
    )


def prepare(execs: Mapping[str, str]) -> None:
    check_inputs()
    configured = check_ownership(
        _cli("show running-config section daemon"),
        _cli("show running-config section router bgp"),
        execs,
    )
    running = "Bgpcpp" in configured and is_running(
        _cli("show daemon Bgpcpp"), "Bgpcpp"
    )
    ensure_config(CONFIG_PATH, running)
    print("IXANVL_PREPARE_OK")


def verify(execs: Mapping[str, str], attempts: int = 30, delay: float = 2) -> None:
    last = ""
    deadline = time.monotonic() + max(1, attempts * delay)

    def read(command: str) -> str:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"IxANVL readiness deadline expired: {last[-2000:]}")
        return _cli(command, timeout=min(30, remaining))

    for attempt in range(attempts):
        configured = check_ownership(
            read("show running-config section daemon"),
            read("show running-config section router bgp"),
            execs,
        )
        states = {
            name: read(f"show daemon {name}") for name in execs if name in configured
        }
        last = "; ".join(
            f"{name}: {states.get(name, 'not configured').strip()}" for name in execs
        )
        if configured == set(execs) and all(
            is_running(state, name) for name, state in states.items()
        ):
            try:
                summary = read("show bgpcpp summary")
            except RuntimeError as error:
                text = str(error)
                if not re.search(
                    r"%\s*Internal error", text, re.IGNORECASE
                ) or re.search(
                    r"authorization|unauthorized|not authorized|permission denied|invalid input|invalid command",
                    text,
                    re.IGNORECASE,
                ):
                    raise
                summary = ""
                last += "\n" + text
            last += "\n" + summary
            if re.search(r"^\s*BGP is up(?:\s|$)", summary, re.MULTILINE):
                print("IXANVL_READY_OK")
                return
        if attempt + 1 < attempts:
            time.sleep(min(delay, max(0, deadline - time.monotonic())))
    raise RuntimeError(f"IxANVL DUT did not become ready: {last[-2000:]}")


def main(payload: str) -> None:
    params = json.loads(payload)
    phase = params["phase"]
    if phase == "prepare":
        prepare(params["daemon_execs"])
    elif phase == "verify":
        verify(params["daemon_execs"])
    else:
        raise ValueError(f"Unknown IxANVL setup phase: {phase}")

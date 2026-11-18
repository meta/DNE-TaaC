# Copyright (c) Meta Platforms, Inc. and affiliates.

from __future__ import annotations

import asyncio
import fnmatch
import json
import math
import os
import re
import stat
import time
import uuid
from collections.abc import Mapping, Set
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any


CAMPAIGN_DIR_ENV = "TAAC_CAMPAIGN_DIR"
SCHEMA_VERSION = 1
_COMMAND_KEYS = frozenset(
    {
        "schema_version",
        "campaign_id",
        "sequence",
        "expected_state_version",
        "action",
        "reason",
        "expires_at",
    }
)
_CORE_PROTOCOL_DIRECTORIES = (
    "commands",
    "acknowledgments",
    "attempts",
    "patches",
    "logs",
    "artifacts",
)
_HOST_ACTION_DIRECTORIES = (
    "host_action_requests",
    "host_action_acknowledgments",
    "host_action_artifacts",
)
_PROTOCOL_DIRECTORIES = (*_CORE_PROTOCOL_DIRECTORIES, *_HOST_ACTION_DIRECTORIES)
_HOST_ACTION_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "campaign_id",
        "sequence",
        "expected_state_version",
        "action_id",
        "reason",
        "expires_at",
    }
)


class CampaignProtocolError(ValueError):
    pass


class BoundaryAction(StrEnum):
    CONTINUE = "CONTINUE"
    STOP_FOR_PATCH = "STOP_FOR_PATCH"
    ABORT_GRACEFULLY = "ABORT_GRACEFULLY"
    RERUN_WITH_PATCH = "RERUN_WITH_PATCH"
    FINISH = "FINISH"
    COLLECT_DIAGNOSTICS = "COLLECT_DIAGNOSTICS"


@dataclass(frozen=True)
class HostActionSpec:
    action_id: str
    kind: str
    host: str
    expected_sessions: int = 32
    timeout_seconds: float = 180.0
    max_invocations: int = 1
    allow_perpetual: bool = False
    min_interval_seconds: float = 0.0
    interface: str | None = None
    max_hold_seconds: float = 60.0
    verify_hrt_recovery: bool = True
    continue_on_failure: bool = False
    interfaces: tuple[str, ...] = ()
    host_patterns: tuple[str, ...] = ()

    def __post_init__(self) -> None:  # noqa: C901
        if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", self.action_id) is None:
            raise CampaignProtocolError("host action_id is invalid")
        if self.kind not in {
            "restart_hrt",
            "kill_hrt",
            "hrt_status",
            "hrt_logs",
            "link_disable",
            "nic_flap",
            "host_status",
            "dls_logs",
            "start_dls",
            "restart_dls",
            "kill_dls",
            "stop_dls",
            "coldboot_via_dls",
            "reboot_host",
        }:
            raise CampaignProtocolError(f"unsupported host action kind {self.kind!r}")
        self._validate_host()
        if type(self.expected_sessions) is not int or self.expected_sessions < 1:
            raise CampaignProtocolError("expected_sessions must be a positive integer")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise CampaignProtocolError("host action timeout must be positive")
        if type(self.max_invocations) is not int or self.max_invocations < 1:
            raise CampaignProtocolError("max_invocations must be a positive integer")
        if type(self.allow_perpetual) is not bool:
            raise CampaignProtocolError("allow_perpetual must be boolean")
        if (
            type(self.verify_hrt_recovery) is not bool
            or type(self.continue_on_failure) is not bool
        ):
            raise CampaignProtocolError("restart policy flags must be boolean")
        if self.kind not in {"restart_hrt", "kill_hrt"} and (
            not self.verify_hrt_recovery or self.continue_on_failure
        ):
            raise CampaignProtocolError(
                "restart policy flags apply only to restart_hrt and kill_hrt"
            )
        if (
            not isinstance(self.min_interval_seconds, (int, float))
            or isinstance(self.min_interval_seconds, bool)
            or not math.isfinite(self.min_interval_seconds)
            or self.min_interval_seconds < 0
        ):
            raise CampaignProtocolError(
                "min_interval_seconds must be finite and non-negative"
            )
        if self.kind == "link_disable":
            if (
                not isinstance(self.interface, str)
                or re.fullmatch(r"eth[0-9]+/[0-9]+/[0-9]+", self.interface) is None
            ):
                raise CampaignProtocolError("link action requires an exact interface")
        elif self.interface is not None:
            raise CampaignProtocolError("interface is only valid for link actions")
        self._validate_interfaces()
        if (
            type(self.max_hold_seconds) not in (int, float)
            or not math.isfinite(self.max_hold_seconds)
            or self.max_hold_seconds <= 0
        ):
            raise CampaignProtocolError("max_hold_seconds must be finite and positive")

    def _validate_interfaces(self) -> None:
        if not isinstance(self.interfaces, (list, tuple)):
            raise CampaignProtocolError("interfaces must be an exact interface list")
        if any(
            not isinstance(interface, str)
            or re.fullmatch(r"beth[0-9]+", interface) is None
            for interface in self.interfaces
        ):
            raise CampaignProtocolError("NIC actions require exact beth interfaces")
        if len(set(self.interfaces)) != len(self.interfaces):
            raise CampaignProtocolError("interfaces must be unique")
        if (self.kind == "nic_flap") != bool(self.interfaces):
            raise CampaignProtocolError(
                "only nic_flap requires a non-empty interface list"
            )
        object.__setattr__(self, "interfaces", tuple(self.interfaces))

    def _validate_host(self) -> None:
        if not isinstance(self.host_patterns, (list, tuple)) or any(
            not isinstance(pattern, str)
            or re.fullmatch(r"[a-z0-9.*-]+", pattern) is None
            for pattern in self.host_patterns
        ):
            raise CampaignProtocolError("host_patterns must be hostname glob strings")
        object.__setattr__(self, "host_patterns", tuple(self.host_patterns))
        if self.host_patterns:
            if self.host != "":
                raise CampaignProtocolError("host_patterns requires an empty host")
        elif (
            not isinstance(self.host, str)
            or re.fullmatch(r"[A-Za-z0-9.-]+", self.host) is None
        ):
            raise CampaignProtocolError("host action hostname is invalid")

    def authorizes_host(self, host: str) -> bool:
        if not isinstance(host, str) or re.fullmatch(r"[A-Za-z0-9.-]+", host) is None:
            return False
        canonical = host.lower().removesuffix(".facebook.com")
        if self.host_patterns:
            return any(fnmatch.fnmatchcase(canonical, p) for p in self.host_patterns)
        return canonical == self.host.lower().removesuffix(".facebook.com")

    def resolve_host(self, host: str | None = None) -> HostActionSpec:
        if self.host_patterns and host is None:
            raise CampaignProtocolError("this action requires --host")
        target = self.host if host is None else host
        if not self.authorizes_host(target):
            raise CampaignProtocolError("host is not authorized for this action")
        return replace(
            self, host=target.lower().removesuffix(".facebook.com"), host_patterns=()
        )

    @classmethod
    def from_payload(cls, payload: object) -> HostActionSpec:
        if not isinstance(payload, dict):
            raise CampaignProtocolError("host action spec must be a JSON object")
        payload = dict(payload)
        expected = {field.name for field in cls.__dataclass_fields__.values()}
        optional_defaults = {
            "allow_perpetual": False,
            "min_interval_seconds": 0.0,
            "interface": None,
            "max_hold_seconds": 60.0,
            "verify_hrt_recovery": True,
            "continue_on_failure": False,
            "interfaces": (),
            "host_patterns": (),
        }
        missing = expected - set(payload)
        unexpected = set(payload) - expected
        if unexpected or not missing.issubset(optional_defaults):
            raise CampaignProtocolError("host action spec fields do not match schema")
        for field in missing:
            payload[field] = optional_defaults[field]
        try:
            return cls(**payload)
        except TypeError as error:
            raise CampaignProtocolError(
                "host action spec field types are invalid"
            ) from error


@dataclass(frozen=True)
class CampaignManifest:
    campaign_id: str
    test_config: str
    playbook_regex: str
    max_attempts: int
    command_timeout_seconds: float
    poll_interval_seconds: float = 1.0
    diagnostic_profiles: tuple[str, ...] = ()
    host_actions: tuple[HostActionSpec, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:  # noqa: C901
        if not isinstance(self.campaign_id, str) or not self.campaign_id:
            raise CampaignProtocolError("campaign_id must be a non-empty string")
        if not isinstance(self.test_config, str) or not self.test_config:
            raise CampaignProtocolError("test_config must be a non-empty string")
        if not isinstance(self.playbook_regex, str) or not self.playbook_regex:
            raise CampaignProtocolError("playbook_regex must be a non-empty string")
        if type(self.max_attempts) is not int:
            raise CampaignProtocolError("max_attempts must be an integer")
        if not isinstance(self.command_timeout_seconds, (int, float)) or isinstance(
            self.command_timeout_seconds, bool
        ):
            raise CampaignProtocolError("command_timeout_seconds must be numeric")
        if not isinstance(self.poll_interval_seconds, (int, float)) or isinstance(
            self.poll_interval_seconds, bool
        ):
            raise CampaignProtocolError("poll_interval_seconds must be numeric")
        if not isinstance(self.diagnostic_profiles, tuple) or not all(
            isinstance(profile, str) for profile in self.diagnostic_profiles
        ):
            raise CampaignProtocolError("diagnostic_profiles must be strings")
        if not isinstance(self.host_actions, tuple) or not all(
            isinstance(action, HostActionSpec) for action in self.host_actions
        ):
            raise CampaignProtocolError(
                "host_actions must contain HostActionSpec values"
            )
        action_ids = [action.action_id for action in self.host_actions]
        if len(set(action_ids)) != len(action_ids):
            raise CampaignProtocolError("host action IDs must be unique")
        if self.schema_version != SCHEMA_VERSION:
            raise CampaignProtocolError("unsupported manifest schema version")
        if self.max_attempts < 1:
            raise CampaignProtocolError("max_attempts must be positive")
        if self.command_timeout_seconds <= 0 or self.poll_interval_seconds <= 0:
            raise CampaignProtocolError("command timeouts must be positive")

    @classmethod
    def from_payload(cls, payload: object) -> CampaignManifest:
        if not isinstance(payload, dict):
            raise CampaignProtocolError("manifest must be a JSON object")
        payload = dict(payload)
        expected = {field.name for field in cls.__dataclass_fields__.values()}
        if set(payload) == expected - {"host_actions"}:
            payload["host_actions"] = []
        if set(payload) != expected:
            raise CampaignProtocolError("manifest fields do not match the schema")
        diagnostics = payload.get("diagnostic_profiles")
        if not isinstance(diagnostics, list) or not all(
            isinstance(profile, str) for profile in diagnostics
        ):
            raise CampaignProtocolError("diagnostic_profiles must be strings")
        action_payloads = payload.get("host_actions")
        if not isinstance(action_payloads, list):
            raise CampaignProtocolError("host_actions must be a list")
        try:
            return cls(
                campaign_id=payload["campaign_id"],
                test_config=payload["test_config"],
                playbook_regex=payload["playbook_regex"],
                max_attempts=payload["max_attempts"],
                command_timeout_seconds=payload["command_timeout_seconds"],
                poll_interval_seconds=payload["poll_interval_seconds"],
                diagnostic_profiles=tuple(diagnostics),
                host_actions=tuple(
                    HostActionSpec.from_payload(action) for action in action_payloads
                ),
                schema_version=payload["schema_version"],
            )
        except (KeyError, TypeError) as error:
            raise CampaignProtocolError("invalid manifest field types") from error

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["diagnostic_profiles"] = list(self.diagnostic_profiles)
        payload["host_actions"] = [asdict(action) for action in self.host_actions]
        return payload

    def get_host_action(self, action_id: str) -> HostActionSpec | None:
        return next(
            (action for action in self.host_actions if action.action_id == action_id),
            None,
        )


@dataclass(frozen=True)
class CampaignCommand:
    campaign_id: str
    sequence: int
    expected_state_version: int
    action: BoundaryAction
    reason: str
    expires_at: float
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def from_payload(cls, payload: object) -> CampaignCommand:
        if not isinstance(payload, dict) or set(payload) != _COMMAND_KEYS:
            raise CampaignProtocolError("command fields do not match the schema")
        try:
            return cls(
                campaign_id=payload["campaign_id"],
                sequence=payload["sequence"],
                expected_state_version=payload["expected_state_version"],
                action=BoundaryAction(payload["action"]),
                reason=payload["reason"],
                expires_at=payload["expires_at"],
                schema_version=payload["schema_version"],
            )
        except (TypeError, ValueError) as error:
            raise CampaignProtocolError("invalid command field types") from error

    def validate(self, campaign_id: str) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise CampaignProtocolError("unsupported command schema version")
        if self.campaign_id != campaign_id:
            raise CampaignProtocolError("command campaign_id does not match")
        if not isinstance(self.sequence, int) or self.sequence < 1:
            raise CampaignProtocolError("command sequence must be positive")
        if not isinstance(self.expected_state_version, int):
            raise CampaignProtocolError("expected_state_version must be an integer")
        if (
            not isinstance(self.reason, str)
            or not self.reason
            or len(self.reason) > 4096
        ):
            raise CampaignProtocolError("command reason is invalid")
        if not isinstance(self.expires_at, (int, float)):
            raise CampaignProtocolError("command expiration is invalid")

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["action"] = self.action.value
        return payload


@dataclass(frozen=True)
class HostActionRequest:
    campaign_id: str
    sequence: int
    expected_state_version: int
    action_id: str
    reason: str
    expires_at: float
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def from_payload(cls, payload: object) -> HostActionRequest:
        if not isinstance(payload, dict) or set(payload) != _HOST_ACTION_REQUEST_KEYS:
            raise CampaignProtocolError(
                "host action request fields do not match schema"
            )
        try:
            return cls(**payload)
        except TypeError as error:
            raise CampaignProtocolError(
                "host action request field types are invalid"
            ) from error

    def validate(self, campaign_id: str) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise CampaignProtocolError("unsupported host action request schema")
        if self.campaign_id != campaign_id:
            raise CampaignProtocolError(
                "host action request campaign_id does not match"
            )
        if type(self.sequence) is not int or self.sequence < 1:
            raise CampaignProtocolError("host action request sequence must be positive")
        if type(self.expected_state_version) is not int:
            raise CampaignProtocolError(
                "host action expected_state_version must be integer"
            )
        if not isinstance(self.action_id, str) or not self.action_id:
            raise CampaignProtocolError("host action request action_id is invalid")
        if (
            not isinstance(self.reason, str)
            or not self.reason
            or len(self.reason) > 4096
        ):
            raise CampaignProtocolError("host action request reason is invalid")
        if not isinstance(self.expires_at, (int, float)):
            raise CampaignProtocolError("host action request expiration is invalid")


def _write_json_file(
    path: Path, payload: Mapping[str, Any], *, exclusive: bool
) -> None:
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if exclusive:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise CampaignProtocolError(
                f"protocol file already exists: {path.name}"
            ) from error
        finally:
            temporary.unlink(missing_ok=True)
        return

    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


class NoopCampaignControl:
    is_enabled = False
    manifest: CampaignManifest | None = None

    def publish_status(self, state: str, **fields: Any) -> dict[str, Any]:
        return {"state": state, "state_version": 0, **fields}

    def publish_event(self, kind: str, **fields: Any) -> dict[str, Any]:
        return {"kind": kind, "event_sequence": 0, **fields}

    async def wait_for_boundary_action(
        self,
        *,
        expected_state_version: int,
        allowed_actions: Set[BoundaryAction],
    ) -> BoundaryAction:
        return BoundaryAction.CONTINUE

    def record_cleanup(
        self, *, success: bool, error: str | None = None
    ) -> dict[str, Any]:
        return self.publish_status(
            "CLEAN" if success else "RECOVERY_REQUIRED", error=error
        )


def _append_event(path: Path, payload: dict[str, Any]) -> None:
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        size = os.fstat(descriptor).st_size
        if size and os.pread(descriptor, 1, size - 1) != b"\n":
            encoded = b"\n" + encoded
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class CampaignControl:
    is_enabled = True

    def __init__(self, root: Path, manifest: CampaignManifest) -> None:
        self.root = root
        self.manifest = manifest
        self._state_version = self._read_counter("status.json", "state_version")
        self._event_sequence = self._read_event_sequence()
        self._last_command_sequence = self._read_counter(
            "command_cursor.json", "last_command_sequence"
        )
        self._host_action_state_version = self._read_counter(
            "host_action_status.json", "state_version"
        )
        self._host_action_event_sequence = self._read_event_sequence_from(
            "host_action_events.jsonl"
        )
        self._last_host_action_sequence = self._read_counter(
            "host_action_cursor.json", "last_host_action_sequence"
        )

    @classmethod
    def initialize(
        cls, root: Path | str, manifest: CampaignManifest
    ) -> CampaignControl:
        campaign_root = Path(root)
        if campaign_root.exists() or campaign_root.is_symlink():
            raise FileExistsError(campaign_root)
        campaign_root.mkdir(mode=0o700, parents=True)
        os.chmod(campaign_root, 0o700)
        for directory in _PROTOCOL_DIRECTORIES:
            path = campaign_root / directory
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700)
        _write_json_file(
            campaign_root / "manifest.json", manifest.to_payload(), exclusive=True
        )
        return cls(campaign_root, manifest)

    @classmethod
    def open(cls, root: Path | str) -> CampaignControl:
        campaign_root = Path(root)
        if campaign_root.is_symlink():
            raise CampaignProtocolError(
                "campaign directory must not be a symbolic link"
            )
        metadata = campaign_root.stat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CampaignProtocolError(
                "campaign directory must be private to its owner"
            )
        manifest_path = campaign_root / "manifest.json"
        if manifest_path.is_symlink():
            raise CampaignProtocolError("manifest must not be a symbolic link")
        with manifest_path.open() as handle:
            manifest = CampaignManifest.from_payload(json.load(handle))
        for directory in _PROTOCOL_DIRECTORIES:
            path = campaign_root / directory
            if not path.exists() and directory in _HOST_ACTION_DIRECTORIES:
                path.mkdir(mode=0o700)
                os.chmod(path, 0o700)
            if path.is_symlink() or not path.is_dir():
                raise CampaignProtocolError(
                    f"campaign {directory} directory is invalid"
                )
            child_metadata = path.stat()
            if (
                child_metadata.st_uid != os.getuid()
                or stat.S_IMODE(child_metadata.st_mode) & 0o077
            ):
                raise CampaignProtocolError(
                    f"campaign {directory} directory must be private"
                )
        return cls(campaign_root, manifest)

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> CampaignControl | NoopCampaignControl:
        env = os.environ if environment is None else environment
        root = env.get(CAMPAIGN_DIR_ENV)
        return cls.open(root) if root else NoopCampaignControl()

    def _read_counter(self, filename: str, key: str) -> int:
        path = self.root / filename
        if not path.exists():
            return 0
        with path.open() as handle:
            payload = json.load(handle)
        value = payload.get(key, 0)
        return value if isinstance(value, int) else 0

    def _read_event_sequence(self) -> int:
        return self._read_event_sequence_from("events.jsonl")

    def _read_event_sequence_from(self, filename: str) -> int:
        path = self.root / filename
        if not path.exists():
            return 0
        last_sequence = 0
        with path.open() as handle:
            for line in handle:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                sequence = payload.get("event_sequence")
                if type(sequence) is int and sequence >= 0:
                    last_sequence = max(last_sequence, sequence)
        return last_sequence

    def publish_status(self, state: str, **fields: Any) -> dict[str, Any]:
        self._state_version = max(
            self._state_version,
            self._read_counter("status.json", "state_version"),
        )
        self._state_version += 1
        payload = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.manifest.campaign_id,
            "state": state,
            "state_version": self._state_version,
            "last_command_sequence": self._last_command_sequence,
            "timestamp": time.time(),
            **fields,
        }
        _write_json_file(self.root / "status.json", payload, exclusive=False)
        return payload

    def publish_event(self, kind: str, **fields: Any) -> dict[str, Any]:
        self._event_sequence = max(
            self._event_sequence,
            self._read_event_sequence(),
        )
        self._event_sequence += 1
        payload = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.manifest.campaign_id,
            "kind": kind,
            "event_sequence": self._event_sequence,
            "timestamp": time.time(),
            **fields,
        }
        _append_event(self.root / "events.jsonl", payload)
        return payload

    def publish_host_action_status(self, state: str, **fields: Any) -> dict[str, Any]:
        self._host_action_state_version = (
            max(
                self._host_action_state_version,
                self._read_counter("host_action_status.json", "state_version"),
            )
            + 1
        )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.manifest.campaign_id,
            "state": state,
            "state_version": self._host_action_state_version,
            "last_request_sequence": self._last_host_action_sequence,
            "timestamp": time.time(),
            **fields,
        }
        _write_json_file(
            self.root / "host_action_status.json", payload, exclusive=False
        )
        return payload

    def publish_host_action_event(self, kind: str, **fields: Any) -> dict[str, Any]:
        self._host_action_event_sequence = (
            max(
                self._host_action_event_sequence,
                self._read_event_sequence_from("host_action_events.jsonl"),
            )
            + 1
        )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.manifest.campaign_id,
            "kind": kind,
            "event_sequence": self._host_action_event_sequence,
            "timestamp": time.time(),
            **fields,
        }
        _append_event(self.root / "host_action_events.jsonl", payload)
        return payload

    def submit_command(
        self,
        *,
        sequence: int,
        expected_state_version: int,
        action: BoundaryAction,
        reason: str,
        expires_at: float,
    ) -> Path:
        command = CampaignCommand(
            campaign_id=self.manifest.campaign_id,
            sequence=sequence,
            expected_state_version=expected_state_version,
            action=action,
            reason=reason,
            expires_at=expires_at,
        )
        command.validate(self.manifest.campaign_id)
        path = self.root / "commands" / f"{sequence:020d}.json"
        _write_json_file(path, command.to_payload(), exclusive=True)
        return path

    def submit_host_action_request(
        self,
        *,
        sequence: int,
        expected_state_version: int,
        action_id: str,
        reason: str,
        expires_at: float,
    ) -> Path:
        request = HostActionRequest(
            campaign_id=self.manifest.campaign_id,
            sequence=sequence,
            expected_state_version=expected_state_version,
            action_id=action_id,
            reason=reason,
            expires_at=expires_at,
        )
        request.validate(self.manifest.campaign_id)
        path = self.root / "host_action_requests" / f"{sequence:020d}.json"
        _write_json_file(path, asdict(request), exclusive=True)
        return path

    def _acknowledge(
        self,
        command: CampaignCommand,
        *,
        accepted: bool,
        reason: str,
    ) -> None:
        self._write_acknowledgment(
            sequence=command.sequence,
            action=command.action.value,
            accepted=accepted,
            reason=reason,
        )

    def _write_acknowledgment(
        self,
        *,
        sequence: int,
        action: str,
        accepted: bool,
        reason: str,
    ) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.manifest.campaign_id,
            "sequence": sequence,
            "action": action,
            "accepted": accepted,
            "reason": reason,
            "timestamp": time.time(),
        }
        path = self.root / "acknowledgments" / f"{sequence:020d}.json"
        _write_json_file(path, payload, exclusive=True)

    def _record_command_cursor(self, sequence: int) -> None:
        self._last_command_sequence = sequence
        _write_json_file(
            self.root / "command_cursor.json",
            {"last_command_sequence": sequence},
            exclusive=False,
        )

    def _record_host_action_cursor(self, sequence: int) -> None:
        self._last_host_action_sequence = sequence
        _write_json_file(
            self.root / "host_action_cursor.json",
            {"last_host_action_sequence": sequence},
            exclusive=False,
        )

    def _new_command_paths(self) -> list[Path]:
        self._last_command_sequence = max(
            self._last_command_sequence,
            self._read_counter("command_cursor.json", "last_command_sequence"),
        )
        paths = []
        for path in (self.root / "commands").glob("*.json"):
            try:
                sequence = int(path.stem)
            except ValueError:
                continue
            if sequence > self._last_command_sequence:
                paths.append(path)
        return sorted(paths)

    def _load_command(self, path: Path) -> CampaignCommand:
        if path.is_symlink():
            raise CampaignProtocolError("command must not be a symbolic link")
        with path.open(encoding="utf-8") as handle:
            command = CampaignCommand.from_payload(json.load(handle))
        command.validate(self.manifest.campaign_id)
        if command.sequence != int(path.stem):
            raise CampaignProtocolError("command sequence does not match filename")
        return command

    def _new_host_action_paths(self) -> list[Path]:
        self._last_host_action_sequence = max(
            self._last_host_action_sequence,
            self._read_counter("host_action_cursor.json", "last_host_action_sequence"),
        )
        return sorted(
            path
            for path in (self.root / "host_action_requests").glob("*.json")
            if path.stem.isdigit() and int(path.stem) > self._last_host_action_sequence
        )

    def _write_host_action_acknowledgment(
        self,
        *,
        sequence: int,
        action_id: str,
        accepted: bool,
        reason: str,
    ) -> None:
        _write_json_file(
            self.root / "host_action_acknowledgments" / f"{sequence:020d}.json",
            {
                "schema_version": SCHEMA_VERSION,
                "campaign_id": self.manifest.campaign_id,
                "sequence": sequence,
                "action_id": action_id,
                "accepted": accepted,
                "reason": reason,
                "timestamp": time.time(),
            },
            exclusive=True,
        )

    async def wait_for_host_action_request(
        self, *, expected_state_version: int
    ) -> HostActionRequest:
        deadline = time.monotonic() + self.manifest.command_timeout_seconds
        while time.monotonic() < deadline:
            for path in self._new_host_action_paths():
                sequence = int(path.stem)
                try:
                    if path.is_symlink():
                        raise CampaignProtocolError(
                            "host action request cannot be symlink"
                        )
                    with path.open(encoding="utf-8") as handle:
                        request = HostActionRequest.from_payload(json.load(handle))
                    request.validate(self.manifest.campaign_id)
                    if request.sequence != sequence:
                        raise CampaignProtocolError(
                            "host action request sequence does not match filename"
                        )
                except (
                    CampaignProtocolError,
                    json.JSONDecodeError,
                    OSError,
                    UnicodeDecodeError,
                ) as error:
                    self._record_host_action_cursor(sequence)
                    self._write_host_action_acknowledgment(
                        sequence=sequence,
                        action_id="INVALID",
                        accepted=False,
                        reason=str(error),
                    )
                    continue
                self._record_host_action_cursor(request.sequence)
                rejection = None
                if request.expected_state_version != expected_state_version:
                    rejection = "host action state version does not match"
                elif request.expires_at <= time.time():
                    rejection = "host action request expired"
                elif self.manifest.get_host_action(request.action_id) is None:
                    rejection = "host action ID is not approved"
                if rejection is not None:
                    self._write_host_action_acknowledgment(
                        sequence=request.sequence,
                        action_id=request.action_id,
                        accepted=False,
                        reason=rejection,
                    )
                    continue
                self._write_host_action_acknowledgment(
                    sequence=request.sequence,
                    action_id=request.action_id,
                    accepted=True,
                    reason="accepted",
                )
                return request
            await asyncio.sleep(self.manifest.poll_interval_seconds)
        self.publish_host_action_status("REQUEST_TIMEOUT")
        raise TimeoutError("timed out waiting for host action request")

    async def wait_for_boundary_action(
        self,
        *,
        expected_state_version: int,
        allowed_actions: Set[BoundaryAction],
    ) -> BoundaryAction:
        deadline = time.monotonic() + self.manifest.command_timeout_seconds
        while time.monotonic() < deadline:
            for path in self._new_command_paths():
                try:
                    command = self._load_command(path)
                except (
                    CampaignProtocolError,
                    json.JSONDecodeError,
                    OSError,
                    UnicodeDecodeError,
                ) as error:
                    sequence = int(path.stem)
                    self._record_command_cursor(sequence)
                    self._write_acknowledgment(
                        sequence=sequence,
                        action="INVALID",
                        accepted=False,
                        reason=str(error),
                    )
                    continue
                self._record_command_cursor(command.sequence)
                rejection = None
                if command.expected_state_version != expected_state_version:
                    rejection = "command state version does not match"
                elif command.expires_at <= time.time():
                    rejection = "command expired"
                elif command.action not in allowed_actions:
                    rejection = f"action {command.action.value} is not allowed"
                if rejection is not None:
                    self._acknowledge(command, accepted=False, reason=rejection)
                    continue
                self._acknowledge(command, accepted=True, reason="accepted")
                return command.action
            await asyncio.sleep(self.manifest.poll_interval_seconds)
        self.publish_status(
            "COMMAND_TIMEOUT",
            expected_state_version=expected_state_version,
        )
        return BoundaryAction.STOP_FOR_PATCH

    def record_cleanup(
        self, *, success: bool, error: str | None = None
    ) -> dict[str, Any]:
        state = "CLEAN" if success else "RECOVERY_REQUIRED"
        self.publish_event("CLEANUP_FINISHED", success=success, error=error)
        return self.publish_status(state, error=error)

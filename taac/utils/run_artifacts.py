#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Run-artifact declarations — OSS-safe, no framework dependencies.

Producers that write a file belonging to the current run declare it here; the
runner decides how to surface it. Neither side imports the other, which is the
point: a collector must not need to know whether the runner inlines its rows,
links them, or drops them.

Declaration happens at construction, BEFORE the file exists — a collector
names its path in ``__init__`` but writes nothing until its first poll, and a
run that dies in setUp still declared paths worth reporting. Consumers
therefore treat a missing file as ordinary, not as an error.

Append-only for the life of the process. Deliberately NOT cleared by
test-config teardown: the runner dumps at end-of-run, long after each config
has torn down, so anything cleared at teardown would be invisible exactly when
it is wanted.

Labels are the user-facing name — they appear in ``--dump-artifacts``
selectors — so they are short, stable, snake_case, and shared with the
collector registry's keys (``cpu_utilization``, ``memory_utilization``,
``systemd_state``) rather than being class names.
"""

import fnmatch
import typing as t
from dataclasses import dataclass
from enum import Enum


class ArtifactKind(Enum):
    """How a consumer may render this artifact.

    The renderer switches on this rather than sniffing file extensions, so a
    producer of a new format declares its own semantics instead of every
    consumer growing a special case.
    """

    # Line-oriented text; safe to inline into a log stream.
    TEXT = "text"
    # Not inlinable (images, pcaps, tarballs). Consumers report the path.
    BINARY = "binary"


# Selector term that disables dumping outright. Honoured ahead of every other
# term so a wrapper can switch off an inherited default without having to
# reconstruct the rest of the selector.
DISABLE_TERM = "none"
# Selector term matching every artifact regardless of kind.
ALL_TERM = "all"


@dataclass(frozen=True)
class RunArtifact:
    path: str
    label: str
    kind: ArtifactKind = ArtifactKind.TEXT
    # Per-artifact cap, applied by the consumer at render time rather than at
    # declaration: the same artifact may be tailed into a console stream and
    # taken whole by a file consumer. None means no cap.
    max_lines: t.Optional[int] = None


_artifacts: t.List[RunArtifact] = []


def declare_artifact(
    path: str,
    label: str,
    kind: ArtifactKind = ArtifactKind.TEXT,
    max_lines: t.Optional[int] = None,
) -> RunArtifact:
    """Declare a file this run produced. Idempotent per path.

    Re-declaring a path returns the existing entry unchanged — back-to-back
    test configs in one runner process re-create their producers, and the
    second declaration must not duplicate the artifact or silently retitle the
    first. Returns the artifact so a producer can hold onto it.
    """
    for existing in _artifacts:
        if existing.path == path:
            return existing
    artifact = RunArtifact(
        path=path, label=label, kind=kind, max_lines=max_lines
    )
    _artifacts.append(artifact)
    return artifact


def get_artifacts(
    kind: t.Optional[ArtifactKind] = None,
) -> t.List[RunArtifact]:
    """Snapshot copy, in declaration order. Optionally filtered by kind."""
    if kind is None:
        return list(_artifacts)
    return [a for a in _artifacts if a.kind is kind]


def is_dump_disabled(selector: str) -> bool:
    """True when ``selector`` switches dumping off entirely.

    Distinct from "matched nothing": an explicit ``none`` is a deliberate
    choice and must not warn, whereas a selector that matches no artifact is
    probably a typo and should.
    """
    terms = _parse_selector(selector)
    return not terms or DISABLE_TERM in terms


def select_artifacts(selector: str) -> t.List[RunArtifact]:
    """Artifacts matching a comma-separated selector, in declaration order.

    Each term is either a kind (``text``, ``binary``, ``all``, ``none``) or an
    fnmatch glob over labels; the result is the union of all terms. Globs
    rather than exact names because producers come in families — ``hrt_*``
    is the selector someone actually wants, not ten names typed by hand.
    """
    terms = _parse_selector(selector)
    if not terms or DISABLE_TERM in terms:
        return []
    return [a for a in _artifacts if _matches_any(a, terms)]


def read_artifact_lines(
    artifact: RunArtifact,
    max_lines: t.Optional[int] = None,
) -> t.Tuple[t.List[str], int]:
    """Read an artifact's lines, plus the count omitted by the cap.

    Returns ``(lines, omitted)``. ``omitted > 0`` means the tail is being
    shown and the consumer should say so — silent truncation reads as a
    complete file. The tail rather than the head because these are poll logs:
    the most recent samples are what a reader came for.

    An explicit ``max_lines`` overrides the artifact's own. Raises OSError on
    an unreadable file: whether that is fatal is the consumer's call, not this
    module's.
    """
    cap = max_lines if max_lines is not None else artifact.max_lines
    with open(artifact.path) as f:
        lines = f.read().splitlines()
    if cap is None or len(lines) <= cap:
        return lines, 0
    return lines[-cap:], len(lines) - cap


def clear_artifacts() -> None:
    """Test-only. Nothing in a real run clears artifacts (see module docstring)."""
    _artifacts.clear()


def _parse_selector(selector: str) -> t.List[str]:
    return [term.strip().lower() for term in selector.split(",") if term.strip()]


def _matches_any(artifact: RunArtifact, terms: t.Sequence[str]) -> bool:
    for term in terms:
        if term == ALL_TERM:
            return True
        if term in (ArtifactKind.TEXT.value, ArtifactKind.BINARY.value):
            if artifact.kind.value == term:
                return True
            continue
        if fnmatch.fnmatch(artifact.label.lower(), term):
            return True
    return False

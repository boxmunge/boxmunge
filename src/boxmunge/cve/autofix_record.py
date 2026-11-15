# SPDX-License-Identifier: Apache-2.0
"""What autofix patched, per project, and the marker of a patch in progress.

Every patch the box applies is recorded in `state/autofix/<project>.json`,
{"version", "records": [...]}, one record per patched service: the image it
was built FROM (`base_ref`, `base_digest`), the local image it built
(`patched_ref`, `boxmunge.invalid/<project>/<service>:autofix-<id12>`, and
`patched_image_id`, the full `sha256:...` ID), the packages it changed, the
CVEs it fixed, when, and what triggered it. Status and security show them,
the deploy guard refuses bringing a patched CVE back, and upstream catch-up
replaces them. They belong to the release they were made for: a successful
release switch forgets them with the image pins
(commands.deploy_steps.clear_release_overrides).

While a patch is being built and started, `state/autofix/<project>.active`
holds {started_at, cves, downtime} (downtime: the project is down for it).

Both files are deploy-writable state that root reads: through fs_nofollow,
times timezone-aware UTC and not in the future, and anything unusable
raises StateError naming the file.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, cast

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.state import StateError

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from boxmunge.paths import BoxPaths

RECORD_VERSION = 1
_CLOCK_SKEW = timedelta(seconds=60)
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
_TRIGGERS = ("urgent", "nightly")

Trigger = Literal["urgent", "nightly"]


@dataclass(frozen=True)
class PackageChange:
    name: str
    before: str
    after: str


@dataclass(frozen=True)
class PatchRecord:
    project: str
    service: str
    base_ref: str
    base_digest: str          # the image the patch was built FROM
    patched_ref: str          # boxmunge.invalid/<project>/<service>:autofix-<id12>
    patched_image_id: str     # full sha256:..., the local image ID
    packages: tuple[PackageChange, ...]
    cves: tuple[str, ...]
    created_at: datetime
    trigger: Trigger


@dataclass(frozen=True)
class AutofixingMarker:
    started_at: datetime
    cves: tuple[str, ...]
    downtime: bool


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} is {value!r}, not a time")
    when = datetime.fromisoformat(value)
    if when.tzinfo is None:
        raise ValueError(f"{field} {value!r} has no timezone")
    if when > datetime.now(timezone.utc) + _CLOCK_SKEW:
        raise ValueError(f"{field} {value!r} is in the future")
    return when


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is {value!r}, not a non-empty string")
    return value


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{field} is not a list")
    return tuple(_text(v, field) for v in value)


def _read_doc(path: Path, what: str) -> Any:
    try:
        text = read_text_nofollow_or_none(path)
        return None if text is None else json.loads(text)
    except (OSError, ValueError) as e:   # UnicodeDecodeError, JSONDecodeError are ValueErrors
        raise StateError(f"cannot read the {what} {path}: {e!r}") from e


def _write_doc(path: Path, doc: dict[str, Any], what: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps(doc, indent=2) + "\n")
    except OSError as e:
        raise StateError(f"cannot write the {what} {path}: {e}") from e


def _unlink(path: Path, what: str) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        raise StateError(f"cannot remove the {what} {path}: {e}") from e


def _record(item: Any, project: str) -> PatchRecord:
    if not isinstance(item, dict):
        raise ValueError(f"a record is {item!r}, not an object")
    if _text(item["project"], "project") != project:
        raise ValueError(f"a record names project {item['project']!r}, not {project!r}")
    service = _text(item["service"], "service")
    ref = _text(item["patched_ref"], "patched_ref")
    prefix = f"boxmunge.invalid/{project}/{service}:autofix-"
    if not ref.startswith(prefix) or not re.fullmatch(r"[0-9a-f]{12}", ref[len(prefix):]):
        raise ValueError(f"patched_ref {ref!r} is not {prefix}<12 hex>")
    image_id = _text(item["patched_image_id"], "patched_image_id")
    if not _IMAGE_ID_RE.fullmatch(image_id):
        raise ValueError(f"patched_image_id {image_id!r} is not a sha256 image ID")
    if item["trigger"] not in _TRIGGERS:
        raise ValueError(f"trigger {item['trigger']!r} is not one of {_TRIGGERS}")
    packages = item["packages"]
    if not isinstance(packages, list):
        raise ValueError("packages is not a list")
    return PatchRecord(
        project=project, service=service, base_ref=_text(item["base_ref"], "base_ref"),
        base_digest=_text(item["base_digest"], "base_digest"), patched_ref=ref,
        patched_image_id=image_id,
        packages=tuple(PackageChange(_text(p["name"], "package name"),
                                     _text(p["before"], "package before"),
                                     _text(p["after"], "package after")) for p in packages),
        cves=_strings(item["cves"], "cves"), created_at=_time(item["created_at"], "created_at"),
        trigger=cast(Trigger, item["trigger"]))


def read_records(paths: BoxPaths, project: str) -> tuple[PatchRecord, ...]:
    """The project's patch records; () when it has none. Raises StateError."""
    path = paths.project_autofix_records(project)
    doc = _read_doc(path, "autofix record")
    if doc is None:
        return ()
    try:
        if not isinstance(doc, dict) or set(doc) != {"version", "records"}:
            raise ValueError('expected {"version", "records"}')
        if doc["version"] != RECORD_VERSION:
            raise ValueError(f"version {doc['version']!r}, expected {RECORD_VERSION}")
        if not isinstance(doc["records"], list) or not doc["records"]:
            raise ValueError("records must be a non-empty list")
        records = tuple(_record(item, project) for item in doc["records"])
        services = [r.service for r in records]
        if len(set(services)) != len(services):
            raise ValueError("a service has more than one record")
        return records
    except (ValueError, KeyError, TypeError) as e:
        raise StateError(f"{path} is not an autofix record: {e!r}") from e


def write_records(paths: BoxPaths, project: str, records: Sequence[PatchRecord]) -> None:
    """Replace the project's records (none: remove the file). Raises StateError."""
    if not records:
        clear_records(paths, project)
        return
    rows = [{"project": r.project, "service": r.service, "base_ref": r.base_ref,
             "base_digest": r.base_digest, "patched_ref": r.patched_ref,
             "patched_image_id": r.patched_image_id,
             "packages": [{"name": p.name, "before": p.before, "after": p.after}
                          for p in r.packages],
             "cves": list(r.cves), "created_at": r.created_at.isoformat(),
             "trigger": r.trigger} for r in records]
    _write_doc(paths.project_autofix_records(project),
               {"version": RECORD_VERSION, "records": rows}, "autofix record")


def clear_records(paths: BoxPaths, project: str) -> None:
    _unlink(paths.project_autofix_records(project), "autofix record")


def mark_autofixing(paths: BoxPaths, project: str, cves: Sequence[str], *,
                    downtime: bool) -> AutofixingMarker:
    marker = AutofixingMarker(datetime.now(timezone.utc), tuple(cves), downtime)
    _write_doc(paths.project_autofix_marker(project),
               {"started_at": marker.started_at.isoformat(), "cves": list(marker.cves),
                "downtime": downtime}, "autofixing marker")
    return marker


def clear_autofixing(paths: BoxPaths, project: str) -> None:
    _unlink(paths.project_autofix_marker(project), "autofixing marker")


def read_autofixing(paths: BoxPaths, project: str) -> AutofixingMarker | None:
    """The marker of a patch in progress, or None. Raises StateError."""
    path = paths.project_autofix_marker(project)
    doc = _read_doc(path, "autofixing marker")
    if doc is None:
        return None
    try:
        if not isinstance(doc, dict) or set(doc) != {"started_at", "cves", "downtime"}:
            raise ValueError("expected {started_at, cves, downtime}")
        if not isinstance(doc["downtime"], bool):
            raise ValueError(f"downtime is {doc['downtime']!r}, not a boolean")
        return AutofixingMarker(_time(doc["started_at"], "started_at"),
                                _strings(doc["cves"], "cves"), doc["downtime"])
    except (ValueError, KeyError, TypeError) as e:
        raise StateError(f"{path} is not an autofixing marker: {e!r}") from e

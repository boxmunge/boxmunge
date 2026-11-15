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

A finding the urgent flow patches waits in `state/autofix/queue/<project>.json`,
{detected_at, findings: [{cve_id, package, image_ref}], downtime}, until the
end of the scan or KEV watch run that found it (commands.autofix_urgent).

From just before an autofix swaps its images in until it has finished
(its patched images healthy and recorded, or rolled back), `state/autofix/<project>.journal`
holds {started_at, pins_before, records_before, built}: the project's pins and
patch records exactly as they were, and the images the run built, as pins.
A journal left behind means the run was killed; the next run undoes it
first (cve.autofix_run.recover_interrupted).

All four are deploy-writable state that root reads: through fs_nofollow,
times timezone-aware UTC and not in the future, and anything unusable
raises StateError naming the file.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.image_pins import ImagePin
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

    def __post_init__(self) -> None:
        """Whatever builds a record, read or written, meets the same rules."""
        for field in ("project", "service", "base_ref", "base_digest"):
            _text(getattr(self, field), field)
        prefix = f"boxmunge.invalid/{self.project}/{self.service}:autofix-"
        tag = self.patched_ref[len(prefix):]
        if not self.patched_ref.startswith(prefix) or not re.fullmatch(r"[0-9a-f]{12}", tag):
            raise ValueError(f"patched_ref {self.patched_ref!r} is not {prefix}<12 hex>")
        if not isinstance(self.patched_image_id, str) \
                or not _IMAGE_ID_RE.fullmatch(self.patched_image_id):
            raise ValueError(f"patched_image_id {self.patched_image_id!r} is not a sha256 image ID")
        if self.trigger not in _TRIGGERS:
            raise ValueError(f"trigger {self.trigger!r} is not one of {_TRIGGERS}")
        for change in self.packages:
            if not isinstance(change, PackageChange):
                raise ValueError(f"package change {change!r} is not a PackageChange")
            for field in ("name", "before", "after"):
                _text(getattr(change, field), f"package {field}")
        for cve in self.cves:
            _text(cve, "cve")
        _check_time(self.created_at, "created_at")


@dataclass(frozen=True)
class AutofixingMarker:
    started_at: datetime
    cves: tuple[str, ...]
    downtime: bool


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} is {value!r}, not a time")
    return _check_time(datetime.fromisoformat(value), field)


def _check_time(when: Any, field: str) -> datetime:
    if not isinstance(when, datetime):
        raise ValueError(f"{field} is {when!r}, not a time")
    value = when.isoformat()
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
    try:   # atomic_write_text makes the directory deploy-owned (mkdir_p_deploy)
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
    if item["project"] != project:
        raise ValueError(f"a record names project {item['project']!r}, not {project!r}")
    packages = item["packages"]
    if not isinstance(packages, list):
        raise ValueError("packages is not a list")
    return PatchRecord(
        project=project, service=item["service"], base_ref=item["base_ref"],
        base_digest=item["base_digest"], patched_ref=item["patched_ref"],
        patched_image_id=item["patched_image_id"],
        packages=tuple(PackageChange(p["name"], p["before"], p["after"]) for p in packages),
        cves=_strings(item["cves"], "cves"), created_at=_time(item["created_at"], "created_at"),
        trigger=item["trigger"])


def _unique_services(records: Sequence[PatchRecord]) -> None:
    services = [r.service for r in records]
    if len(set(services)) != len(services):
        raise ValueError("a service has more than one record")


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
        _unique_services(records)
        return records
    except (ValueError, KeyError, TypeError) as e:
        raise StateError(f"{path} is not an autofix record: {e!r}") from e


def write_records(paths: BoxPaths, project: str, records: Sequence[PatchRecord]) -> None:
    """Replace the project's records (none: remove the file). Raises StateError."""
    if not records:
        clear_records(paths, project)
        return
    try:
        for r in records:
            if r.project != project:
                raise ValueError(f"a record names project {r.project!r}, not {project!r}")
        _unique_services(records)
    except ValueError as e:
        raise StateError(f"refusing to write a bad autofix record for {project}: {e}") from e
    _write_doc(paths.project_autofix_records(project),
               {"version": RECORD_VERSION, "records": _record_rows(records)}, "autofix record")


def _record_rows(records: Sequence[PatchRecord]) -> list[dict[str, Any]]:
    return [{"project": r.project, "service": r.service, "base_ref": r.base_ref,
             "base_digest": r.base_digest, "patched_ref": r.patched_ref,
             "patched_image_id": r.patched_image_id,
             "packages": [{"name": p.name, "before": p.before, "after": p.after}
                          for p in r.packages],
             "cves": list(r.cves), "created_at": r.created_at.isoformat(),
             "trigger": r.trigger} for r in records]


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


@dataclass(frozen=True)
class QueuedFinding:
    cve_id: str
    package: str
    image_ref: str


@dataclass(frozen=True)
class QueueEntry:
    """A project's urgent patch, waiting to run: what was found, when, and
    whether the project was taken down for it."""
    detected_at: datetime
    findings: tuple[QueuedFinding, ...]
    downtime: bool

    @property
    def cves(self) -> tuple[str, ...]:
        return tuple(sorted({f.cve_id for f in self.findings}))


def write_queue_entry(paths: BoxPaths, project: str, entry: QueueEntry) -> None:
    if not entry.findings:
        raise StateError(f"refusing to queue an autofix of {project} with no findings")
    _write_doc(paths.project_autofix_queue(project), {
        "detected_at": entry.detected_at.isoformat(), "downtime": entry.downtime,
        "findings": [{"cve_id": f.cve_id, "package": f.package, "image_ref": f.image_ref}
                     for f in entry.findings]}, "autofix queue entry")


def read_queue_entry(paths: BoxPaths, project: str) -> QueueEntry | None:
    """The project's queued urgent patch, or None. Raises StateError."""
    path = paths.project_autofix_queue(project)
    doc = _read_doc(path, "autofix queue entry")
    if doc is None:
        return None
    try:
        if not isinstance(doc, dict) or set(doc) != {"detected_at", "findings", "downtime"}:
            raise ValueError("expected {detected_at, findings, downtime}")
        if not isinstance(doc["downtime"], bool):
            raise ValueError(f"downtime is {doc['downtime']!r}, not a boolean")
        rows = doc["findings"]
        if not isinstance(rows, list) or not rows:
            raise ValueError("findings must be a non-empty list")
        findings = tuple(QueuedFinding(_text(r["cve_id"], "cve_id"), _text(r["package"], "package"),
                                       _text(r["image_ref"], "image_ref")) for r in rows)
        return QueueEntry(_time(doc["detected_at"], "detected_at"), findings, doc["downtime"])
    except (ValueError, KeyError, TypeError) as e:
        raise StateError(f"{path} is not an autofix queue entry: {e!r}") from e


def remove_queue_entry(paths: BoxPaths, project: str) -> None:
    _unlink(paths.project_autofix_queue(project), "autofix queue entry")


def queued_projects(paths: BoxPaths) -> tuple[str, ...]:
    """The names with a queue entry (`<name>.json`), sorted; the caller
    validates each as a project name. Raises StateError."""
    return _names(paths.autofix_queue_dir, ".json")


def _names(directory: Path, suffix: str) -> tuple[str, ...]:
    try:
        names = [e.name for e in directory.iterdir()]
    except FileNotFoundError:
        return ()
    except OSError as e:
        raise StateError(f"cannot list {directory}: {e}") from e
    return tuple(sorted(n[:-len(suffix)] for n in names
                        if n.endswith(suffix) and not n.startswith(".")))


@dataclass(frozen=True)
class AutofixJournal:
    """What an autofix run that was killed left to undo."""
    started_at: datetime
    pins_before: tuple[ImagePin, ...]
    records_before: tuple[PatchRecord, ...]
    built: tuple[ImagePin, ...]


def _pin_rows(pins: Sequence[ImagePin]) -> list[dict[str, str]]:
    return [{"service": p.service, "ref": p.ref, "image_id": p.image_id, "reason": p.reason}
            for p in pins]


def _pins(rows: Any, field: str) -> tuple[ImagePin, ...]:
    if not isinstance(rows, list):
        raise ValueError(f"{field} is not a list")
    return tuple(ImagePin(r["service"], r["ref"], r["image_id"], r["reason"]) for r in rows)


def write_journal(paths: BoxPaths, project: str, journal: AutofixJournal) -> None:
    _write_doc(paths.project_autofix_journal(project), {
        "started_at": journal.started_at.isoformat(),
        "pins_before": _pin_rows(journal.pins_before),
        "records_before": _record_rows(journal.records_before),
        "built": _pin_rows(journal.built),
    }, "autofix journal")


def read_journal(paths: BoxPaths, project: str) -> AutofixJournal | None:
    """The journal of a run that did not finish, or None. Raises StateError."""
    path = paths.project_autofix_journal(project)
    doc = _read_doc(path, "autofix journal")
    if doc is None:
        return None
    try:
        keys = {"started_at", "pins_before", "records_before", "built"}
        if not isinstance(doc, dict) or set(doc) != keys:
            raise ValueError("expected {started_at, pins_before, records_before, built}")
        rows = doc["records_before"]
        if not isinstance(rows, list):
            raise ValueError("records_before is not a list")
        records = tuple(_record(item, project) for item in rows)
        _unique_services(records)
        return AutofixJournal(_time(doc["started_at"], "started_at"),
                              _pins(doc["pins_before"], "pins_before"), records,
                              _pins(doc["built"], "built"))
    except (ValueError, KeyError, TypeError) as e:
        raise StateError(f"{path} is not an autofix journal: {e!r}") from e


def remove_journal(paths: BoxPaths, project: str) -> None:
    _unlink(paths.project_autofix_journal(project), "autofix journal")


def journaled_projects(paths: BoxPaths) -> tuple[str, ...]:
    """The names with a journal (`<name>.journal`), sorted; the caller
    validates each as a project name. Raises StateError."""
    return _names(paths.state / "autofix", ".journal")

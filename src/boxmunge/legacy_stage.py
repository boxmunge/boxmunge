# SPDX-License-Identifier: Apache-2.0
"""Stages left by boxmunge 0.10.1, in the old layout (staged release in the
project dir, production's kept in .releases/prestage/).

This is the only module that knows the old layout. The upgrade never
migrates such a stage (D9): the project keeps running its current
containers, every production start or deploy for it is refused, and the
operator resolves it with `boxmunge-server legacy-stage <p>` once a
platform rollback is no longer possible. Delete this module (with the
reserved BOXMUNGE_ENTRIES / CONTROL_ENTRIES names) in the first minor whose
upgrade floor is the beta.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from boxmunge import docker_containers
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import atomic_write_text, exclusive_lock, read_text_nofollow
from boxmunge.git_slot import GitRefError, head_sha, rev_parse
from boxmunge.notify import notify
from boxmunge.state import StateError, read_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

LEGACY_STAGING_FILES = ("compose.staging-base.yml", "compose.boxmunge-staging.yml")


@dataclass(frozen=True)
class LegacyStage:
    kind: str   # "bundle" | "git" | "leftover"


def legacy_staging_state(paths: BoxPaths, project: str) -> Path:
    return paths.state / "staging" / f"{project}.json"


def _present(path: Path) -> bool:
    """Whether anything (a dangling link included) is at ``path``. Unlike
    os.path.lexists, an error other than absence (EACCES) is raised: it
    must not read as "no stage"."""
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def _state_active(paths: BoxPaths, project: str) -> bool:
    path = legacy_staging_state(paths, project)
    if not _present(path):
        return False
    try:
        doc = json.loads(read_text_nofollow(path))
    except (OSError, ValueError):  # a link, a FIFO or garbage: still a stage
        doc = None
    if not isinstance(doc, dict):
        return True  # unreadable: treat as a stage; legacy-stage shows the evidence
    return bool(doc.get("active"))


def legacy_stage(paths: BoxPaths, project: str) -> LegacyStage | None:
    """Read-only detection (spec 'Migration', Detection table). Raises
    OSError when it cannot tell (legacy_stage_refusal maps that)."""
    project_dir = paths.project_dir(project)
    if _present(project_dir / ".releases" / "prestage"):
        return LegacyStage("bundle")
    staged = _state_active(paths, project) or any(
        _present(project_dir / name) for name in LEGACY_STAGING_FILES)
    if not staged:
        return None
    return LegacyStage("git" if _present(project_dir / "repo") else "leftover")


def real_dir_problem(path: Path) -> str | None:
    """Why `path` is not a real directory, or None. The kept trees are
    deploy-writable, and root must never read or re-own through a link there."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return f"{path} does not exist"
    if stat.S_ISDIR(mode):
        return None
    return f"{path} is not a directory (a link or a file); refusing to read through it"


def legacy_staging_compose(project_dir: Path) -> list[str] | None:
    """The compose files a 0.10.1 stage ran staging from, in the project
    dir, or None when its overlay is not there."""
    if not _present(project_dir / LEGACY_STAGING_FILES[1]):
        return None
    base = (LEGACY_STAGING_FILES[0] if _present(project_dir / LEGACY_STAGING_FILES[0])
            else "compose.yml")
    return [base, LEGACY_STAGING_FILES[1]]


def legacy_refusal(project: str, stage: LegacyStage) -> str:
    return (f"'{project}' has a release staged by boxmunge 0.10.1 ({stage.kind}); the "
            f"project directory may hold the staged files. Resolve it first with: "
            f"boxmunge-server legacy-stage {project}")


def _undetermined(project: str, error: OSError) -> str:
    return f"cannot tell whether a 0.10.1 stage is on disk for '{project}': {error}"


def cannot_tell(project: str, error: OSError) -> str:
    """Why a detection that raised (legacy_stage) cannot tell, and what to do."""
    return f"{_undetermined(project, error)}; fix the permissions (or the error shown), then retry"


def cannot_tell_left_as_is(project: str, error: OSError) -> str:
    """cannot_tell for a project the upgrade left as it is: a retry is not
    the way back to this release's configs; a deploy, resume or recover is."""
    return (f"{_undetermined(project, error)}; it keeps its previous configs: fix the "
            f"cause, then deploy, resume or recover {project}. If a 0.10.1 stage turns "
            f"out to exist, boxmunge-server legacy-stage {project} resolves it")


def legacy_stage_refusal(paths: BoxPaths, project: str) -> str | None:
    """Why ``project`` is refused for a 0.10.1 stage, or None. A detection
    that cannot tell refuses too."""
    try:
        stage = legacy_stage(paths, project)
    except OSError as e:
        return cannot_tell(project, e)
    return None if stage is None else legacy_refusal(project, stage)


def refuse_if_legacy_stage(paths: BoxPaths, project: str) -> bool:
    refusal = legacy_stage_refusal(paths, project)
    if refusal is not None:
        print(f"ERROR: {refusal}", file=sys.stderr)
    return refusal is not None


# -- Evidence: which release production's containers run (spec "Evidence") --

class EvidenceError(Exception):
    """The evidence of what production runs cannot be read."""


@dataclass(frozen=True)
class Evidence:
    classification: str            # "untouched" | "recreated"
    t: datetime                    # when the stage changed the project dir
    current_ref: str | None        # the deploy state's
    staged_ref: str | None         # as recorded
    production_ref: str | None     # bundle: the kept release's ref; git: current_ref's SHA
    head: str | None               # git: repo/ HEAD
    notes: tuple[str, ...] = ()
    # git: the staged ref's full SHA; "?" when short, unresolvable or not
    # recorded (see notes), None for a stage of the checked-out tree.
    staged_sha: str | None = None

    def describe(self) -> list[str]:
        staged = self.staged_ref
        if self.staged_sha and self.staged_sha != self.staged_ref:
            staged = f"{staged} ({self.staged_sha})"
        lines = [f"stage made at {self.t.isoformat()}",
                 f"deploy state current_ref: {self.current_ref}",
                 f"staged ref: {staged}",
                 f"production's release: {self.production_ref}"]
        if self.head:
            lines.append(f"repo/ HEAD: {self.head}")
        lines += list(self.notes)
        lines.append(f"production's containers: {self.classification}")
        return lines


_SHA = re.compile(r"[0-9a-f]{4,40}")


def stage_time(paths: BoxPaths, project: str, stage: LegacyStage) -> datetime:
    """T: the prestage's meta.json mtime (bundle), or the newest checkout in
    repo/'s HEAD reflog (git)."""
    pdir = paths.project_dir(project)
    if stage.kind == "bundle":
        _require_kept_dirs(pdir)
        try:
            st = os.lstat(pdir / ".releases" / "prestage" / "meta.json")
        except OSError as e:
            raise EvidenceError(f"cannot read the kept release's meta.json: {e}") from e
        if not stat.S_ISREG(st.st_mode):
            raise EvidenceError("the kept release's meta.json is not a regular file")
        return datetime.fromtimestamp(st.st_mtime, timezone.utc)
    reflog = pdir / "repo" / ".git" / "logs" / "HEAD"
    try:
        lines = read_text_nofollow(reflog).splitlines()
        times = [int(line.split("\t", 1)[0].split()[-2]) for line in lines
                 if "\tcheckout:" in line]
    except (OSError, UnicodeDecodeError, ValueError, IndexError) as e:
        raise EvidenceError(f"cannot read {reflog}: {e}") from e
    if not times:
        raise EvidenceError(f"{reflog} records no checkout")
    return datetime.fromtimestamp(max(times), timezone.utc)


def _git_full(repo: Path, ref: str | None, label: str, notes: list[str]) -> str | None:
    """A ref as a full SHA; a short or unresolvable one is reported ("?"),
    never guessed. git failing is unreadable evidence, not "no such commit"."""
    if not ref or ref == "latest":
        return None
    if _SHA.fullmatch(ref) and len(ref) < 40:
        notes.append(f"{label} {ref} is a short SHA; it is not compared")
        return "?"
    try:
        sha = rev_parse(repo, ref)
    except GitRefError as e:
        raise EvidenceError(f"cannot resolve {label} {ref}: {e}") from e
    if sha is None:
        notes.append(f"{label} {ref} does not resolve to a commit")
        return "?"
    return sha


def _require_kept_dirs(pdir: Path) -> None:
    for path in (pdir / ".releases", pdir / ".releases" / "prestage"):
        problem = real_dir_problem(path)
        if problem:
            raise EvidenceError(problem)


def _json_doc(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(read_text_nofollow(path))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise EvidenceError(f"cannot read {path}: {e}") from e
    if not isinstance(doc, dict):
        raise EvidenceError(f"{path} is not a JSON object")
    return doc


def _ref_of(path: Path, doc: dict[str, Any]) -> str | None:
    ref = doc.get("ref")
    if ref is not None and not isinstance(ref, str):
        raise EvidenceError(f"{path}: ref {ref!r} is not a string")
    return ref


def _staged_record(paths: BoxPaths, project: str, notes: list[str]) -> tuple[bool, str | None]:
    """(recorded, ref) from state/staging. 0.10.1 checks out the staged ref
    before it writes {"active": true, "ref": ref or "latest"}, so a stage
    killed in between leaves no state, or an earlier unstage's
    {"active": false}: the ref is then unknown, never "no change"."""
    path = legacy_staging_state(paths, project)
    if path.exists():
        doc = _json_doc(path)
        if doc.get("active") is True and "ref" in doc:
            return True, _ref_of(path, doc)
    notes.append("the staged ref is not recorded; it is not compared")
    return False, None


def evidence(paths: BoxPaths, project: str, stage: LegacyStage) -> Evidence:
    """Read-only. Raises EvidenceError when any of it cannot be read."""
    pdir = paths.project_dir(project)
    try:
        current = read_state(paths.project_deploy_state(project)).get("current_ref")
    except StateError as e:
        raise EvidenceError(str(e)) from e
    notes: list[str] = []
    head = staged_sha = None
    if stage.kind == "bundle":
        _require_kept_dirs(pdir)
        live, kept = pdir / ".releases" / "live.json", pdir / ".releases" / "prestage" / "meta.json"
        staged = _ref_of(live, _json_doc(live))
        production = _ref_of(kept, _json_doc(kept))
        shown = staged
    else:
        repo = pdir / "repo"
        recorded, shown = _staged_record(paths, project, notes)
        try:
            head = head_sha(repo)
        except GitRefError as e:
            raise EvidenceError(f"cannot read repo/'s HEAD: {e}") from e
        production = _git_full(repo, current, "current_ref", notes)
        staged = staged_sha = _git_full(repo, shown, "staged ref", notes) if recorded else "?"
        if staged is None or (staged != "?" and staged == production):
            # The stage changed no code: whatever runs, runs production's.
            return Evidence("untouched", stage_time(paths, project, stage), current, shown,
                            production, head, tuple(notes), staged_sha)
    t = stage_time(paths, project, stage)
    try:
        created = docker_containers.created_times(project)
    except DockerError as e:
        raise EvidenceError(f"Docker cannot be asked about the containers: {e}") from e
    # A bundle stage that left the deploy state naming the staged ref was
    # promoted, at least partly; a git one compares SHAs above.
    refs_differ = stage.kind == "git" or current != staged
    untouched = refs_differ and all(c < t for c in created.values())
    return Evidence("untouched" if untouched else "recreated", t, current, shown,
                    production, head, tuple(notes), staged_sha)


# -- The dedupe record (state/legacy-stages.json) and the alert -------------

LEGACY_ALERT = ("{p} has a release staged by boxmunge 0.10.1. It was left as is and keeps "
                "running its current containers; starts, deploys, pause and quarantine are "
                "refused or held until you run `boxmunge-server legacy-stage {p}`.")
ALERT_EVERY = timedelta(hours=24)


def records_path(paths: BoxPaths) -> Path:
    return paths.state / "legacy-stages.json"


def _read_records(paths: BoxPaths) -> dict[str, Any]:
    """The whole record. A corrupt one raises StateError naming the file
    (a per-project input error: check-all reports it and carries on)."""
    path = records_path(paths)
    if not os.path.lexists(path):
        return {}
    try:
        doc = json.loads(read_text_nofollow(path))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise StateError(f"cannot read {path}: {e}; fix or remove it") from e
    if not isinstance(doc, dict) or not all(isinstance(r, dict) for r in doc.values()):
        raise StateError(f"{path} is not a JSON object of per-project objects; "
                         f"fix or remove it")
    return doc


def _last_alert(paths: BoxPaths, rec: dict[str, Any]) -> datetime | None:
    value = rec.get("last_alert")
    if value is None:
        return None
    try:
        when = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        when = None
    if when is None or when.tzinfo is None:
        raise StateError(f"{records_path(paths)}: last_alert {value!r} is not a time with a "
                         f"timezone; fix or remove it")
    return when


@contextmanager
def _records(paths: BoxPaths) -> Iterator[dict[str, Any]]:
    with exclusive_lock(paths.state / ".legacy-stages.lock"):
        doc = _read_records(paths)
        before = json.dumps(doc, sort_keys=True)
        yield doc
        if json.dumps(doc, sort_keys=True) != before:
            atomic_write_text(records_path(paths), json.dumps(doc, indent=2) + "\n",
                              mode=0o644, refuse_link=True)


def get_record(paths: BoxPaths, project: str) -> dict | None:
    return _read_records(paths).get(project)


def update_record(paths: BoxPaths, project: str, **fields: Any) -> dict:
    with _records(paths) as doc:
        rec = doc.setdefault(project, {})
        rec.update(fields)
        return dict(rec)


def drop_record(paths: BoxPaths, project: str) -> None:
    with _records(paths) as doc:
        doc.pop(project, None)


def alert_legacy(paths: BoxPaths, project: str, stage: LegacyStage, *,
                 now: datetime | None = None) -> bool:
    """Alert at priority 1, at most once a day per project. True if sent;
    an undelivered alert is retried on the next call."""
    now = now or datetime.now(timezone.utc)
    with _records(paths) as doc:
        rec = doc.setdefault(project, {})
        for key, value in (("kind", stage.kind), ("first_seen", now.isoformat()),
                           ("last_alert", None), ("choice", None)):
            rec.setdefault(key, value)
        last = _last_alert(paths, rec)
        if last is not None and now - last < ALERT_EVERY:
            return False
        if not notify(paths, f"{project}: release staged by boxmunge 0.10.1",
                      LEGACY_ALERT.format(p=project), component="legacy-stage",
                      project=project, priority=1):
            return False
        rec["last_alert"] = now.isoformat()
        return True

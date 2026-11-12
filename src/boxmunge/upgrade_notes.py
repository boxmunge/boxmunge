# SPDX-License-Identifier: Apache-2.0
"""Upgrade notes as data: what each release asks of projects and boxes.

Every release from FIRST_NOTES_RELEASE has an entry file in the repository,
upgrade-notes/<X.Y.Z>.json. The release workflow compiles them
(compile_notes, through scripts/release-lint.py) into upgrade-notes.json, a
release asset listed in the cosign-signed SHA256SUMS. On a box,
`upgrade-howto` reads the verified bytes (parse_notes) and picks the entries
between the box's release and the target (select).

Entry files are authored, so reading one is strict: an unknown key is a typo
and refused. The compiled document is read by older releases, so parse_notes
ignores keys it does not know: a later release may add keys within format 1.
A new scope, when, kind or class value, or a key whose meaning changes,
needs FORMAT 2, and every value this module does not know fails closed.

Stdlib only, with no boxmunge imports: release-lint loads this file by path
before any dependency is installed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

FORMAT = 1
FIRST_NOTES_RELEASE = "0.11.8"
SCOPES = ("box", "project")
WHENS = ("before", "after")
KINDS = ("required", "recommended", "fact")
FILES = ("manifest.yml", "compose.yml", "Dockerfile")
CLASSES = ("feature", "breakfix", "security")
# The upgrade shim's NOTES_MAX_BYTES: every box refuses a larger document.
MAX_BYTES = 1_048_576
TEXT_LIMITS = {"title": 100, "change": 1000, "verify": 500}

FILE_KEYS = ("version", "no_project_action", "entries")
ENTRY_KEYS = ("id", "scope", "when", "kind", "title", "change", "verify", "files",
              "superseded_by", "refs")
DOC_KEYS = ("format", "release", "floor", "bridge", "releases", "no_action", "entries")
COMPILED = "upgrade-notes.json"

_VERSION_RE = re.compile(r"(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})")
_SLUG = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_REF_RE = re.compile(r"#[1-9][0-9]{0,6}")


class NotesError(ValueError):
    """An entry file or a compiled upgrade-notes.json is invalid."""


@dataclass(frozen=True)
class Entry:
    introduced: str
    id: str
    scope: str
    when: str
    kind: str
    title: str
    change: str
    verify: str
    files: tuple[str, ...]
    superseded_by: str | None
    refs: tuple[str, ...]


@dataclass(frozen=True)
class ReleaseInfo:
    release_class: str
    breaking: bool


@dataclass(frozen=True)
class Notes:
    release: str
    floor: str
    bridge: str
    releases: dict[str, ReleaseInfo]
    no_action: tuple[str, ...]
    entries: tuple[Entry, ...]


@dataclass(frozen=True)
class EntryFile:
    version: str
    no_project_action: bool
    entries: tuple[Entry, ...]


@dataclass(frozen=True)
class Guide:
    installed: str
    target: str
    below_floor: bool
    floor: str
    bridge: str
    box_before: tuple[Entry, ...]
    project_before: tuple[Entry, ...]
    project_after: tuple[Entry, ...]
    box_after: tuple[Entry, ...]
    no_action: tuple[str, ...]


def _show(value: object) -> str:
    """A value quoted for an error message: escaped, and bounded."""
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def version_key(v: object) -> tuple[int, int, int]:
    """X.Y.Z as numbers to compare. Anything else (a v prefix, a pre-release,
    a build, leading zeros) is refused."""
    if not isinstance(v, str) or not _VERSION_RE.fullmatch(v):
        raise NotesError(f"{_show(v)} is not a version X.Y.Z")
    major, minor, patch = (int(n) for n in v.split("."))
    return major, minor, patch


def _version(value: object, where: str) -> str:
    try:
        version_key(value)
    except NotesError as e:
        raise NotesError(f"{where}: {e}") from None
    return value  # type: ignore[return-value]


def _keys(raw: dict, expected: tuple[str, ...], where: str, *, strict: bool) -> None:
    missing = [k for k in expected if k not in raw]
    if missing:
        raise NotesError(f"{where}: missing {', '.join(missing)}")
    unknown = sorted(k for k in raw if k not in expected)
    if strict and unknown:
        raise NotesError(f"{where}: unknown key {', '.join(map(_show, unknown))} "
                         f"(the keys are {', '.join(expected)})")


def _choice(raw: dict, field: str, allowed: tuple[str, ...], where: str) -> str:
    value = raw[field]
    if value not in allowed or not isinstance(value, str):
        raise NotesError(f"{where}: {field} {_show(value)} must be one of {', '.join(allowed)}")
    return value


def _text(raw: dict, field: str, where: str) -> str:
    value, limit = raw[field], TEXT_LIMITS[field]
    if not isinstance(value, str) or not value:
        raise NotesError(f"{where}: {field} must be non-empty text")
    if len(value) > limit:
        raise NotesError(f"{where}: {field} is {len(value)} characters; the limit is {limit}")
    newline_ok = field != "title"
    bad = next((c for c in value if not (c.isprintable() or (newline_ok and c == "\n"))),
               None)
    if bad is not None:
        allowed = "printable characters" + ("" if not newline_ok else " and newlines")
        raise NotesError(f"{where}: {field} holds {_show(bad)}; only {allowed} are allowed")
    return value


def _string_list(raw: dict, field: str, where: str) -> list[str]:
    value = raw[field]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise NotesError(f"{where}: {field} must be a list of strings")
    if len(set(value)) != len(value):
        raise NotesError(f"{where}: {field} lists a name twice")
    return value


def _files(raw: dict, scope: str, where: str) -> tuple[str, ...]:
    files = _string_list(raw, "files", where)
    unknown = [f for f in files if f not in FILES]
    if unknown:
        raise NotesError(f"{where}: files {_show(unknown)}: only {', '.join(FILES)}")
    if scope == "project" and not files:
        raise NotesError(f"{where}: files must name the project files to check "
                         f"({', '.join(FILES)}) for a project entry")
    if scope == "box" and files:
        raise NotesError(f"{where}: files must be [] for a box entry")
    return tuple(f for f in FILES if f in files)


def _refs(raw: dict, where: str) -> tuple[str, ...]:
    refs = _string_list(raw, "refs", where)
    bad = [r for r in refs if not _REF_RE.fullmatch(r)]
    if bad:
        raise NotesError(f"{where}: refs {_show(bad)}: each must be a PR or issue, like #231")
    return tuple(refs)


def _entry(raw: object, introduced: str, where: str, *, strict: bool) -> Entry:
    if not isinstance(raw, dict):
        raise NotesError(f"{where}: an entry must be an object")
    entry_id = raw.get("id")
    if not isinstance(entry_id, str) or not re.fullmatch(re.escape(introduced) + "-" + _SLUG,
                                                         entry_id):
        raise NotesError(f"{where}: id {_show(entry_id)} must be {introduced}-<slug>, the "
                         f"slug in lowercase letters, digits and hyphens")
    where = f"{where} ({entry_id})"
    _keys(raw, ENTRY_KEYS, where, strict=strict)
    scope = _choice(raw, "scope", SCOPES, where)
    superseded_by = raw["superseded_by"]
    if superseded_by is not None:
        _version(superseded_by, f"{where}: superseded_by")
        if version_key(superseded_by) <= version_key(introduced):
            raise NotesError(f"{where}: superseded_by {superseded_by} must be a release "
                             f"later than {introduced}, or null")
    return Entry(introduced=introduced, id=entry_id, scope=scope,
                 when=_choice(raw, "when", WHENS, where),
                 kind=_choice(raw, "kind", KINDS, where),
                 title=_text(raw, "title", where), change=_text(raw, "change", where),
                 verify=_text(raw, "verify", where), files=_files(raw, scope, where),
                 superseded_by=superseded_by, refs=_refs(raw, where))


def _unique_ids(entries: tuple[Entry, ...], where: str) -> None:
    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            raise NotesError(f"{where}: duplicate id {entry.id}")
        seen.add(entry.id)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    doc: dict = {}
    for key, value in pairs:
        if key in doc:
            raise NotesError(f"duplicate key {_show(key)}")
        doc[key] = value
    return doc


def load_entry_file(path: Path) -> EntryFile:
    """One release's entry file, validated. Every error names the file, and
    the entry id and field where there is one."""
    where = f"{path.parent.name}/{path.name}"
    stem = path.name.removesuffix(".json")
    if stem == path.name:
        raise NotesError(f"{where}: an entry file is named <X.Y.Z>.json")
    version = _version(stem, f"{where}: the file name")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_keys)
    except (OSError, ValueError) as e:  # JSONDecodeError and NotesError are ValueErrors
        raise NotesError(f"{where}: not readable JSON: {e}") from e
    if not isinstance(doc, dict):
        raise NotesError(f"{where}: must be a JSON object with {', '.join(FILE_KEYS)}")
    _keys(doc, FILE_KEYS, where, strict=True)
    if doc["version"] != version:
        raise NotesError(f"{where}: version {_show(doc['version'])} must match the file "
                         f"name, {version}")
    no_action, raw_entries = doc["no_project_action"], doc["entries"]
    if not isinstance(no_action, bool):
        raise NotesError(f"{where}: no_project_action must be true or false")
    if not isinstance(raw_entries, list):
        raise NotesError(f"{where}: entries must be a list")
    if no_action and raw_entries:
        raise NotesError(f"{where}: no_project_action is true, so entries must be []; set "
                         f"it to false to publish these entries")
    if not no_action and not raw_entries:
        raise NotesError(f"{where}: entries is empty; add what {version} asks of projects "
                         f"and boxes, or set \"no_project_action\": true if it asks nothing")
    entries = tuple(_entry(raw, version, f"{where}: entries[{i}]", strict=True)
                    for i, raw in enumerate(raw_entries))
    _unique_ids(entries, where)
    return EntryFile(version, no_action, entries)


def _release_info(raw: object, where: str) -> ReleaseInfo:
    if not isinstance(raw, dict):
        raise NotesError(f"{where}: must be an object with class and breaking")
    cls, breaking = raw.get("class"), raw.get("breaking")
    if cls not in CLASSES or not isinstance(cls, str):
        raise NotesError(f"{where}: class {_show(cls)} must be one of {', '.join(CLASSES)}")
    if not isinstance(breaking, bool):
        raise NotesError(f"{where}: breaking must be true or false")
    return ReleaseInfo(cls, breaking)


def _listed_releases(releases_doc: object) -> dict[str, ReleaseInfo]:
    """releases.json's entries by version."""
    rows = releases_doc.get("releases") if isinstance(releases_doc, dict) else None
    if not isinstance(rows, list):
        raise NotesError("releases.json: must be an object with a 'releases' list")
    listed: dict[str, ReleaseInfo] = {}
    for i, row in enumerate(rows):
        where = f"releases.json: releases[{i}]"
        version = _version(row.get("version") if isinstance(row, dict) else None, where)
        if version in listed:
            raise NotesError(f"{where}: duplicate version {version}")
        listed[version] = _release_info(row, f"{where} ({version})")
    return listed


def _check_bounds(floor: str, bridge: str, release: str, where: str) -> None:
    _version(floor, f"{where}floor")
    _version(bridge, f"{where}bridge")
    if not version_key(floor) <= version_key(bridge) <= version_key(release):
        raise NotesError(f"{where}floor {floor}, bridge {bridge} and release {release} "
                         f"must be in that order")


def _entry_doc(entry: Entry) -> dict:
    return {"introduced": entry.introduced, "id": entry.id, "scope": entry.scope,
            "when": entry.when, "kind": entry.kind, "title": entry.title,
            "change": entry.change, "verify": entry.verify, "files": list(entry.files),
            "superseded_by": entry.superseded_by, "refs": list(entry.refs)}


def _ordered(entries) -> tuple[Entry, ...]:
    return tuple(sorted(entries, key=lambda e: (version_key(e.introduced), e.id)))


def compile_notes(notes_dir: Path, release: str, releases_doc: dict, floor: str,
                  bridge: str) -> dict:
    """The upgrade-notes.json document for `release`: every entry file up to
    it, and the class and breaking flag of every release from the floor.
    Every file in the directory is validated, later ones included."""
    _version(release, "release")
    _check_bounds(floor, bridge, release, "")
    listed = _listed_releases(releases_doc)
    if release not in listed:
        raise NotesError(f"{release} is not listed in releases.json; add it with its "
                         f"class and breaking flag")
    if not notes_dir.is_dir():
        raise NotesError(f"{notes_dir}: no upgrade-notes directory")
    files = {f.version: f for f in map(load_entry_file, sorted(notes_dir.glob("*.json")))}
    top = version_key(release)
    shipped = {v: f for v, f in files.items() if version_key(v) <= top}
    for version in sorted(shipped, key=version_key):
        if version not in listed:
            raise NotesError(f"upgrade-notes/{version}.json: {version} is not listed in "
                             f"releases.json; list the release, or remove the file")
    first = version_key(FIRST_NOTES_RELEASE)
    for version in sorted(listed, key=version_key):
        if first <= version_key(version) <= top and version not in files:
            raise NotesError(
                f"no upgrade-notes/{version}.json (looked in {notes_dir}): every release "
                f"from {FIRST_NOTES_RELEASE} has one. Add it with the entries {version} "
                f"asks of projects and boxes, or, if it asks nothing, as "
                f"{{\"version\": \"{version}\", \"no_project_action\": true, "
                f"\"entries\": []}}")
    entries = _ordered(e for f in shipped.values() for e in f.entries)
    for e in entries:
        if e.superseded_by is None:
            continue
        if version_key(e.superseded_by) > top:
            raise NotesError(f"upgrade-notes/{e.introduced}.json ({e.id}): superseded_by "
                             f"{e.superseded_by} is later than the release being built, "
                             f"{release}; set it in the release that supersedes the entry")
        if e.superseded_by not in listed:
            raise NotesError(f"upgrade-notes/{e.introduced}.json ({e.id}): superseded_by "
                             f"{e.superseded_by} is not listed in releases.json")
    doc = {"format": FORMAT, "release": release, "floor": floor, "bridge": bridge,
           "releases": {v: {"class": listed[v].release_class, "breaking": listed[v].breaking}
                        for v in sorted(listed, key=version_key)
                        if version_key(floor) <= version_key(v) <= top},
           "no_action": [v for v in sorted(shipped, key=version_key)
                         if shipped[v].no_project_action],
           "entries": [_entry_doc(e) for e in entries]}
    parse_notes(doc)  # what a box reads back; a failure here is a bug in this module
    return doc


def dump_notes(doc: dict) -> bytes:
    """The bytes a release publishes: ASCII JSON, refused over MAX_BYTES."""
    data = (json.dumps(doc, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    if len(data) > MAX_BYTES:
        raise NotesError(f"{COMPILED} would be {len(data)} bytes; boxes refuse more than "
                         f"{MAX_BYTES}. Mark superseded entries, or shorten them")
    return data


def _string_versions(value: object, release: str, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise NotesError(f"{where} must be a list of versions")
    for v in value:
        if version_key(_version(v, where)) > version_key(release):
            raise NotesError(f"{where}: {v} is later than the release {release}")
    return tuple(value)


def _compiled_entry(raw: object, release: str, where: str) -> Entry:
    if not isinstance(raw, dict):
        raise NotesError(f"{where}: an entry must be an object")
    introduced = _version(raw.get("introduced"), f"{where}: introduced")
    if version_key(introduced) > version_key(release):
        raise NotesError(f"{where}: introduced {introduced} is later than the release "
                         f"{release}")
    entry = _entry(raw, introduced, where, strict=False)
    if entry.superseded_by and version_key(entry.superseded_by) > version_key(release):
        raise NotesError(f"{where} ({entry.id}): superseded_by {entry.superseded_by} is "
                         f"later than the release {release}")
    return entry


def parse_notes(doc: object) -> Notes:
    """A compiled upgrade-notes.json (already parsed from JSON), validated.
    Keys it does not know are ignored; values it does not know are refused."""
    if not isinstance(doc, dict):
        raise NotesError(f"{COMPILED}: must be a JSON object")
    fmt = doc.get("format")
    if type(fmt) is not int or fmt != FORMAT:
        raise NotesError(f"{COMPILED}: format {_show(fmt)} is not {FORMAT}, the only "
                         f"format this release reads")
    _keys(doc, DOC_KEYS, COMPILED, strict=False)
    release = _version(doc["release"], f"{COMPILED}: release")
    _check_bounds(doc["floor"], doc["bridge"], release, f"{COMPILED}: ")
    raw_releases = doc["releases"]
    if not isinstance(raw_releases, dict):
        raise NotesError(f"{COMPILED}: releases must be an object")
    releases = {_version(v, f"{COMPILED}: releases"):
                _release_info(info, f"{COMPILED}: releases[{v}]")
                for v, info in raw_releases.items()}
    if release not in releases:
        raise NotesError(f"{COMPILED}: releases does not list the release {release}")
    no_action = _string_versions(doc["no_action"], release, f"{COMPILED}: no_action")
    raw_entries = doc["entries"]
    if not isinstance(raw_entries, list):
        raise NotesError(f"{COMPILED}: entries must be a list")
    entries = tuple(_compiled_entry(raw, release, f"{COMPILED}: entries[{i}]")
                    for i, raw in enumerate(raw_entries))
    _unique_ids(entries, COMPILED)
    return Notes(release, doc["floor"], doc["bridge"], releases, no_action, entries)


def select(notes: Notes, installed: str) -> Guide:
    """The entries a box on `installed` is shown for an upgrade to
    notes.release: introduced after `installed`, up to the release, and not
    superseded. Below the floor, nothing: that box upgrades by hand first."""
    at, top = version_key(installed), version_key(notes.release)
    below = at < version_key(notes.floor)

    def in_range(version: str) -> bool:
        return not below and at < version_key(version) <= top

    shown = _ordered(e for e in notes.entries
                     if in_range(e.introduced) and e.superseded_by is None)

    def section(scope: str, when: str) -> tuple[Entry, ...]:
        return tuple(e for e in shown if e.scope == scope and e.when == when)

    return Guide(installed=installed, target=notes.release, below_floor=below,
                 floor=notes.floor, bridge=notes.bridge,
                 box_before=section("box", "before"),
                 project_before=section("project", "before"),
                 project_after=section("project", "after"),
                 box_after=section("box", "after"),
                 no_action=tuple(v for v in sorted(notes.no_action, key=version_key)
                                 if in_range(v)))

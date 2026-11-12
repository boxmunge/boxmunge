# SPDX-License-Identifier: Apache-2.0
"""Upgrade notes as data: the entry files, the compiled upgrade-notes.json a
release publishes, and the entries a box is shown (boxmunge.upgrade_notes)."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from boxmunge import upgrade_notes as un
from boxmunge.upgrade_notes import (
    Entry, Notes, NotesError, ReleaseInfo, compile_notes, dump_notes, load_entry_file,
    parse_notes, select, version_key,
)

REPO = Path(__file__).resolve().parents[1]
FLOOR, BRIDGE = "0.11.0", "0.11.6"


def _raw(entry_id: str, scope: str = "project", when: str = "before", **over) -> dict:
    raw = {"id": entry_id, "scope": scope, "when": when, "kind": "required",
           "title": "Pin the base image", "change": "Set an exact tag.\nThen redeploy.",
           "verify": "validate <project> passes",
           "files": ["compose.yml"] if scope == "project" else [],
           "superseded_by": None, "refs": ["#231"]}
    raw.update(over)
    return raw


def _write(notes_dir: Path, version: str, *entries: dict, doc: dict | None = None) -> Path:
    notes_dir.mkdir(parents=True, exist_ok=True)
    path = notes_dir / f"{version}.json"
    body = doc if doc is not None else {
        "version": version, "no_project_action": not entries, "entries": list(entries)}
    path.write_text(json.dumps(body))
    return path


def _releases(*specs: tuple) -> dict:
    """specs: (version, class) or (version, class, breaking)."""
    return {"releases": [{"version": s[0], "class": s[1],
                          "breaking": s[2] if len(s) > 2 else False,
                          "url": f"https://example.invalid/v{s[0]}"} for s in specs]}


RELEASES = _releases(("0.10.1", "security", True), ("0.11.0", "feature", True),
                     ("0.11.7", "security"), ("0.11.8", "breakfix"),
                     ("0.12.0", "feature", True))


@pytest.fixture
def notes_dir(tmp_path: Path) -> Path:
    d = tmp_path / "upgrade-notes"
    _write(d, "0.11.8")
    _write(d, "0.12.0", _raw("0.12.0-python-floor", scope="box"),
           _raw("0.12.0-compose-tag", when="after", kind="recommended",
                files=["Dockerfile", "compose.yml"]))
    return d


class TestVersionKey:
    def test_reads_x_y_z(self):
        assert version_key("0.11.8") == (0, 11, 8)
        assert version_key("0.11.10") > version_key("0.11.9")

    @pytest.mark.parametrize("bad", ["0.11", "v0.11.8", "0.11.8-rc.1", "0.11.8+abc",
                                     "0.011.8", "0.11.8\n", " 0.11.8", "", 11, None])
    def test_refuses_anything_else(self, bad):
        with pytest.raises(NotesError, match="X.Y.Z"):
            version_key(bad)


class TestLoadEntryFile:
    def test_reads_a_file(self, notes_dir):
        f = load_entry_file(notes_dir / "0.12.0.json")
        assert f.version == "0.12.0" and f.no_project_action is False
        assert [e.id for e in f.entries] == ["0.12.0-python-floor", "0.12.0-compose-tag"]
        floor = f.entries[0]
        assert floor.introduced == "0.12.0" and floor.files == () and floor.refs == ("#231",)
        # files come back in FILES order, whatever order they were written in
        assert f.entries[1].files == ("compose.yml", "Dockerfile")

    def test_reads_a_no_action_file(self, notes_dir):
        f = load_entry_file(notes_dir / "0.11.8.json")
        assert f.no_project_action is True and f.entries == ()

    @pytest.mark.parametrize("mutate,field", [
        (lambda d: d["entries"][0].update(scope="fleet"), "scope"),
        (lambda d: d["entries"][0].update(when="during"), "when"),
        (lambda d: d["entries"][0].update(kind="optional"), "kind"),
        (lambda d: d.update(no_project_action=True), "no_project_action"),
        (lambda d: d.update(entries=[]), "no_project_action"),
        (lambda d: d.update(no_project_action="yes"), "no_project_action"),
        (lambda d: d["entries"][0].update(files=[]), "files"),
        (lambda d: d["entries"][0].update(scope="box"), "files"),
        (lambda d: d["entries"][0].update(files=["Makefile"]), "files"),
        (lambda d: d["entries"][0].update(files=["compose.yml", "compose.yml"]), "files"),
        (lambda d: d["entries"].append(copy.deepcopy(d["entries"][0])), "duplicate id"),
        (lambda d: d["entries"][0].update(superseded_by="0.12.0"), "superseded_by"),
        (lambda d: d["entries"][0].update(superseded_by="0.11.9"), "superseded_by"),
        (lambda d: d["entries"][0].update(superseded_by="later"), "superseded_by"),
        (lambda d: d["entries"][0].update(id="0.11.9-pin"), "id"),
        (lambda d: d["entries"][0].update(id="0.12.0-Pin_Image"), "id"),
        (lambda d: d["entries"][0].update(refs=["231"]), "refs"),
        (lambda d: d["entries"][0].update(superseeded_by=None), "superseeded_by"),
        (lambda d: d["entries"][0].pop("verify"), "verify"),
        (lambda d: d.update(version="0.12.1"), "version"),
        (lambda d: d.update(extra=1), "extra"),
    ])
    def test_load_entry_file_rejects(self, tmp_path, mutate, field):
        doc = {"version": "0.12.0", "no_project_action": False,
               "entries": [_raw("0.12.0-pin-image")]}
        mutate(doc)
        path = _write(tmp_path / "upgrade-notes", "0.12.0", doc=doc)
        with pytest.raises(NotesError, match=field) as e:
            load_entry_file(path)
        assert "upgrade-notes/0.12.0.json" in str(e.value)

    def test_errors_inside_an_entry_name_its_id(self, tmp_path):
        path = _write(tmp_path / "upgrade-notes", "0.12.0", _raw("0.12.0-pin", kind="maybe"))
        with pytest.raises(NotesError, match=r"0\.12\.0-pin.*kind"):
            load_entry_file(path)

    @pytest.mark.parametrize("name", ["latest.json", "0.12.json", "v0.12.0.json"])
    def test_refuses_a_file_not_named_for_a_version(self, tmp_path, name):
        path = tmp_path / name
        path.write_text(json.dumps({"version": "0.12.0", "no_project_action": True,
                                    "entries": []}))
        with pytest.raises(NotesError, match="file name"):
            load_entry_file(path)

    @pytest.mark.parametrize("text", ["{", '{"version": "0.12.0", "version": "0.12.0", '
                                           '"no_project_action": true, "entries": []}', "[]"])
    def test_refuses_unreadable_json(self, tmp_path, text):
        path = tmp_path / "0.12.0.json"
        path.write_text(text)
        with pytest.raises(NotesError, match="0.12.0.json"):
            load_entry_file(path)


class TestEntryText:
    @pytest.mark.parametrize("field,value", [
        ("title", "\x1b[31mred"),
        ("title", "two\nlines"),
        ("title", "x" * 101),
        ("change", "x" * 1001),
        ("change", "right-to-left ‮ override"),
        ("change", "a\ttab"),
        ("verify", "x" * 501),
        ("verify", ""),
        ("title", 7),
    ])
    def test_entry_text_rejects_control_characters_and_overlength(self, tmp_path, field,
                                                                   value):
        path = _write(tmp_path / "upgrade-notes", "0.12.0",
                      _raw("0.12.0-pin", **{field: value}))
        with pytest.raises(NotesError, match=field):
            load_entry_file(path)

    def test_newlines_and_the_limits_themselves_are_allowed(self, tmp_path):
        path = _write(tmp_path / "upgrade-notes", "0.12.0", _raw(
            "0.12.0-pin", title="t" * 100, change="line\n" * 200, verify="v" * 500))
        entry = load_entry_file(path).entries[0]
        assert len(entry.change) == 1000 and len(entry.verify) == 500


class TestCompile:
    def test_compile_notes_shape(self, notes_dir):
        doc = compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE)
        assert doc["format"] == 1
        assert (doc["release"], doc["floor"], doc["bridge"]) == ("0.12.0", FLOOR, BRIDGE)
        assert list(doc["releases"]) == ["0.11.0", "0.11.7", "0.11.8", "0.12.0"]
        assert doc["releases"]["0.11.0"] == {"class": "feature", "breaking": True}
        assert doc["releases"]["0.11.8"] == {"class": "breakfix", "breaking": False}
        assert doc["no_action"] == ["0.11.8"]
        assert [e["id"] for e in doc["entries"]] == ["0.12.0-compose-tag",
                                                     "0.12.0-python-floor"]
        assert doc["entries"][0] == {
            "introduced": "0.12.0", "id": "0.12.0-compose-tag", "scope": "project",
            "when": "after", "kind": "recommended", "title": "Pin the base image",
            "change": "Set an exact tag.\nThen redeploy.", "verify": "validate <project> passes",
            "files": ["compose.yml", "Dockerfile"], "superseded_by": None, "refs": ["#231"]}

    def test_compile_notes_refuses_missing_release_file(self, notes_dir):
        (notes_dir / "0.12.0.json").unlink()
        with pytest.raises(NotesError, match="no upgrade-notes/0.12.0.json") as e:
            compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE)
        assert '"no_project_action": true' in str(e.value) and "entries" in str(e.value)

    def test_compile_refuses_a_listed_release_without_notes(self, notes_dir):
        releases = _releases(("0.11.0", "feature", True), ("0.11.8", "breakfix"),
                             ("0.11.9", "security"), ("0.12.0", "feature", True))
        with pytest.raises(NotesError, match="no upgrade-notes/0.11.9.json"):
            compile_notes(notes_dir, "0.12.0", releases, FLOOR, BRIDGE)

    def test_releases_before_the_first_need_no_notes(self, tmp_path):
        empty = tmp_path / "upgrade-notes"
        empty.mkdir()
        doc = compile_notes(empty, "0.11.7", RELEASES, FLOOR, BRIDGE)
        assert doc["no_action"] == [] and doc["entries"] == []
        assert list(doc["releases"]) == ["0.11.0", "0.11.7"]

    def test_compile_ignores_files_newer_than_release(self, notes_dir):
        _write(notes_dir, "0.12.1", _raw("0.12.1-later"))
        doc = compile_notes(notes_dir, "0.11.8", RELEASES, FLOOR, BRIDGE)
        assert doc["no_action"] == ["0.11.8"] and doc["entries"] == []
        assert "0.12.0" not in doc["releases"]

    def test_compile_still_validates_files_newer_than_release(self, notes_dir):
        _write(notes_dir, "0.12.1", _raw("0.12.1-later", kind="maybe"))
        with pytest.raises(NotesError, match="0.12.1.json"):
            compile_notes(notes_dir, "0.11.8", RELEASES, FLOOR, BRIDGE)

    def test_compile_refuses_superseded_by_after_release(self, notes_dir):
        _write(notes_dir, "0.12.0", _raw("0.12.0-pin", superseded_by="0.12.1"))
        with pytest.raises(NotesError, match=r"0\.12\.0-pin.*superseded_by 0\.12\.1"):
            compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE)

    def test_compile_refuses_superseded_by_an_unlisted_release(self, tmp_path):
        d = tmp_path / "upgrade-notes"
        _write(d, "0.11.8", _raw("0.11.8-pin", superseded_by="0.11.9"))
        _write(d, "0.12.0")
        with pytest.raises(NotesError, match="0.11.9"):
            compile_notes(d, "0.12.0", RELEASES, FLOOR, BRIDGE)

    def test_compile_refuses_an_unlisted_release(self, notes_dir):
        with pytest.raises(NotesError, match="0.12.1 is not listed"):
            compile_notes(notes_dir, "0.12.1", RELEASES, FLOOR, BRIDGE)

    def test_compile_refuses_notes_for_a_release_never_listed(self, notes_dir):
        _write(notes_dir, "0.11.9")
        with pytest.raises(NotesError, match="upgrade-notes/0.11.9.json.*not listed"):
            compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE)

    @pytest.mark.parametrize("floor,bridge", [("0.11", BRIDGE), ("0.12.1", "0.12.1"),
                                              (FLOOR, "0.10.9")])
    def test_compile_refuses_a_bad_floor_or_bridge(self, notes_dir, floor, bridge):
        with pytest.raises(NotesError, match="floor|bridge"):
            compile_notes(notes_dir, "0.12.0", RELEASES, floor, bridge)

    def test_compile_refuses_a_missing_directory(self, tmp_path):
        with pytest.raises(NotesError, match="upgrade-notes"):
            compile_notes(tmp_path / "upgrade-notes", "0.12.0", RELEASES, FLOOR, BRIDGE)


class TestDump:
    def test_dump_is_ascii_json_ending_in_a_newline(self, notes_dir):
        _write(notes_dir, "0.12.0", _raw("0.12.0-pin", title="Café → bar"))
        data = dump_notes(compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE))
        assert data.endswith(b"\n") and data.isascii()
        assert json.loads(data)["entries"][0]["title"] == "Café → bar"

    def test_dump_refuses_a_document_over_the_shims_cap(self, notes_dir, monkeypatch):
        monkeypatch.setattr(un, "MAX_BYTES", 100)
        with pytest.raises(NotesError, match="100"):
            dump_notes(compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE))


class TestParse:
    def test_parse_notes_round_trips_compile(self, notes_dir):
        doc = compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE)
        notes = parse_notes(json.loads(dump_notes(doc)))
        assert (notes.release, notes.floor, notes.bridge) == ("0.12.0", FLOOR, BRIDGE)
        assert notes.releases["0.11.0"] == ReleaseInfo("feature", True)
        assert notes.no_action == ("0.11.8",)
        assert notes.entries == load_entry_file(notes_dir / "0.12.0.json").entries[::-1]

    @pytest.mark.parametrize("fmt", [2, 0, "1", True, None])
    def test_parse_notes_rejects_unknown_format(self, notes_dir, fmt):
        doc = compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE)
        doc["format"] = fmt
        with pytest.raises(NotesError, match="format"):
            parse_notes(doc)

    def test_parse_ignores_keys_it_does_not_know(self, notes_dir):
        """A later release may add keys within format 1."""
        doc = compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE)
        doc["signed_by"] = "x"
        doc["entries"][0]["posture"] = ["strict"]
        doc["releases"]["0.12.0"]["cooldown_days"] = 7
        assert parse_notes(doc).entries[0].id == "0.12.0-compose-tag"

    @pytest.mark.parametrize("mutate,field", [
        (lambda d: d["entries"][0].update(kind="warning"), "kind"),
        (lambda d: d["entries"][0].update(introduced="0.12.1"), "introduced"),
        (lambda d: d["entries"][0].update(title="\x07bell"), "title"),
        (lambda d: d["entries"][0].pop("introduced"), "introduced"),
        (lambda d: d["entries"].append(copy.deepcopy(d["entries"][0])), "duplicate id"),
        (lambda d: d["releases"]["0.11.0"].update({"class": "hotfix"}), "class"),
        (lambda d: d["releases"]["0.11.0"].update(breaking="yes"), "breaking"),
        (lambda d: d["releases"].pop("0.12.0"), "releases"),
        (lambda d: d.update(releases=[]), "releases"),
        (lambda d: d.update(no_action=["0.12.1"]), "no_action"),
        (lambda d: d.update(no_action="0.11.8"), "no_action"),
        (lambda d: d.update(release="latest"), "release"),
        (lambda d: d.pop("bridge"), "bridge"),
        (lambda d: d.update(entries={}), "entries"),
    ])
    def test_parse_notes_rejects(self, notes_dir, mutate, field):
        doc = compile_notes(notes_dir, "0.12.0", RELEASES, FLOOR, BRIDGE)
        mutate(doc)
        with pytest.raises(NotesError, match=field) as e:
            parse_notes(doc)
        assert str(e.value).startswith("upgrade-notes.json")

    @pytest.mark.parametrize("doc", [[], "notes", None])
    def test_parse_notes_rejects_a_non_object(self, doc):
        with pytest.raises(NotesError, match="object"):
            parse_notes(doc)


def _e(introduced: str, slug: str, scope: str = "project", when: str = "before",
       superseded_by: str | None = None) -> Entry:
    return Entry(introduced=introduced, id=f"{introduced}-{slug}", scope=scope, when=when,
                 kind="required", title="t", change="c", verify="v",
                 files=("compose.yml",) if scope == "project" else (),
                 superseded_by=superseded_by, refs=())


def _notes(*entries: Entry, no_action: tuple[str, ...] = ()) -> Notes:
    releases = {v: ReleaseInfo("feature", False)
                for v in ("0.11.0", "0.11.8", "0.11.9", "0.12.0")}
    return Notes(release="0.12.0", floor=FLOOR, bridge=BRIDGE, releases=releases,
                 no_action=no_action, entries=entries)


class TestSelect:
    def test_select_in_range_only(self):
        notes = _notes(_e("0.11.9", "a"), _e("0.12.0", "b"))
        assert [e.id for e in select(notes, "0.11.9").project_before] == ["0.12.0-b"]
        assert [e.id for e in select(notes, "0.11.8").project_before] == ["0.11.9-a",
                                                                          "0.12.0-b"]
        guide = select(notes, "0.12.0")
        assert guide.project_before == () and guide.below_floor is False

    def test_select_drops_superseded(self):
        notes = _notes(_e("0.11.9", "old", superseded_by="0.12.0"), _e("0.12.0", "new"))
        assert [e.id for e in select(notes, "0.11.8").project_before] == ["0.12.0-new"]

    def test_select_orders_sections_and_by_introduced_then_id(self):
        notes = _notes(_e("0.12.0", "b", "box", "after"), _e("0.12.0", "z"),
                       _e("0.11.9", "y"), _e("0.12.0", "a"), _e("0.12.0", "x", "box"),
                       _e("0.11.9", "w", "project", "after"))
        guide = select(notes, "0.11.8")
        assert (guide.installed, guide.target) == ("0.11.8", "0.12.0")
        assert [e.id for e in guide.box_before] == ["0.12.0-x"]
        assert [e.id for e in guide.project_before] == ["0.11.9-y", "0.12.0-a", "0.12.0-z"]
        assert [e.id for e in guide.project_after] == ["0.11.9-w"]
        assert [e.id for e in guide.box_after] == ["0.12.0-b"]

    def test_select_below_floor(self):
        guide = select(_notes(_e("0.12.0", "a"), _e("0.12.0", "b", "box"),
                              no_action=("0.11.8",)), "0.10.1")
        assert guide.below_floor is True
        assert (guide.floor, guide.bridge) == (FLOOR, BRIDGE)
        assert guide.box_before == guide.project_before == guide.project_after == ()
        assert guide.box_after == () and guide.no_action == ()

    def test_select_no_action_versions_in_range(self):
        notes = _notes(no_action=("0.11.8", "0.11.9"))
        assert select(notes, "0.11.8").no_action == ("0.11.9",)
        assert select(notes, "0.11.7").no_action == ("0.11.8", "0.11.9")

    def test_select_refuses_an_installed_version_it_cannot_read(self):
        with pytest.raises(NotesError, match="X.Y.Z"):
            select(_notes(), "0.11.8+abc1234")


def test_repository_notes_files_are_valid():
    """Every entry file in the repository loads, so a bad one fails the PR
    that adds it, not the release."""
    files = sorted((REPO / "upgrade-notes").glob("*.json"), key=lambda p: version_key(p.stem))
    assert [p.name for p in files][:1] == [f"{un.FIRST_NOTES_RELEASE}.json"]
    for path in files:
        load_entry_file(path)
    assert load_entry_file(files[0]).no_project_action is True


def test_module_imports_nothing_from_boxmunge():
    """scripts/release-lint.py loads this file by path, before any dependency
    is installed."""
    source = (REPO / "src" / "boxmunge" / "upgrade_notes.py").read_text()
    assert "boxmunge" not in "".join(
        line for line in source.splitlines() if line.startswith(("import ", "from ")))

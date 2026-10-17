"""Which top-level ``-staging`` entries are staging's own (staging_copies).

A name proves nothing: a release installed before the suffix was reserved
may ship ``foo-staging/`` as code, and an operator may make one. Staging
mounts, and unstage removes, only what is staging's: the copy of an entry
production mounts or records, of box-owned state, or one the slot records
that staging created.
"""
from __future__ import annotations

import json

from boxmunge.staged_release import new_meta, release_dir, slot_dir, write_meta
from boxmunge.staging_cleanup import remove_retired_staging_data, retired_staging_copies
from boxmunge.staging_copies import foreign_copies, slot_made
from boxmunge.staging_isolation import separation_problems, staging_copy_tops


def _project(paths, compose: str, record: list[str]):
    pdir = paths.project_dir("myapp")
    (pdir / ".releases").mkdir(parents=True)
    (pdir / ".releases" / "data-dirs.json").write_text(
        json.dumps({"version": 1, "data_dirs": record}))
    (pdir / "compose.yml").write_text(compose)
    return pdir


def _entry(pdir, name: str, content: str = "x") -> None:
    (pdir / name).mkdir()
    (pdir / name / "f").write_text(content)


def _slot(paths, compose: str, made: tuple[str, ...] = ()) -> None:
    slot = slot_dir(paths, "myapp")
    release_dir(slot).mkdir(parents=True)
    (release_dir(slot) / "compose.yml").write_text(compose)
    write_meta(slot, new_meta("bundle", "myapp-v2", None, made=made))


def test_release_code_named_staging_is_not_staging_s(paths) -> None:
    pdir = _project(paths, "services:\n  web:\n    image: x\n", [])
    _entry(pdir, "foo-staging", "production's code")
    assert foreign_copies(pdir, ()) == {"foo-staging"}


def test_copies_of_production_data_are_staging_s(paths) -> None:
    pdir = _project(paths, "services:\n  web:\n    image: x\n    volumes:\n"
                           "      - ./uploads:/u\n", ["media"])
    for name in ("uploads-staging", "media-staging", "data-staging"):
        _entry(pdir, name)
    assert foreign_copies(pdir, ()) == set()


def test_a_copy_the_slot_made_is_staging_s(paths) -> None:
    pdir = _project(paths, "services:\n  web:\n    image: x\n", [])
    _entry(pdir, "cache-staging")
    assert foreign_copies(pdir, ("cache-staging",)) == set()


def test_production_s_own_staging_named_data_is_never_staging_s(paths) -> None:
    pdir = _project(paths, "services:\n  web:\n    image: x\n    volumes:\n"
                           "      - ./cache-staging:/c\n", ["cache-staging"])
    _entry(pdir, "cache-staging", "production's")
    assert foreign_copies(pdir, ("cache-staging",)) == {"cache-staging"}


def test_slot_made_reads_the_slot_and_is_empty_without_one(paths) -> None:
    _project(paths, "services:\n  web:\n    image: x\n", [])
    assert slot_made(paths, "myapp") == ()
    _slot(paths, "services:\n  web:\n    image: x\n", made=("a-staging",))
    assert slot_made(paths, "myapp") == ("a-staging",)


def test_separation_refuses_a_source_that_is_not_staging_s(tmp_path) -> None:
    pdir, release = tmp_path / "p", tmp_path / "p/.releases/staged/release"
    model = {"services": {"app": {"volumes": [
        {"type": "bind", "source": f"{pdir}/foo-staging", "target": "/foo"},
        {"type": "bind", "source": f"{pdir}/uploads-staging", "target": "/u"}]}}}
    assert staging_copy_tops(model, pdir, release) == {"foo-staging", "uploads-staging"}
    problems = separation_problems(model, pdir, release, foreign={"foo-staging"})
    assert len(problems) == 1
    assert f"{pdir}/foo-staging" in problems[0] and "not staging's" in problems[0]
    assert separation_problems(model, pdir, release, foreign=set()) == []


def test_unstage_cleanup_leaves_release_code_named_staging(paths, capsys) -> None:
    """The reviewer's case: the slot mounts ./foo read-write, production
    does not mount it, and production's tree has its own foo-staging/."""
    pdir = _project(paths, "services:\n  web:\n    image: x\n", [])
    _slot(paths, "services:\n  web:\n    image: x\n    volumes:\n"
                 "      - ./foo:/foo\n      - ./bar:/bar\n", made=("bar-staging",))
    _entry(pdir, "foo-staging", "production's code")
    (pdir / "bar-staging").mkdir()  # an empty copy: no helper needed to remove it
    made = slot_made(paths, "myapp")
    assert retired_staging_copies(pdir, made) == [pdir / "bar-staging"]
    assert remove_retired_staging_data(paths, "myapp", made) == [pdir / "bar-staging"]
    assert (pdir / "foo-staging" / "f").read_text() == "production's code"
    assert not (pdir / "bar-staging").exists()
    out = capsys.readouterr().out
    assert f"{pdir / 'foo-staging'}" in out and "not staging's" in out

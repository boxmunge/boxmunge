# SPDX-License-Identifier: Apache-2.0
"""0.11.9 s9-readers: the reads of deploy-writable paths that had gone around
fs_nofollow. Root reaches them from timers (health, scan, container-update,
the upgrade shim) or under sudo, and deploy can put anything at the names: a
link to another file, a link to nothing, a FIFO, a huge file.

Each row names one reader and what it reads. The tests run every row through
the same four plants (a link to a file outside the project, a FIFO, a
dangling link, a file past the cap). A refused read raises, or says so in
what the command prints. Rows of a project's own files (`project_link`) are
also given a link into the project, as a git project's manifest.yml and
compose.yml are, which must still read. A broken YAML file must not have a
line of itself quoted back (`yaml_rows`)."""
from __future__ import annotations

import contextlib
import io
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from boxmunge import compose_up_steps, fs_nofollow
from boxmunge.caddy import generate_caddy_config
from boxmunge.commands.caddy_status import run_caddy_status
from boxmunge.commands.diff_cmd import run_diff
from boxmunge.commands.logs import _show_boxmunge_logs
from boxmunge.commands.stage_cmd import _sha256
from boxmunge.compose_references import walk_references
from boxmunge.compose_resolve import declared_read_only
from boxmunge.compose_validate import validate_user_compose
from boxmunge.bind_mounts import bind_mounted_dirs
from boxmunge.health_checks.projects import _drifted
from boxmunge.manifest import load_manifest, load_manifest_as_written
from boxmunge.paths import BoxPaths
from boxmunge.secrets import _parse as parse_secrets
from boxmunge.staging_cleanup import _production_sources
from boxmunge.staging_compose import generate_staging_compose_base
from boxmunge.staging_isolation import _refuse_other_files, _without_read_files
from boxmunge.staging_prepare import require_read_files
from boxmunge.tui.project_detail import ProjectDetailScreen
from tests.test_commands.test_diff_cmd import _place_bundle, _setup_project
from tests.test_root_state_reads import _outcome

P = "myapp"
MiB = 1024 * 1024
MANIFEST = (f"id: 01TEST\nproject: {P}\nsource: bundle\nhosts:\n  - {P}.example.com\n"
            "services:\n  web:\n    port: 8080\n    routes:\n      - path: /\n")
COMPOSE = "services:\n  web:\n    image: nginx\n"
BINDS = "services:\n  web:\n    image: nginx\n    volumes:\n      - ./data:/data\n"
READ_ONLY = "services:\n  web:\n    image: nginx\n    read_only: true\n"
Outcome = tuple[str, Any]


def _raised(outcome: Outcome) -> bool:
    return outcome[0] == "raised"


def _printed(fn: Callable[[], Any]) -> tuple[Any, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        return fn(), out.getvalue()


def _failed_command(outcome: Outcome) -> bool:
    """A command's refusal: a non-zero exit with the reason printed."""
    return outcome[0] == "raised" or outcome[1][0] != 0


@dataclass(frozen=True)
class Row:
    name: str
    path: Callable[[BoxPaths], Path]
    record: str | Callable[[BoxPaths], str]
    read: Callable[[BoxPaths], Any]
    refused: Callable[[Outcome], bool] = _raised
    setup: Callable[[BoxPaths], None] = lambda _p: None
    cap: int | None = MiB             # bytes the reader accepts; None: streamed, no cap
    project_link: bool = False        # a link inside its tree is honest (a git project's, a git slot's)
    home: Callable[[BoxPaths], Path] = lambda p: p.project_dir(P)   # the tree it belongs to
    yaml: bool = False                # parses YAML: a broken file must not be quoted back

    def text(self, paths: BoxPaths) -> str:
        return self.record(paths) if callable(self.record) else self.record


def _compose(paths: BoxPaths) -> Path:
    return paths.project_compose(P)


def _release(paths: BoxPaths, name: str) -> Path:
    return paths.project_releases(P) / "r1" / name


def _live_scripts(paths: BoxPaths) -> bool:
    """sweep_live_scripts: whether it said it could not tell."""
    live = paths.project_releases(P) / "live-scripts"
    live.mkdir(parents=True, exist_ok=True)
    with patch.object(compose_up_steps.docker_containers, "container_bind_sources",
                      return_value=[]):
        _, said = _printed(lambda: compose_up_steps.sweep_live_scripts(paths, P, "t"))
    return "WARNING" in said


def _manifest_in_project(paths: BoxPaths) -> None:
    paths.project_manifest(P).parent.mkdir(parents=True, exist_ok=True)
    paths.project_manifest(P).write_text(MANIFEST)


def _generated_site(paths: BoxPaths) -> str:
    return generate_caddy_config(load_manifest(paths.project_manifest(P)))


def _diff(paths: BoxPaths) -> None:
    _setup_project(paths)
    _place_bundle(paths)


def _screen(paths: BoxPaths) -> Any:
    shown: dict[str, str] = {}
    widget = lambda sel: SimpleNamespace(update=lambda text: shown.__setitem__(sel, text))  # noqa: E731
    return SimpleNamespace(
        paths=paths, project_name=P, shown=shown, query_one=lambda sel, _cls=None: widget(sel),
        _caddy_text=lambda: ProjectDetailScreen._caddy_text(SimpleNamespace(paths=paths, project_name=P)))


def _tui_manifest(paths: BoxPaths) -> str:
    screen = _screen(paths)
    ProjectDetailScreen._load_config(screen)
    return screen.shown["#manifest-view"]


def _tui_site(paths: BoxPaths) -> str:
    return ProjectDetailScreen._caddy_text(SimpleNamespace(paths=paths, project_name=P))


def _showing_refusal(outcome: Outcome) -> bool:
    return _raised(outcome) or "(refused)" in outcome[1]


ROWS = [
    Row("manifest", lambda p: p.project_manifest(P), MANIFEST,
        lambda p: load_manifest_as_written(p.project_manifest(P)), project_link=True, yaml=True),
    Row("compose_validate", _compose, COMPOSE,
        lambda p: validate_user_compose(_compose(p), p, project_name=P),
        project_link=True, yaml=True),
    Row("compose_references", _compose, COMPOSE,
        lambda p: walk_references(_compose(p), (p.project_dir(P),))[0],
        lambda o: _raised(o) or bool(o[1]), project_link=True, yaml=True),
    Row("compose_resolve.declared_read_only", _compose, READ_ONLY,
        lambda p: declared_read_only(_compose(p)), project_link=True, yaml=True),
    Row("bind_mounts", _compose, BINDS,
        lambda p: bind_mounted_dirs(_compose(p), p.project_dir(P)), project_link=True, yaml=True),
    Row("staging_cleanup", _compose, BINDS,
        lambda p: _production_sources(p.project_dir(P)), project_link=True, yaml=True),
    Row("compose_up_steps.sweep_live_scripts", lambda p: p.project_compose_override(P),
        compose_up_steps.LIVE_SCRIPTS_SOURCE, _live_scripts, lambda o: o[0] == "value" and o[1]),
    Row("projects._drifted", lambda p: p.project_caddy_site(P), _generated_site,
        lambda p: _drifted(p, p.project_dir(P)), setup=_manifest_in_project),
    Row("staging_compose", lambda p: _release(p, "compose.yml"), COMPOSE,
        lambda p: generate_staging_compose_base(_release(p, "compose.yml"), set(), p.project_dir(P)),
        home=lambda p: _release(p, ""), project_link=True, yaml=True),
    Row("staging_isolation._refuse_other_files", lambda p: _release(p, "compose.yml"), COMPOSE,
        lambda p: _refuse_other_files(_release(p, "compose.yml")), home=lambda p: _release(p, ""), project_link=True, yaml=True),
    Row("staging_isolation._without_read_files", lambda p: _release(p, "compose.yml"), COMPOSE,
        lambda p: _without_read_files(_release(p, "compose.yml"), p.root / "scratch.yml").exists(),
        home=lambda p: _release(p, ""), project_link=True, yaml=True),
    Row("staging_prepare", lambda p: p.project_releases(P) / "staged" / "compose.staging-base.yml",
        COMPOSE, lambda p: require_read_files(
            p.project_releases(P) / "staged" / "compose.staging-base.yml", _release(p, ""), P,
            p.project_dir(P)), yaml=True),
    Row("tui manifest", lambda p: p.project_manifest(P), MANIFEST, _tui_manifest,
        _showing_refusal, project_link=True),
    Row("tui site", lambda p: p.project_caddy_site(P), "site\n", _tui_site, _showing_refusal),
    Row("secrets", lambda p: p.project_secrets(P), "KEY=value\n", lambda p: parse_secrets(p.project_secrets(P))),
    Row("diff site", lambda p: p.project_caddy_site("testapp"), "site\n",
        lambda p: _printed(lambda: run_diff("testapp", p)), _failed_command, setup=_diff),
    Row("diff overlay", lambda p: p.project_compose_override("testapp"), "services: {}\n",
        lambda p: _printed(lambda: run_diff("testapp", p)), _failed_command, setup=_diff),
    Row("caddy-status", lambda p: p.project_caddy_site(P), "site\n",
        lambda p: _printed(lambda: run_caddy_status(p)), _failed_command),
    Row("logs", lambda p: p.log_file, "line\n", lambda p: _printed(lambda: _show_boxmunge_logs(p)),
        cap=fs_nofollow.READ_LIMIT_BYTES),
    Row("stage _sha256", lambda p: p.inbox / "b.tar.gz", "bundle", lambda p: _sha256(p.inbox / "b.tar.gz"),
        cap=None),
]
IDS = [r.name for r in ROWS]


@pytest.fixture(autouse=True)
def _no_docker(monkeypatch):
    def none(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("docker")
    monkeypatch.setattr("boxmunge.commands.caddy_status.subprocess.run", none)


def _plant(row: Row, paths: BoxPaths) -> Path:
    row.setup(paths)
    path = row.path(paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _baseline(row: Row, paths: BoxPaths) -> tuple[Path, Outcome]:
    path = _plant(row, paths)
    path.write_text(row.text(paths))
    outcome = _outcome(lambda: row.read(paths))
    assert not row.refused(outcome), f"the valid file is refused: {outcome}"
    return path, outcome


@pytest.fixture(params=ROWS, ids=IDS)
def row(request) -> Row:
    return request.param


def test_a_link_to_a_file_outside_the_project_is_refused(paths, tmp_path, row) -> None:
    path, _ = _baseline(row, paths)
    elsewhere = tmp_path / "elsewhere" / "planted"
    elsewhere.parent.mkdir()
    os.replace(path, elsewhere)
    path.symlink_to(elsewhere)
    outcome = _outcome(lambda: row.read(paths))
    assert row.refused(outcome), outcome


def test_a_fifo_is_refused_without_blocking(paths, row) -> None:
    path = _plant(row, paths)
    os.mkfifo(path)
    outcome = _outcome(lambda: row.read(paths), fifo=path)
    assert row.refused(outcome), outcome


def test_a_dangling_link_is_not_no_file(paths, tmp_path, row) -> None:
    path = _plant(row, paths)
    path.symlink_to(tmp_path / "gone")
    outcome = _outcome(lambda: row.read(paths))
    assert row.refused(outcome), outcome


def test_a_file_past_the_cap_is_refused(paths, row) -> None:
    if row.cap is None:
        pytest.skip("streamed, no cap")
    path = _plant(row, paths)
    path.write_text(row.text(paths) + "\n# " + "x" * row.cap)
    outcome = _outcome(lambda: row.read(paths), seconds=30)
    assert row.refused(outcome), outcome


def test_a_link_into_the_project_still_reads(paths, row) -> None:
    """A git project links manifest.yml and compose.yml into repo/, and so does a
    git slot's release tree."""
    if not row.project_link:
        pytest.skip("never a link")
    path, baseline = _baseline(row, paths)
    inside = row.home(paths) / "repo" / path.name
    inside.parent.mkdir(parents=True, exist_ok=True)
    os.replace(path, inside)
    path.symlink_to(inside)
    assert _outcome(lambda: row.read(paths)) == baseline


def test_a_broken_file_is_not_quoted_back(paths, row) -> None:
    """PyYAML quotes the line it chokes on when given a string; a link to a
    root-only file that is no YAML would be printed, or logged where deploy
    reads, a line at a time."""
    if not row.yaml:
        pytest.skip("not parsed as YAML")
    path = _plant(row, paths)
    path.write_text("services: [TOPSECRETLINE\n  web: nope\n")
    try:
        said = repr(row.read(paths))
    except Exception as e:  # noqa: BLE001 - the message is checked
        said = f"{e} {e.__cause__}"
    assert "TOPSECRETLINE" not in said


def test_an_unparsable_production_compose_fails_that_projects_teardown_only(paths) -> None:
    """staging-teardown-all (the shim's platform rollback) tears each project
    down in turn and reports the ones it could not: a compose.yml that does
    not parse must be that project's failure, not an escape that skips the
    rest."""
    _compose(paths).parent.mkdir(parents=True, exist_ok=True)
    _compose(paths).write_text("services: [unclosed\n  web: nope\n")
    with pytest.raises(ValueError, match="cannot read production's compose.yml"):
        _production_sources(paths.project_dir(P))

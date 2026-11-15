"""Every production start runs the image pins (image_pins).

A pin lives in production's overlay (compose.boxmunge.yml), which every
production start includes; a start that renders the overlay first renders
the pins into it, and a release switch renders its own release without
them and clears them. Here the starts are enumerated from the source, as
tests/test_root_compose_call_sites.py does, so a new one has to be placed
in a group, and each group is held to how it keeps the pins: a patched
image cannot silently drop off a start.
"""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import boxmunge
from boxmunge.paths import BoxPaths

SRC = Path(boxmunge.__file__).parent
NAME = "shop"
OVERLAY = "compose.boxmunge.yml"
_START_CHECKS = {"compose_up_checked", "start_containers_checked", "check_start",
                 "check_containers_start"}

RENDERS = "renders the overlay, with the pins, before it starts"
RECORDS = "starts nothing: records the overlay its caller rendered, with the pins, just before"
RUNS_OVERLAY = "renders nothing: starts from the overlay the last render wrote, pins included"
CONTAINERS = "starts existing containers, created from the pinned overlay, as they were created"
SWITCH = "installs a release: rendered without the pins, which the switch clears"
STAGING = "staging runs the staged release from its slot: the pins are production's"
STARTS = {
    ("backup_offline.py", "run_offline"): CONTAINERS,
    ("commands/data_cmd.py", "_start_again"): CONTAINERS,
    ("commands/data_cmd.py", "adopt_locked"): CONTAINERS,
    ("staging_data.py", "copy_production_data"): CONTAINERS,
    ("commands/deploy.py", "_start"): SWITCH,
    ("commands/rollback.py", "restore_rolled_back_data"): SWITCH,
    ("commands/quarantine_lift.py", "restore_from_quarantine"): RENDERS,
    ("commands/recover_cmd.py", "recover_locked"): RENDERS,
    ("commands/resume_cmd.py", "resume_locked"): RENDERS,
    ("commands/upgrade_offline.py", "regenerate_offline"): RENDERS,
    ("commands/upgrade_steps.py", "_record_bind_sources"): RECORDS,
    ("userns/bringup.py", "_project"): RENDERS,
    ("commands/restore.py", "_replace_data"): RUNS_OVERLAY,
    ("commands/restore.py", "_up"): RUNS_OVERLAY,
    ("commands/upgrade_steps.py", "_restart_locked"): RUNS_OVERLAY,
    ("container_recreate.py", "recreate_project"): RUNS_OVERLAY,
    ("cve/quarantine.py", "lift_quarantine"): RUNS_OVERLAY,
    ("production_stopped.py", "start_stopped"): RUNS_OVERLAY,
    ("staging_bringup.py", "_prepare_storage"): STAGING,
    ("staging_bringup.py", "bring_up_staging"): STAGING,
}


def _trees() -> dict[str, ast.Module]:
    return {str(p.relative_to(SRC)): ast.parse(p.read_text()) for p in sorted(SRC.rglob("*.py"))}


def _called(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    return f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)


def _starts() -> dict[tuple[str, str], list[ast.Call]]:
    found: dict[tuple[str, str], list[ast.Call]] = {}
    for rel, tree in _trees().items():
        if rel == "compose_guard.py":
            continue
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = [n for n in ast.walk(fn) if _called(n) in _START_CHECKS]
                if calls:
                    found[(rel, fn.name)] = calls
    return found


def test_every_prod_start_path_reads_the_overlay_pins(paths: BoxPaths) -> None:
    """Each start is placed, and each group keeps the pins as it says."""
    starts = _starts()
    assert set(starts) == set(STARTS), (
        "a start was added or moved: say in STARTS how it runs the image pins")
    trees = _trees()
    for (rel, fn), group in STARTS.items():
        calls = starts[(rel, fn)]
        staged = [c for c in calls if any(
            kw.arg == "staging" and ast.unparse(kw.value) == "True" for kw in c.keywords)]
        assert (group == STAGING) == (len(staged) == len(calls)), (rel, fn)
        if group == RENDERS:
            assert _renders(trees[rel], fn), (rel, fn)
        if group == RECORDS:
            callers = [f.name for f in _functions(trees[rel]).values()
                       if fn in _calls_made(f)]
            assert callers and all(_renders_before(trees[rel], c, fn) for c in callers), \
                (rel, fn, callers)
    # Every production file list includes the overlay once it exists.
    _assert_file_lists_include_the_overlay(paths)


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}


def _calls_made(fn: ast.AST) -> list[str]:
    return [name for n in ast.walk(fn) if (name := _called(n)) is not None]


def _renders(tree: ast.Module, fn: str, seen: frozenset[str] = frozenset()) -> bool:
    """`fn` renders the overlay itself, or through a function of its module
    it calls (pins and all: no `installing`)."""
    functions = _functions(tree)
    for node in ast.walk(functions[fn]):
        if _called(node) == "prepare_compose_override":
            if not any(kw.arg == "installing" for kw in node.keywords):
                return True
        elif (callee := _called(node)) in functions and callee not in seen | {fn}:
            if _renders(tree, callee, seen | {fn}):
                return True
    return False


def _renders_before(tree: ast.Module, caller: str, fn: str) -> bool:
    """`caller` renders (as _renders) before its call of `fn`."""
    body = ast.unparse(_functions(tree)[caller])
    return "prepare_compose_override(" in body[:body.index(f"{fn}(")]


def _assert_file_lists_include_the_overlay(paths: BoxPaths) -> None:
    from boxmunge import backup_offline, production_stopped
    from boxmunge.commands import (
        quarantine_lift, restore, resume_cmd, security_scan_inputs, upgrade_steps,
    )
    from boxmunge.container_update_targets import _build_project_target
    from boxmunge.userns import bringup
    project_dir = paths.project_dir(NAME)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(f"project: {NAME}\n")
    paths.project_compose_override(NAME).write_text("services: {}\n")
    with patch("boxmunge.container_update_targets.classify"), \
            patch("boxmunge.container_update_targets.load_manifest",
                  return_value={"project": NAME}):
        target = _build_project_target(paths, {}, project_dir)
    lists = {
        "backup_offline.PROD_FILES": backup_offline.PROD_FILES,
        "production_stopped.PROD_FILES": production_stopped.PROD_FILES,
        "userns.bringup.PROJECT_FILES": bringup.PROJECT_FILES,
        "container update target": target.compose_files,
        "quarantine_lift": quarantine_lift.compose_files_for(paths, NAME),
        "restore": restore._compose_files(paths, NAME),
        "resume": resume_cmd._compose_files(NAME, paths),
        "upgrade": upgrade_steps._compose_files(paths, NAME),
        "scan": security_scan_inputs.project_compose_files(paths, NAME),
    }
    assert {k: OVERLAY in v for k, v in lists.items()} == {k: True for k in lists}
    # The rest name the overlay in the start itself.
    for rel, fn in (("commands/deploy.py", "_start"), ("commands/recover_cmd.py",
                                                       "recover_locked"),
                    ("commands/rollback.py", "restore_rolled_back_data"),
                    ("commands/upgrade_offline.py", "regenerate_offline")):
        node = next(n for n in ast.walk(_trees()[rel])
                    if isinstance(n, ast.FunctionDef) and n.name == fn)
        assert OVERLAY in ast.unparse(node), (rel, fn)


@pytest.fixture
def started(paths: BoxPaths):
    """What the starts that render nothing hand the start checks."""
    asked: list[list[str]] = []

    def check(paths, project, *, compose_files=None, **kwargs):
        asked.append(list(compose_files or []))
        raise RuntimeError("checked")
    with patch("boxmunge.compose_guard.check_start", check):
        yield asked


def _container_update(paths: BoxPaths) -> None:
    from boxmunge.container_update import _recreate
    from boxmunge.container_update_targets import _build_project_target
    paths.project_dir(NAME).mkdir(parents=True, exist_ok=True)
    paths.project_compose_override(NAME).write_text("services: {}\n")
    with patch("boxmunge.container_update_targets.classify"), \
            patch("boxmunge.container_update_targets.load_manifest",
                  return_value={"project": NAME}):
        target = _build_project_target(paths, {}, paths.project_dir(NAME))
    _recreate(paths, SimpleNamespace(is_caddy=False, name=NAME,
                                     compose_files=target.compose_files))


def _staging_copy_restart(paths: BoxPaths) -> None:
    from boxmunge.production_stopped import start_stopped
    with patch("boxmunge.production_stopped._all_present", lambda *a: False):
        start_stopped(paths, NAME, [f"{NAME}-web-1"], component="health", page=False)


@pytest.mark.parametrize("start", [_container_update, _staging_copy_restart])
def test_a_start_that_renders_nothing_runs_the_overlay(paths, started, start) -> None:
    with pytest.raises(Exception, match="checked"):
        start(paths)
    assert started and all(OVERLAY in files for files in started)

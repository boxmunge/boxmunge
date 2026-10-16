"""Every start of a project's containers goes through the start checks.

boxmunge.compose_guard re-validates a project and checks its bind sources
before `docker compose up` or `start`. A call site that reached
docker.compose_up directly, or built its own `compose up` argv, would
recreate containers from files nobody re-checked. The static tests find
every such site; the behavioural ones prove each root-run path refuses a
tampered project and leaves its containers alone.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.compose_guard import ComposeRefused
from tests.deploy_helpers import mark_deployed

SRC = Path(__file__).resolve().parents[1] / "src" / "boxmunge"
GUARD = "compose_guard.py"
# The primitives themselves, and the self-test canary: boxmunge's own fixed
# compose file under canary/, outside every project.
RAW_ALLOWED = {"docker.py", "commands/self_test_cmd.py"}
_PRIMITIVES = {"compose_up", "start_containers"}
_START_VERBS = {"up", "start", "restart", "create"}


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        yield str(path.relative_to(SRC)), ast.parse(path.read_text())


def _called_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _calls(tree: ast.AST, names: set[str]) -> list[ast.Call]:
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and _called_name(n) in names]


def _builds_docker_command(func: ast.AST) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.List) and node.elts:
            first = node.elts[0]
            if isinstance(first, ast.Constant) and first.value == "docker":
                return True
        if isinstance(node, ast.Call) and _called_name(node) == "compose_command":
            return True
    return False


def _start_verbs(func: ast.AST) -> list[int]:
    """Lines where a start verb is a literal element of an argv list."""
    return [elt.lineno for node in ast.walk(func) if isinstance(node, (ast.List, ast.Tuple))
            for elt in node.elts
            if isinstance(elt, ast.Constant) and elt.value in _START_VERBS]


def test_only_the_guard_calls_the_compose_start_primitives() -> None:
    offenders = [f"{rel}:{call.lineno}" for rel, tree in _modules() if rel != GUARD
                 for call in _calls(tree, _PRIMITIVES)]
    assert not offenders, (
        f"compose_up/start_containers called outside compose_guard: {offenders}. "
        f"Use compose_guard.compose_up_checked / start_containers_checked.")


def test_no_module_builds_its_own_compose_start_command() -> None:
    offenders = []
    for rel, tree in _modules():
        if rel in RAW_ALLOWED:
            continue
        for func in ast.walk(tree):
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and _builds_docker_command(func):
                offenders += [f"{rel}:{line}" for line in _start_verbs(func)]
    assert not offenders, f"hand-built docker start commands: {offenders}"


def test_platform_starts_are_only_for_caddy() -> None:
    sites = [rel for rel, tree in _modules() for _ in _calls(tree, {"compose_up_platform"})]
    assert sites == ["container_update.py"]


def test_only_self_test_starts_the_canary_unchecked() -> None:
    sites = [rel for rel, tree in _modules() for _ in _calls(tree, {"compose_up_canary"})]
    assert sites == ["commands/restore.py"]
    canary = [f"{rel}:{call.lineno}" for rel, tree in _modules()
              for call in ast.walk(tree) if isinstance(call, ast.Call)
              for kw in call.keywords
              if kw.arg == "canary" and isinstance(kw.value, ast.Constant) and kw.value.value]
    assert [c.split(":")[0] for c in canary] == ["commands/self_test_cmd.py"], canary


def test_the_scan_finds_the_checked_call_sites() -> None:
    """Guards the scan itself: it must keep seeing the real call sites."""
    names = {"compose_up_checked", "start_containers_checked", "check_start",
             "check_containers_start"}
    sites = sorted({rel for rel, tree in _modules() if rel != GUARD
                    for _ in _calls(tree, names)})
    assert sites == [
        "commands/deploy.py", "commands/recover_cmd.py", "commands/restore.py",
        "commands/resume_cmd.py", "commands/security_resume.py", "commands/stage_cmd.py",
        "commands/upgrade_steps.py", "container_update.py", "cve/quarantine.py",
        "staging_data.py",
    ]


# ---------------------------------------------------------------------------
# Each root-run path refuses a tampered project
# ---------------------------------------------------------------------------

NAME = "shop"


@pytest.fixture
def tampered(tmp_path: Path):
    """A deployed project whose data/uploads mount a container has since
    replaced with a symlink to another directory of the project."""
    from boxmunge.paths import BoxPaths
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.config, paths.deploy_state, paths.health_state, paths.logs,
              paths.caddy_sites):
        d.mkdir(parents=True)
    paths.config_file.write_text(yaml.safe_dump({
        "hostname": "box.example.com", "admin_email": "ops@example.com",
        "pushover": {"user_key": "u", "app_token": "t"},
    }))
    project_dir = paths.project_dir(NAME)
    (project_dir / "data" / "uploads").mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "project": NAME,
        "source": "bundle", "hosts": [f"{NAME}.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        "backup": {"type": "postgres", "service": "web", "dump_command": "d",
                   "restore_command": "r"},
    }))
    (project_dir / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx:1.27", "volumes": ["./data/uploads:/uploads"]}}}))
    mark_deployed(paths, NAME)
    (project_dir / "media").mkdir()
    (project_dir / "data" / "uploads").rmdir()
    os.symlink("../media", project_dir / "data" / "uploads")
    sent: list[str] = []
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.notify.send_notification",
                  lambda u, t, title, body, priority=0: sent.append(title) or True):
        yield paths, sent, up, start


def _assert_refused(tampered) -> None:
    paths, sent, up, start = tampered
    up.assert_not_called()
    start.assert_not_called()
    assert any("start refused" in t for t in sent), sent
    assert "data/uploads is a symlink" in paths.log_file.read_text()


def test_upgrade_restart_refuses(tampered) -> None:
    from boxmunge.commands.upgrade_steps import restart_projects
    restart = restart_projects(tampered[0], refused=())
    assert restart.succeeded == [] and restart.failed == []
    assert restart.start_refused == [NAME]
    _assert_refused(tampered)


def test_container_update_refuses_and_does_not_roll_back(tampered, fake_containers) -> None:
    import boxmunge.container_update as cu  # noqa: F401 (patched by name)
    from boxmunge.commands.container_update_cmd import update_project
    from boxmunge.container_update_targets import UpdateTarget
    paths = tampered[0]
    target = UpdateTarget(name=NAME, project_dir=paths.project_dir(NAME),
                          compose_files=["compose.yml"], strategy="rollback_to_previous",
                          has_backup=False)
    with patch.object(cu, "compose_pull"), \
            patch.object(cu, "detect_image_changes", return_value={"web": "nginx:1.28"}), \
            patch.object(cu, "tag_image") as retag:
        result = update_project(paths, target, dry_run=False)
    assert result["status"] == "failed" and result["reason"].startswith("refused:")
    assert result["rollback_attempted"] is False
    retag.assert_not_called()
    _assert_refused(tampered)


def test_recover_refuses(tampered) -> None:
    from boxmunge.commands import recover_cmd
    from boxmunge.state import write_state
    paths = tampered[0]
    write_state(paths.project_health_state(NAME), {"status": "critical_stopped"})
    with patch.object(recover_cmd, "caddy_reload"):
        assert recover_cmd.run_recover(NAME, paths, yes=True) == 1
    _assert_refused(tampered)


def test_resume_refuses_before_pulling_or_releasing_restart_policies(tampered) -> None:
    from boxmunge.commands import resume_cmd
    from boxmunge.pause import is_paused, write_paused_state
    paths = tampered[0]
    write_paused_state(NAME, paths)
    with patch.object(resume_cmd, "compose_pull") as pull, \
            patch.object(resume_cmd, "release_restart_policies") as release:
        assert resume_cmd.run_resume(NAME, paths, yes=True) == 3
    pull.assert_not_called()
    release.assert_not_called()
    assert is_paused(NAME, paths)
    _assert_refused(tampered)


def test_security_resume_refuses_before_restoring_routing(tampered) -> None:
    from boxmunge.commands import security_resume
    from boxmunge.cve.quarantine import is_quarantined
    from boxmunge.state import write_state
    paths = tampered[0]
    write_state(paths.project_quarantine_state(NAME), {"cve_id": "CVE-2099-0001"})
    with patch.object(security_resume, "prepare_caddy_config") as caddy:
        assert security_resume._resume_lift(paths, NAME) == 1
    caddy.assert_not_called()
    assert is_quarantined(NAME, paths)
    _assert_refused(tampered)


def test_restore_refuses_before_stopping_the_project(tampered) -> None:
    from boxmunge.commands import restore
    paths = tampered[0]
    with patch.object(restore, "compose_down") as down:
        rc = restore._replace_data(NAME, paths, "web", "r", Path("/nonexistent"),
                                   Path("/nonexistent"), None, leave_stopped=False)
    assert rc == 1
    down.assert_not_called()
    _assert_refused(tampered)


def test_staging_copy_refuses_before_stopping_production(tampered) -> None:
    from boxmunge import staging_data
    from boxmunge.staging_copy_plan import CopyPlan
    paths = tampered[0]
    uploads = str(paths.project_dir(NAME) / "data" / "uploads")
    with patch.object(staging_data, "_running",
                      side_effect=lambda p: [f"{NAME}-web-1"] if p == NAME else []), \
            patch.object(staging_data, "verify_plan", return_value=[]), \
            patch.object(staging_data, "_run") as run, \
            patch("boxmunge.docker_containers.container_bind_sources",
                  return_value=[(uploads, True)]):
        with pytest.raises(ComposeRefused):
            staging_data.copy_production_data(paths, NAME, CopyPlan())
    assert not [c for c in run.call_args_list if c.args[0][:2] == ["docker", "stop"]]
    _assert_refused(tampered)


# ---------------------------------------------------------------------------
# While a release is staged, production is not recreated from its files
# ---------------------------------------------------------------------------


@pytest.fixture
def staged(tampered):
    """An untampered project with a release staged over it."""
    paths = tampered[0]
    uploads = paths.project_dir(NAME) / "data" / "uploads"
    uploads.unlink()
    uploads.mkdir()
    (paths.project_releases(NAME) / "prestage" / "release").mkdir(parents=True)
    return tampered


def _assert_refused_while_staged(staged) -> None:
    paths, sent, up, start = staged
    up.assert_not_called()
    start.assert_not_called()
    assert any("start refused" in t for t in sent), sent
    assert "a release is staged" in paths.log_file.read_text()


def test_upgrade_restart_refuses_while_staged(staged) -> None:
    from boxmunge.commands.upgrade_steps import restart_projects
    restart = restart_projects(staged[0], refused=())
    assert restart.succeeded == [] and restart.failed == []
    assert restart.start_refused == [NAME]
    _assert_refused_while_staged(staged)


def test_recover_refuses_while_staged(staged) -> None:
    from boxmunge.commands import recover_cmd
    from boxmunge.state import write_state
    paths = staged[0]
    write_state(paths.project_health_state(NAME), {"status": "critical_stopped"})
    with patch.object(recover_cmd, "caddy_reload"):
        assert recover_cmd.run_recover(NAME, paths, yes=True) == 1
    _assert_refused_while_staged(staged)


def test_container_update_refuses_while_staged(staged, fake_containers) -> None:
    import boxmunge.container_update as cu  # noqa: F401 (patched by name)
    from boxmunge.commands.container_update_cmd import update_project
    from boxmunge.container_update_targets import UpdateTarget
    paths = staged[0]
    target = UpdateTarget(name=NAME, project_dir=paths.project_dir(NAME),
                          compose_files=["compose.yml"], strategy="rollback_to_previous",
                          has_backup=False)
    with patch.object(cu, "compose_pull"), \
            patch.object(cu, "detect_image_changes", return_value={"web": "nginx:1.28"}), \
            patch.object(cu, "tag_image") as retag:
        result = update_project(paths, target, dry_run=False)
    assert result["status"] == "failed" and "a release is staged" in result["reason"]
    retag.assert_not_called()
    _assert_refused_while_staged(staged)


def test_staged_project_starts_once_unstaged(staged) -> None:
    import shutil
    from boxmunge.commands.upgrade_steps import restart_projects
    paths, _, up, _ = staged
    shutil.rmtree(paths.project_releases(NAME) / "prestage")
    assert restart_projects(paths, refused=()).succeeded == [NAME]
    up.assert_called_once()


def test_promote_and_staging_starts_are_allowed_while_staged(staged) -> None:
    from boxmunge.compose_guard import compose_up_checked, start_containers_checked
    paths, _, up, start = staged
    compose_up_checked(paths, NAME, component="promote", compose_files=["compose.yml"],
                       record=True, promoting=True)
    compose_up_checked(paths, NAME, component="stage", compose_files=["compose.yml"],
                       staging=True, record=True)
    with patch("boxmunge.docker_containers.container_bind_sources", return_value=[]):
        start_containers_checked(paths, NAME, [f"{NAME}-web-1"], component="stage")
    assert up.call_count == 2
    start.assert_called_once()

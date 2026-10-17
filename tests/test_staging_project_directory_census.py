"""Every staging compose invocation carries --project-directory <slot>/release.

A staging invocation is one naming the staging compose project or run from,
or with files in, the slot: one that reaches the slot under production's
project name is a violation too, not a call the census may skip.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from boxmunge import docker, docker_run
from boxmunge.commands.smoke_result import SmokeResult
from boxmunge.commands.project_delete_cmd import delete_locked
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.staged_release import manual_teardown, slot_dir
from tests.bundle_helpers import manifest_text, place_bundle
from tests.stage_helpers import V3, prod_and_stage

SLOT = "/myapp/.releases/staged"
# A smoke runs after every start; staging's fails, and that failure fetches
# the service's logs.
SMOKED = {"manifest.yml": manifest_text().replace(
    "    port: 8080\n", "    port: 8080\n    smoke: boxmunge-scripts/smoke.sh\n"),
    "boxmunge-scripts/smoke.sh": "exit 0\n"}


def _staging(cmd: list[str], cwd: str) -> bool:
    if "compose" not in cmd:
        return False
    named = "-p" in cmd and cmd[cmd.index("-p") + 1] == "myapp-staging"
    return named or SLOT in cwd or any(SLOT in arg for arg in cmd)


def _smoke(container: str, script: str, service: str) -> SmokeResult:
    if container.startswith("myapp-staging-"):
        return SmokeResult(status="critical", message="staging smoke failed")
    return SmokeResult(status="ok", message="")


def _staging_configs_name_their_release(configs: list[dict], slot: Path,
                                        project_dir: Path) -> None:
    """Every `compose config` of <p>-staging (staging_model) runs from, and
    with --project-directory, the release its files describe: the slot's,
    the slot being built, or the candidate checked before it (precheck)."""
    releases = {slot / "release", slot.with_name(slot.name + ".building") / "release",
                project_dir / ".releases" / "incoming" / "myapp"}
    staging = [c for c in configs if c.get("project_name") == "myapp-staging"]
    assert any(c.get("project_directory") == slot / "release" for c in staging), staging
    for c in staging:
        assert c.get("project_directory") in releases, c
        assert c["cwd"] == c.get("project_directory"), c


def test_every_staging_invocation_names_the_slot(paths, fake_containers) -> None:
    prod_and_stage(paths, staged_files=SMOKED)
    fake_containers.run("myapp", "web", "sha256:1")
    fake_containers.run("myapp-staging", "web", "sha256:2")
    calls: list[tuple[list[str], str]] = []
    spawned: list[list[str]] = []

    def run(cmd, cwd=None, **kw):
        calls.append((list(cmd), str(cwd or "")))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    real_config = docker.compose_config  # the conftest's stand-in: it never reaches _run
    configs: list[dict] = []

    def config(project_dir, compose_files=None, **kw):
        configs.append({"cwd": Path(project_dir), "files": list(compose_files or []), **kw})
        return real_config(project_dir, compose_files, **kw)

    def spawn(cmd, *a, **kw):
        spawned.append(list(cmd))
        raise OSError("the census runs no real process")

    # Every module's binding of docker_run.run, so no seam is missed.
    seams = [patch.object(mod, "_run", run) for name, mod in list(sys.modules.items())
             if name.startswith("boxmunge") and getattr(mod, "_run", None) is docker_run.run]
    seams.append(patch.object(docker, "compose_config", config))
    place_bundle(paths, timestamp=V3, files=SMOKED)
    for seam in seams:
        seam.start()
    try:
        with patch("subprocess.Popen", spawn), \
                patch("boxmunge.commands.check._smoke_one", _smoke), \
                patch("boxmunge.commands.deploy.caddy_reload"), \
                patch("boxmunge.staging_bringup.caddy_reload"), \
                patch("boxmunge.commands.unstage_cmd.caddy_reload"), \
                patch("boxmunge.commands.project_delete_cmd.caddy_reload"):
            assert run_stage("myapp", paths, ref=V3) == 0     # re-stage: down + up
            assert run_promote("myapp", paths) == 0           # deploy + teardown
            place_bundle(paths, timestamp="2026-10-16T120000000000", files=SMOKED)
            assert run_stage("myapp", paths) == 0
            assert run_unstage("myapp", paths) == 0
            delete_locked("myapp", paths, force=True)
    finally:
        for seam in seams:
            seam.stop()
    assert spawned == []
    staging = [cmd for cmd, cwd in calls if _staging(cmd, cwd)]
    assert len(staging) >= 4
    assert any("logs" in cmd for cmd in staging), "the smoke failure's log fetch did not run"
    for cmd in staging:
        assert cmd[cmd.index("-p") + 1] == "myapp-staging", cmd
        i = cmd.index("--project-directory")
        assert cmd[i + 1].endswith("/myapp/.releases/staged/release"), cmd
    slot = slot_dir(paths, "myapp")
    _staging_configs_name_their_release(configs, slot, paths.project_dir("myapp"))
    assert f"--project-directory {slot}/release " in manual_teardown(paths, "myapp")

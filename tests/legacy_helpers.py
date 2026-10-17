"""Fabricate the on-disk state boxmunge 0.10.1 leaves mid-stage (the
integration tier, Task 39, makes the real thing with 0.10.1's own CLI)."""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone

from boxmunge.legacy_stage import legacy_staging_state
from boxmunge.release import mark_live
from boxmunge.state import write_state
from tests.bundle_helpers import manifest_text, place_bundle
from tests.git_helpers import commit, git, origin_with
from tests.stage_helpers import V1, V2
from tests.txn_helpers import docker_off


def _staging_state(paths, ref: str) -> None:
    state = legacy_staging_state(paths, "myapp")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"active": True, "ref": ref}))


def legacy_bundle_stage(paths, *, prod_backup: str = "postgres",
                        staged_backup: str = "none"):
    """Production v1 deployed; a 0.10.1 bundle stage of v2 over it."""
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n",
                                             "manifest.yml": manifest_text(backup=prod_backup)})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    pdir = paths.project_dir("myapp")
    prestage = pdir / ".releases" / "prestage"
    (prestage / "release").mkdir(parents=True)
    for name in ("VERSION", "manifest.yml", "compose.yml"):
        shutil.copy2(pdir / name, prestage / "release" / name)
    (prestage / "meta.json").write_text(json.dumps({"ref": f"myapp-{V1}"}) + "\n")
    (pdir / "VERSION").write_text("v2\n")
    (pdir / "manifest.yml").write_text(manifest_text(backup=staged_backup))
    (pdir / "compose.staging-base.yml").write_text("services:\n  web:\n    image: nginx\n")
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    mark_live(paths, "myapp", f"myapp-{V2}")
    _staging_state(paths, f"myapp-{V2}")
    return pdir


def legacy_git_stage(paths, tmp, *, prod_backup: str = "postgres",
                     staged_backup: str = "none") -> tuple[str, str]:
    """A git project deployed at commit A; a 0.10.1 stage checked out B in
    repo/. Deploy state records A's short SHA, as 0.10.1 did. Returns (A, B)."""
    from boxmunge.project_registry import add_project
    add_project("myapp", paths)
    _, work = origin_with(tmp, {"manifest.yml": manifest_text(backup=prod_backup)})
    a = git("rev-parse", "HEAD", cwd=work)
    b = commit(work, {"manifest.yml": manifest_text(backup=staged_backup)}, "B")
    repo = paths.project_dir("myapp") / "repo"
    shutil.copytree(work, repo, symlinks=True)
    git("checkout", "-q", "--detach", a, cwd=repo)
    git("checkout", "-q", "--detach", b, cwd=repo)
    (paths.project_dir("myapp") / "manifest.yml").write_text(manifest_text(backup=staged_backup))
    (paths.project_dir("myapp") / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    paths.project_deploy_state("myapp").parent.mkdir(parents=True, exist_ok=True)
    write_state(paths.project_deploy_state("myapp"), {"current_ref": a[:7]})
    _staging_state(paths, b)
    return a, b


def reflog_checkout_time(repo) -> datetime:
    """The newest checkout: entry's time in repo/'s HEAD reflog."""
    lines = (repo / ".git" / "logs" / "HEAD").read_text().splitlines()
    stamps = [int(line.split("\t", 1)[0].split()[-2]) for line in lines if "\tcheckout:" in line]
    return datetime.fromtimestamp(max(stamps), timezone.utc)


def stamp(path, when: datetime) -> None:
    ts = when.replace(tzinfo=timezone.utc).timestamp()
    os.utime(path, (ts, ts))

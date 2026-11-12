# SPDX-License-Identifier: Apache-2.0
"""A box under tmp_path for the readiness tests, and a recorder that stands
in for every subprocess the readiness check starts."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml

from boxmunge.manifest import CURRENT_SCHEMA_VERSION
from boxmunge.paths import BoxPaths
from boxmunge.readiness_contract import Finding, Readiness
from boxmunge.release_txn import open_txn
from boxmunge.version import write_installed_version
from tests.deploy_helpers import mark_deployed

IMAGE = "nginx:1.25"
COMMAND = re.compile(r"\b(prod-deploy|upgrade(-check)?|validate|project-delete|apt-get|"
                     r"systemctl|resume|install-txn|rollback)\b")


def make_box(root: Path, installed: str = "0.11.7") -> BoxPaths:
    paths = BoxPaths(root=root)
    for d in ("config", "projects", "state/deploy", "stashes", "logs", "caddy/sites",
              "upgrade-state"):
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, installed, "abc1234")
    paths.log_file.write_text(json.dumps({  # today's: logging appends, not rotates
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "level": "info",
        "component": "test", "project": None, "msg": "an earlier entry"}) + "\n")
    return paths


def add_project(paths: BoxPaths, name: str, *, compose: str | None = None,
                schema: int = CURRENT_SCHEMA_VERSION) -> Path:
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.dump({
        "schema_version": schema, "project": name, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (pdir / "compose.yml").write_text(f"services:\n  web:\n    image: {IMAGE}\n")
    paths.project_caddy_site(name).write_text(f"# live config for {name}\n")
    mark_deployed(paths, name)
    if compose is not None:
        (pdir / "compose.yml").write_text(compose)
    return pdir


def open_install(paths: BoxPaths, name: str) -> None:
    open_txn(paths, name, source="bundle", ref=f"{name}-x", replaced_ref=None,
             staged_id=None, snapshot="")


def ids(r: Readiness) -> list[tuple[str | None, str]]:
    """(project or None for the box, rule id) of every finding."""
    return [(None, f.id) for f in r.box] + [(p.name, f.id) for p in r.projects
                                             for f in p.findings]


def findings(r: Readiness) -> list[Finding]:
    return list(r.box) + [f for p in r.projects for f in p.findings]


def tree_state(root: Path) -> dict[str, tuple]:
    """Every entry under ``root``, links not followed: (mode, size, mtime_ns,
    sha256 of a regular file's bytes)."""
    state = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            st = path.lstat()
            digest = (hashlib.sha256(path.read_bytes()).hexdigest()
                      if stat.S_ISREG(st.st_mode) else None)
            state[str(path.relative_to(root))] = (st.st_mode, st.st_size, st.st_mtime_ns, digest)
    return state


class Recorder:
    """Stands in for subprocess.run: records every argv and answers the few
    commands the readiness check runs itself."""

    def __init__(self) -> None:
        self.argvs: list[list[str]] = []
        self.compose_version = "2.40.0"

    def docker(self) -> list[list[str]]:
        return [argv for argv in self.argvs if argv[:1] == ["docker"]]

    def _answer(self, argv: list[str]) -> tuple[int, str, str]:
        if argv[:4] == ["docker", "compose", "version", "--short"]:
            return 0, f"{self.compose_version}\n", ""
        if argv[:3] == ["docker", "image", "inspect"]:
            digest = hashlib.sha256(argv[3].encode()).hexdigest()
            return 0, json.dumps([{"Id": f"sha256:{digest}", "RepoDigests": []}]), ""
        if argv[:1] == ["git"]:
            return 0, "abc1234\n", ""
        return 0, "", ""

    def __call__(self, cmd, *args, **kwargs) -> subprocess.CompletedProcess:
        argv = [str(part) for part in cmd]
        self.argvs.append(argv)
        code, out, err = self._answer(argv)
        if not (kwargs.get("text") or kwargs.get("universal_newlines")):
            return subprocess.CompletedProcess(argv, code, out.encode(), err.encode())
        return subprocess.CompletedProcess(argv, code, out, err)

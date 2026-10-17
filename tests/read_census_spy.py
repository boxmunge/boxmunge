"""The read census's spy (tests/test_staging_read_census.py).

Records, while a production command runs: every file opened (builtins, io,
os and tarfile's own alias), every docker argument and working directory
at each docker_run.run binding, each `compose config` (the unit tier's
stand-in never reaches docker_run), split into staging-model resolutions
and the rest, and every process spawned past those seams (refused).
"""
from __future__ import annotations

import builtins
import os
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from unittest.mock import patch

from boxmunge import docker, docker_run

SLOT = "/.releases/staged/"
# Resolved ambiguity 8: the meta (status summaries) and the staged
# compose.yml (DataDirs.staged), opened as files.
ALWAYS = ("/.releases/staged/meta.json", "/.releases/staged/release/compose.yml")
# Deploy and rollback also resolve staging's model for the D8 isolation
# proof; in the unit tier the stand-in for `compose config` opens these.
D8 = ALWAYS + ("/.releases/staged/compose.staging-base.yml",
               "/.releases/staged/compose.boxmunge-staging.yml",
               "/.releases/staged/release/.env")


@dataclass
class Seen:
    opened: list[str] = field(default_factory=list)
    docker: list[str] = field(default_factory=list)      # argv and cwd, flattened
    staging_models: list[dict] = field(default_factory=list)

    def violations(self, *, d8: bool = False) -> list[str]:
        allowed = D8 if d8 else ALWAYS
        found = [f"open {p}" for p in self.opened if SLOT in p and not p.endswith(allowed)]
        found += [f"docker {a}" for a in self.docker if SLOT in a]
        if not d8:
            found += [f"staging model {m}" for m in self.staging_models]
        return found


def _text(value) -> str | None:
    try:
        return os.fsdecode(value)
    except TypeError:
        return None


@contextmanager
def reads():
    seen = Seen()
    real_open, real_os_open, real_config = builtins.open, os.open, docker.compose_config

    def note(into: list[str], *values) -> None:
        into.extend(t for t in map(_text, values) if t is not None)

    def b_open(file, *a, **k):
        note(seen.opened, file)
        return real_open(file, *a, **k)

    def o_open(path, *a, **k):
        note(seen.opened, path)
        return real_os_open(path, *a, **k)

    def run(cmd, cwd=None, **k):
        note(seen.docker, *cmd, cwd or "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def config(project_dir, compose_files=None, **kw):
        if kw.get("project_name", "").endswith("-staging"):
            seen.staging_models.append({"cwd": str(project_dir), **kw})
        else:
            note(seen.docker, project_dir, *(compose_files or []),
                 kw.get("project_directory") or "", kw.get("env_file") or "")
        return real_config(project_dir, compose_files, **kw)

    def spawn(cmd, *a, cwd=None, **k):
        note(seen.docker, *([cmd] if isinstance(cmd, str) else cmd), cwd or "")
        raise OSError("the read census spawns no process")

    seams = [patch.object(mod, "_run", run) for name, mod in list(sys.modules.items())
             if name.startswith("boxmunge") and getattr(mod, "_run", None) is docker_run.run]
    with ExitStack() as stack:
        for seam in (patch("builtins.open", b_open), patch("io.open", b_open),
                     patch("os.open", o_open), patch("tarfile.bltn_open", b_open),
                     patch("subprocess.Popen", spawn),
                     patch.object(docker, "compose_config", config), *seams):
            stack.enter_context(seam)
        yield seen

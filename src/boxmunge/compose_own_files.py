# SPDX-License-Identifier: Apache-2.0
"""Bind mounts may not let a container change what boxmunge reads.

Root reads a project's files long after deploy validated them: timers and
upgrades re-run `docker compose up` on compose.yml, `.env` and the
generated overlays, deploy runs the manifest's pre_deploy command, and
rollback reinstalls the kept releases. A container that could write any of
those would hand root a compose file nobody validated (`privileged: true`,
`/:/host`) on its next recreate. So a read-write bind mount may not be the
project directory, be or contain one of those files, or lie inside one.
Mounting them read-only is fine.

A container that can write the directory holding a bind source can swap
that source for a symlink, and Docker follows it the next time the
container starts, including a start by its restart policy, which no
boxmunge check sees. So no bind source may lie inside a read-write one.
The same holds for a build's local inputs (context, Dockerfile, additional
contexts): the builder resolves a context root through a symlink, so a
container that swaps `./data/ctx` for a link to another project bakes that
project's files into an image it then runs. The rule is judged on the
declared paths, not on what exists at validation: a bundle is validated
before its `./data` exists.
(Between production and staging, `stage` refuses any bind source either
one shares with or nests inside the other: staging_isolation.)

Unlike the hardening rules these are not relaxed by `security.profile:
off`: they protect the platform, not the container.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable

from boxmunge.compose_build import local_build_inputs
from boxmunge.compose_mounts import (
    file_entries, path_within, project_rel, service_bind_entries,
)

# Project entries boxmunge reads or runs, relative to the project directory.
# repo/.git, not repo/: git runs hooks from it on the next deploy's fetch.
# compose.boxmunge-staging.yml and compose.staging-base.yml are a 0.10.1
# stage's files (legacy_stage), reserved until the upgrade floor passes the beta.
CONTROL_ENTRIES: tuple[str, ...] = (
    "compose.yml", "manifest.yml", ".env", "project.env", "secrets.env",
    "compose.boxmunge.yml", "compose.boxmunge-staging.yml", "compose.staging-base.yml",
    "caddy.override.conf", "security", ".releases", "boxmunge-scripts", "repo/.git",
)


def _within(path: str, root: str) -> bool:
    """path_within for project-relative paths, where `.` is the project
    directory and holds them all."""
    return root == "." or path_within(path, root)


def _project_rels(path: str, base_dir: Path, project_dir: Path) -> set[str]:
    """Where an absolute path lies, relative to the project, in both its
    spelled and symlink-resolved forms. A path under `base_dir` (where the
    compose file is validated, which during intake is not the project
    directory yet) is relative to it; any other one to the project dir."""
    rels: set[str] = set()
    for form in {os.path.abspath(path), os.path.realpath(path)}:
        for root in (base_dir, project_dir):
            rel = project_rel(form, root, literal=True)
            if rel is not None:
                rels.add(rel)
                break
    return rels


def service_binds(doc: dict[str, Any], base_dir: Path) -> list[tuple[str, str, str, bool]]:
    """(user, what, absolute source, read-write) for every host path the
    model mounts or builds from: service bind mounts, the files of top-level
    secrets and configs (mounted read-only), and each service's local build
    inputs (read, never written, by the builder)."""
    binds = []
    for svc_name, svc in (doc.get("services") or {}).items():
        if not isinstance(svc, dict):
            continue
        binds += [(f"service {svc_name}", "bind source", bind.path, bind.read_write)
                  for bind in service_bind_entries(svc_name, svc, base_dir)]
        for what, path in local_build_inputs(svc.get("build"), base_dir):
            binds.append((f"service {svc_name}", what, path, False))
    binds += [(f"{bind.section} {bind.name}", "bind source", bind.path, False)
              for bind in file_entries(doc, base_dir)]
    return binds


def _protected(base_dir: Path, project_dir: Path, read_files: Iterable[Path]) -> set[str]:
    protected: set[str] = set()
    for entry in CONTROL_ENTRIES:
        protected |= _project_rels(str(base_dir / entry), base_dir, project_dir)
    for path in read_files:
        protected |= _project_rels(str(path), base_dir, project_dir)
    return protected


def _own_file_hit(src: str, rels: set[str], protected: set[str]) -> str | None:
    hit = sorted(p for p in protected for rel in rels
                 if _within(p, rel) or _within(rel, p))
    return hit[0] if hit else None


def _bind_problems(
    binds: list[tuple[str, str, str, bool]], base_dir: Path, project_dir: Path,
    protected: set[str],
) -> list[str]:
    """`binds`: (user, what, absolute source, read-write), checked against
    the control files and for nesting inside each other."""
    located = [(user, what, src, rw, _project_rels(src, base_dir, project_dir))
               for user, what, src, rw in binds]
    problems: list[str] = []
    for user, _what, src, rw, rels in located:
        if not rw:
            continue
        hit = _own_file_hit(src, rels, protected)
        if hit:
            what = "the project directory" if "." in rels else src
            problems.append(
                f"{user}: mounts {what} read-write, which would let the "
                f"container rewrite {hit}, a file boxmunge reads when it "
                f"restarts the project as root. Mount it read-only (append "
                f"':ro'), and mount a data subdirectory such as ./data "
                f"read-write instead."
            )
    for user, _what, src, rw, rels in located:
        if not rw:
            continue
        for other_user, other_what, other_src, _, other_rels in located:
            if any(o != r and _within(o, r) for o in other_rels for r in rels):
                problems.append(
                    f"{other_user}: {other_what} {other_src} lies inside "
                    f"{src}, which {user} mounts read-write, so that "
                    f"container could replace it with a symlink to any host "
                    f"path, which Docker would follow the next time it starts "
                    f"the container or builds the image. Mount sibling "
                    f"directories (./data, ./uploads) instead of one inside "
                    f"another, and keep a secrets/configs file outside every "
                    f"directory a service mounts read-write, and every build "
                    f"context, Dockerfile and additional context too."
                )
    return problems


def own_file_problems(
    doc: dict[str, Any], base_dir: Path, project_dir: Path, read_files: Iterable[Path],
    *, in_place: bool = False,
) -> list[str]:
    """Every bind mount that would let a container change what boxmunge
    reads, or redirect another mount. `read_files` are the compose, include,
    extends, env and label files the compose file makes Compose read.

    By default `base_dir` stands in for the project dir the release will be
    installed in (a bundle under intake). `in_place`: the model runs from
    `base_dir` where it is (staging, from the slot's release inside
    `.releases`), so every path is located where it really lies."""
    stand_in = project_dir if in_place else base_dir
    protected = _protected(stand_in, project_dir, read_files)
    return _bind_problems(service_binds(doc, base_dir), stand_in, project_dir, protected)


def container_bind_problems(
    container_binds: Iterable[tuple[str, bool]], project_dir: Path,
    read_files: Iterable[Path],
) -> list[str]:
    """Run the own-file and nesting rules over the bind mounts a project's
    EXISTING containers hold (abs source, read-write). This catches a
    project deployed before these rules, whose container already mounts the
    project directory (or a control file) read-write: the record alone would
    bless that mount, so the running state is inspected directly."""
    protected = _protected(project_dir, project_dir, read_files)
    binds = [("an existing container", "bind source", src, rw) for src, rw in container_binds]
    return _bind_problems(binds, project_dir, project_dir, protected)

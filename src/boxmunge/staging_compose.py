# SPDX-License-Identifier: Apache-2.0
"""The staging compose base: the staged release's compose.yml rewritten so
staging shares nothing with production.

Staging runs from the slot with ``--project-directory <slot>/release``, so
a relative path resolves inside the staged release exactly as it will in
the project dir once promoted. Release-code paths therefore stay relative.
What production keeps as box state (data directories, secrets.env, ...)
is pointed at by absolute path: bind mounts and config/secret files at
the entry's ``-staging`` copy in the project dir, env files at the file
itself (Compose reads them; nothing is mounted). A path that leaves the
project is made absolute against the project dir, so it means what it
means for production (a bind gets the ``-staging`` suffix). Staging
builds from the staged tree: an absolute build input naming release code
in the project dir becomes the same path relative to the release, and one
in box state, or one with no staged counterpart, is refused. Explicit
volume and network names and published ports
are dropped (container_name never gets here: validation refuses it);
staging_isolation then proves the result disjoint.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from boxmunge.bind_mounts import project_relative
from boxmunge.bundle import BOXMUNGE_ENTRIES
from boxmunge.compose import ComposeError
from boxmunge.compose_mounts import is_bind_entry, volume_source
from boxmunge.staged_release import STAGING_BASE, STAGING_OVERLAY

STAGING_FILES = [STAGING_BASE, STAGING_OVERLAY]


def staging_source(source: str, project_dir: Path, box_state: set[str], *, bind: bool) -> str:
    """Where staging reads what production reads from ``source``. A bind
    (or config/secret file, which Compose mounts) gets staging's copy; an
    env file, read by Compose and never mounted, is the file itself."""
    rel = project_relative(source, project_dir)
    if rel is None:
        outside = source if os.path.isabs(source) or source.startswith("~") \
            else os.path.normpath(os.path.join(project_dir, source))
        return outside.rstrip("/") + ("-staging" if bind else "")
    if rel == ".":
        return source  # the isolation check refuses it, naming the mount
    top, _, rest = rel.partition(os.sep)
    if top not in box_state:
        return source
    if not bind:
        return str(project_dir / rel)
    return str(project_dir / f"{top}-staging" / rest) if rest else str(project_dir / f"{top}-staging")


def _staging_volume(entry: Any, project_dir: Path, box_state: set[str]) -> Any:
    if not is_bind_entry(entry):
        return entry
    new = staging_source(volume_source(entry), project_dir, box_state, bind=True)
    if isinstance(entry, dict):
        return {**entry, "source": new}
    return ":".join([new, *entry.split(":")[1:]])


def _staging_read_file(entry: Any, project_dir: Path, box_state: set[str]) -> Any:
    """An env_file or label_file entry: Compose reads the file, nothing mounts it."""
    if isinstance(entry, str):
        return staging_source(entry, project_dir, box_state, bind=False)
    if isinstance(entry, dict) and isinstance(entry.get("path"), str):
        return {**entry, "path": staging_source(entry["path"], project_dir, box_state, bind=False)}
    return entry


def _outside(path: str, project_dir: Path) -> str:
    """A path leaving the project, absolute so it means what it means for
    production."""
    return path if os.path.isabs(path) or path.startswith("~") \
        else os.path.normpath(os.path.join(project_dir, path))


def _release_code(path: str, base: str, project_dir: Path, box_state: set[str],
                  what: str) -> str | None:
    """Where in the project a local build input lies (``path`` resolved
    against ``base`` as Compose resolves it), or None outside it. Box state
    is refused: staging would build from release/'s copy of the name while
    production builds from the data itself. boxmunge's own entries are no
    release code at all, so nothing in the staged release stands for them."""
    if path.startswith("~"):
        return None
    rel = project_relative(os.path.join(base, path), project_dir)
    if rel is None:
        return None
    top = rel.partition(os.sep)[0]
    if top in BOXMUNGE_ENTRIES:
        raise _unmappable(path, what, f"is in {top}, which boxmunge keeps, not the release")
    if top in box_state:
        raise ComposeError(
            f"build {what} {path!r} is in {top}, which the project dir keeps as "
            f"server-owned state, not release code, so staging and production "
            f"would build from different files. Build from release code: move "
            f"the build inputs into a directory the release carries.")
    return rel


def _unmappable(path: str, what: str, why: str) -> ComposeError:
    return ComposeError(
        f"build {what} {path!r} {why}, so staging cannot build the staged "
        f"release's copy of it. Use a path relative to the release (for a "
        f"dockerfile, relative to a build context in the release).")


def _local_input(path: str, project_dir: Path, box_state: set[str], what: str) -> str:
    """A build context or additional context. Compose resolves a relative
    one against the project directory, which for staging is the staged
    release; an absolute one naming release code in the project dir would
    build production's copy, so it becomes the same path relative to the
    release."""
    if "://" in path:
        return path
    rel = _release_code(path, str(project_dir), project_dir, box_state, what)
    if rel is None:
        return _outside(path, project_dir)
    if not os.path.isabs(path):
        return path
    return "." if rel == "." else os.path.join(".", rel)


def _dockerfile(dockerfile: str, context: str, project_dir: Path, box_state: set[str]) -> str:
    """Compose resolves a relative dockerfile against the build context, so
    release code is named relative to staging's context; only an in-project
    context resolves in the staged release."""
    remote = "://" in context
    if remote and not os.path.isabs(dockerfile):
        return dockerfile  # a file of the remote context
    prod_context = os.path.normpath(os.path.join(project_dir, os.path.expanduser(context)))
    context_rel = None if remote else _release_code(
        context, str(project_dir), project_dir, box_state, "context")
    rel = _release_code(dockerfile, prod_context, project_dir, box_state, "dockerfile")
    if rel is None:
        if os.path.isabs(dockerfile) or dockerfile.startswith("~") or context_rel is None:
            return dockerfile
        return os.path.normpath(os.path.join(prod_context, dockerfile))
    if context_rel is None:
        raise _unmappable(dockerfile, "dockerfile", f"is release code in the project dir "
                          f"but the build context {context!r} is not in the release")
    if not os.path.isabs(dockerfile):
        return dockerfile
    return os.path.relpath(rel, context_rel)


def _staging_contexts(contexts: Any, project_dir: Path, box_state: set[str]) -> Any:
    def one(name: str, ref: str) -> str:
        return _local_input(ref, project_dir, box_state, f"additional_contexts.{name}")
    if isinstance(contexts, dict):
        return {k: one(k, v) if isinstance(v, str) else v for k, v in contexts.items()}
    if not isinstance(contexts, list):
        return contexts
    out = []
    for entry in contexts:
        name, sep, ref = entry.partition("=") if isinstance(entry, str) else ("", "", "")
        out.append(f"{name}={one(name, ref)}" if sep else entry)
    return out


def _staging_build(build: Any, project_dir: Path, box_state: set[str]) -> Any:
    if isinstance(build, str):
        return _local_input(build, project_dir, box_state, "context")
    if not isinstance(build, dict):
        return build
    build = dict(build)
    context = build.get("context", ".")  # Compose's default: the project directory
    if isinstance(build.get("context"), str):
        build["context"] = _local_input(context, project_dir, box_state, "context")
    if isinstance(build.get("dockerfile"), str) and isinstance(context, str):
        build["dockerfile"] = _dockerfile(build["dockerfile"], context, project_dir, box_state)
    if "additional_contexts" in build:
        build["additional_contexts"] = _staging_contexts(
            build["additional_contexts"], project_dir, box_state)
    return build


def _drop_names(doc: dict[str, Any], kind: str) -> None:
    decls = doc.get(kind)
    if not isinstance(decls, dict):
        return
    for key, decl in decls.items():
        if not isinstance(decl, dict):
            continue
        if decl.get("external"):
            raise ComposeError(f"top-level {kind[:-1]} {key!r} is external; "
                               f"staging would share it with production")
        decl.pop("name", None)


def generate_staging_compose_base(compose_path: Path, box_state: set[str],
                                  project_dir: Path) -> str:
    """Return the staged compose.yml rewritten for staging (module docstring).

    ``project_dir`` is production's project dir; ``box_state`` its entries
    that are not release code (data_dirs).
    Services pulled in by `include:` or `extends: {file: ...}` live in
    other files this rewrite cannot reach, so those are refused rather
    than staged with production's mounts.
    """
    doc = yaml.safe_load(Path(compose_path).read_text())
    if not isinstance(doc, dict):
        raise ComposeError(
            f"compose.yml must be a YAML mapping at the top level "
            f"(got {type(doc).__name__})"
        )
    services = doc.get("services")
    if services is not None and not isinstance(services, dict):
        raise ComposeError(
            f"compose.yml 'services' must be a mapping "
            f"(got {type(services).__name__})"
        )
    other_files = "include" in doc or any(
        isinstance(svc, dict) and isinstance(svc.get("extends"), dict)
        and "file" in svc["extends"] for svc in (services or {}).values()
    )
    if other_files:
        raise ComposeError(
            "stage cannot separate staging from production for services that "
            "come from include: or extends: file: (their bind mounts would be "
            "shared with production). Move those services into compose.yml to "
            "use stage."
        )
    _drop_names(doc, "volumes")
    _drop_names(doc, "networks")
    for section in ("configs", "secrets"):
        decls = doc.get(section)
        for decl in (decls.values() if isinstance(decls, dict) else []):
            if isinstance(decl, dict) and isinstance(decl.get("file"), str):
                decl["file"] = staging_source(decl["file"], project_dir, box_state, bind=True)
    for svc in (services or {}).values():
        if not isinstance(svc, dict):
            continue  # malformed entry: leave it for Compose to reject
        svc.pop("ports", None)
        volumes = svc.get("volumes")
        if isinstance(volumes, list):
            svc["volumes"] = [_staging_volume(v, project_dir, box_state) for v in volumes]
        for key in ("env_file", "label_file"):
            if svc.get(key) is not None:
                entries = svc[key] if isinstance(svc[key], list) else [svc[key]]
                svc[key] = [_staging_read_file(e, project_dir, box_state) for e in entries]
        if "build" in svc:
            svc["build"] = _staging_build(svc["build"], project_dir, box_state)
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)

# SPDX-License-Identifier: Apache-2.0
"""Each service's `build:` mapping as Compose merges it from the literal
compose files.

Compose's resolved model (`docker compose config`) drops a false
`build.pull`, so the files themselves are read, as compose_references
walks them. Compose (checked on v5.1.3) merges a build key by key, the
nearer definition winning: a service's own keys over the service it
`extends` (under any name, in any file), and the including file's keys
over an included file's service of the same name. A `build: <context>`
string is the mapping `{context: <context>}`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from boxmunge.compose_references import ComposeSources, compose_sources


def build_specs(compose_path: Path, roots: tuple[Path, ...]) -> dict[str, dict[str, Any]]:
    """{service: its merged `build:` mapping} for every service of the
    project that builds. Raises OSError, ValueError or yaml.YAMLError for
    files the reference walk cannot follow (validation refuses those
    first, so the caller treats it as a broken assumption)."""
    sources = compose_sources(compose_path, roots)
    specs: dict[str, dict[str, Any]] = {}
    for path in reversed(sources.project_files):  # the top file merges last, winning
        for name in sources.services(path):
            spec = _resolved(sources, path, name, frozenset())
            if spec is not None:
                specs[name] = _merge(specs.get(name, {}), spec)
    return specs


def service_contexts(spec: dict[str, Any]) -> set[str]:
    """The services a build names as `service:<name>` additional contexts."""
    return {v.removeprefix("service:") for v in _contexts(spec).values()
            if isinstance(v, str) and v.startswith("service:")}


def _resolved(sources: ComposeSources, path: Path, name: str,
              seen: frozenset[tuple[Path, str]]) -> dict[str, Any] | None:
    """``name``'s build in ``path``, merged over what it extends."""
    services = sources.services(path)
    if name not in services:
        raise ValueError(f"{path.name}: service {name!r} is extended but not defined")
    svc = services[name]
    if not isinstance(svc, dict):
        raise ValueError(f"{path.name}: service {name!r} is not a mapping")
    own = _normalised(svc.get("build"))
    parent = sources.extends.get((path, name))
    if parent is None:
        return own
    if (path, name) in seen:
        raise ValueError(f"{path.name}: service {name!r} extends itself")
    inherited = _resolved(sources, *parent, seen | {(path, name)})
    if inherited is None or own is None:
        return own if inherited is None else inherited
    return _merge(inherited, own)


def _normalised(build: Any) -> dict[str, Any] | None:
    if isinstance(build, str):
        return {"context": build}
    if not isinstance(build, dict):
        return None
    if isinstance(build.get("additional_contexts"), list):
        return {**build, "additional_contexts": _contexts(build)}
    return build


def _contexts(spec: dict[str, Any]) -> dict[str, Any]:
    """additional_contexts as a mapping (the list form is `name=value`)."""
    contexts = spec.get("additional_contexts") or {}
    if isinstance(contexts, dict):
        return contexts
    return dict(str(c).split("=", 1) for c in contexts if isinstance(c, str) and "=" in c)


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    """``over`` wins key by key; nested mappings merge the same way."""
    merged = dict(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged

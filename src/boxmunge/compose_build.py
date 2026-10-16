# SPDX-License-Identifier: Apache-2.0
"""Build-input isolation rules for user compose files.

A build runs on the host's builder, as whoever runs the deploy, so every
input it reads from the host must stay inside the project: the context,
each named additional context, the Dockerfile (resolved against the
context, the way the builder resolves it), and any cache directory. The
non-path forms that read nothing from this host stay allowed: remote git
and HTTP(S) contexts, `docker-image://` and `service:` additional
contexts, registry and inline caches. Anything else, including build keys
this module does not know, is refused, because it cannot be checked.

Build privileges (`network: host`, `privileged`, `entitlements`) are
hardening questions and live in compose_service_rules; these rules are not
relaxed by `security.profile: off`.
"""
from __future__ import annotations

import posixpath
from pathlib import Path
from typing import Any

from boxmunge.compose_mounts import host_path_forms, outside_roots

_REMOTE_PREFIXES = ("https://", "http://", "git://", "ssh://", "git@")
_ADDITIONAL_PREFIXES = _REMOTE_PREFIXES + ("docker-image://", "service:")
_SAFE_CACHE_TYPES = frozenset({"registry", "inline"})
_ALLOWED_BUILD_NETWORKS = frozenset({"", "default", "none", "host"})

# Keys that read nothing from the host and grant nothing beyond an ordinary
# build. `secrets` only names top-level secrets, whose files are confined
# by compose_isolation.
_PLAIN_KEYS = frozenset({
    "args", "dockerfile_inline", "extra_hosts", "isolation", "labels",
    "no_cache", "no_cache_filter", "platforms", "provenance", "pull", "sbom",
    "secrets", "shm_size", "tags", "target", "ulimits",
})
# Checked here or (privileges) in compose_service_rules.
_CHECKED_KEYS = frozenset({
    "context", "dockerfile", "additional_contexts", "network", "cache_from",
    "cache_to", "ssh", "entitlements", "privileged",
})

_KEEP_INSIDE = "Keep every build input inside the project directory."


def _is_remote(ref: str) -> bool:
    return ref.startswith(_REMOTE_PREFIXES)


def _has_scheme(ref: str) -> bool:
    return "://" in ref


class _BuildCheck:
    def __init__(self, svc_name: str, base_dir: Path, roots: tuple[Path, ...]) -> None:
        self.prefix = f"service {svc_name}:"
        self.base_dir = base_dir
        self.roots = roots
        self.problems: list[str] = []

    def _outside(self, label: str, path: str) -> None:
        if outside_roots(path, self.base_dir, self.roots):
            norm, _ = host_path_forms(path, self.base_dir)
            self.problems.append(
                f"{self.prefix} {label} resolves to {norm}, outside the project "
                f"directory. {_KEEP_INSIDE}"
            )

    def context(self, context: Any) -> str | None:
        """Check the main context; return its local path, or None if remote."""
        if context is None:
            return "."
        if not isinstance(context, str) or not context:
            self.problems.append(f"{self.prefix} build context {context!r} must be a path")
            return None
        if _is_remote(context):
            return None
        if _has_scheme(context):
            self.problems.append(
                f"{self.prefix} build context {context!r} is neither a path nor a "
                f"git or HTTP(S) URL. Use a directory inside the project or a "
                f"remote git repository."
            )
            return None
        self._outside(f"build context {context!r}", context)
        return context

    def dockerfile(self, dockerfile: Any, context: str | None) -> None:
        if not isinstance(dockerfile, str) or not dockerfile:
            return
        if not dockerfile.startswith("/") and context is None:
            return  # a path inside the remote repository
        local = dockerfile if dockerfile.startswith("/") else posixpath.join(
            host_path_forms(context or ".", self.base_dir)[0], dockerfile,
        )
        self._outside(f"build.dockerfile {dockerfile!r}", local)

    def additional_contexts(self, contexts: Any) -> None:
        if contexts is None:
            return
        if isinstance(contexts, list):
            contexts = dict(
                str(e).split("=", 1) if "=" in str(e) else (str(e), "") for e in contexts
            )
        if not isinstance(contexts, dict):
            self.problems.append(f"{self.prefix} build.additional_contexts must be a mapping")
            return
        for name, ref in contexts.items():
            label = f"build.additional_contexts.{name} {ref!r}"
            if not isinstance(ref, str) or not ref:
                self.problems.append(f"{self.prefix} {label} must be a path")
            elif ref.startswith(_ADDITIONAL_PREFIXES):
                continue
            elif _has_scheme(ref):
                self.problems.append(
                    f"{self.prefix} {label} reads from the host or a source "
                    f"boxmunge cannot check (oci-layout:// reads a host "
                    f"directory). Use a directory inside the project, "
                    f"docker-image://<image>, service:<name>, or a remote git URL."
                )
            else:
                self._outside(label, ref)

    def caches(self, key: str, entries: Any) -> None:
        for entry in entries if isinstance(entries, list) else [entries]:
            if entry is None:
                continue
            fields = dict(
                part.split("=", 1) for part in str(entry).split(",") if "=" in part
            )
            kind = fields.get("type", "registry").strip().lower()
            if kind not in _SAFE_CACHE_TYPES or {"src", "dest"} & set(fields):
                self.problems.append(
                    f"{self.prefix} build.{key} entry {entry!r} uses a cache that "
                    f"reads or writes host paths or a store boxmunge cannot check. "
                    f"Use type=registry,ref=<image> or type=inline, or remove it."
                )

    def network(self, network: Any) -> None:
        if network is None:
            return
        if not isinstance(network, str) or network.strip().lower() not in _ALLOWED_BUILD_NETWORKS:
            self.problems.append(
                f"{self.prefix} build.network {network!r} attaches build steps to "
                f"a Docker network by name, which may be another project's. "
                f"Remove it (builds use the default build network), or use none."
            )

    def ssh(self, ssh: Any) -> None:
        if ssh:
            self.problems.append(
                f"{self.prefix} build.ssh {ssh!r} hands build steps the SSH agent "
                f"or private key files of whoever runs the deploy. Remove it: "
                f"vendor private dependencies into the project before bundling, "
                f"or pass a credential as a build secret whose file is inside "
                f"the project."
            )

    def unknown_keys(self, build: dict[str, Any]) -> None:
        for key in build:
            if key in _PLAIN_KEYS or key in _CHECKED_KEYS or str(key).startswith("x-"):
                continue
            self.problems.append(
                f"{self.prefix} build.{key} is not a build option boxmunge "
                f"knows how to check. Remove it."
            )


def build_problems(
    svc_name: str, build: Any, base_dir: Path, roots: tuple[Path, ...],
) -> list[str]:
    """Return every build input of one service that reaches outside the project."""
    if build is None:
        return []
    if isinstance(build, str):
        build = {"context": build}
    if not isinstance(build, dict):
        return [f"service {svc_name}: build must be a path or a mapping"]
    check = _BuildCheck(svc_name, base_dir, roots)
    check.unknown_keys(build)
    context = check.context(build.get("context"))
    check.dockerfile(build.get("dockerfile"), context)
    check.additional_contexts(build.get("additional_contexts"))
    for key in ("cache_from", "cache_to"):
        check.caches(key, build.get(key))
    check.network(build.get("network"))
    check.ssh(build.get("ssh"))
    return check.problems

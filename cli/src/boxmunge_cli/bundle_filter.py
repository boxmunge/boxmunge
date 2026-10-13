# SPDX-License-Identifier: Apache-2.0
"""What goes into a bundle: the content policy and the tar writer.

Every path in the project tree gets exactly one verdict:

  never     Always left out, whatever .boxmungeignore says: VCS history,
            local .env files (Compose reads .env on the server), and the
            client's own .boxmunge config.
  refused   Bundling stops with an error unless .boxmungeignore excludes the
            path: secrets.env (it would replace the server's CLI-managed
            secrets), a top-level repo/ (it switches the project to git
            mode), symlinks that are absolute or leave the tree, and special
            files (devices, FIFOs, sockets).
  default   Left out unless a '!pattern' in .boxmungeignore re-includes it:
            dependency and cache dirs, compiled Python, earlier bundles, and
            the server-managed data/ and backups/ dirs.
  ignored   Matched by .boxmungeignore.
  shipped   Everything else.
"""

from __future__ import annotations

import fnmatch
import os
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from boxmunge_cli.ignore_rules import IgnoreRules

IGNORE_FILE = ".boxmungeignore"

_VCS_DIRS = frozenset({".git", ".hg", ".svn"})
_DEFAULT_EXCLUDED_DIRS = {
    "__pycache__": "Python bytecode cache",
    ".venv": "virtualenv",
    "venv": "virtualenv",
    "node_modules": "installed dependencies",
    ".mypy_cache": "tool cache",
    ".pytest_cache": "tool cache",
    ".ruff_cache": "tool cache",
    ".tox": "tool cache",
}
_SERVER_MANAGED_DIRS = {
    "data": "server-managed persistent data",
    "backups": "server-managed backups",
}


@dataclass
class BundlePlan:
    root: Path
    shipped: list[str] = field(default_factory=list)
    excluded: list[tuple[str, str]] = field(default_factory=list)
    refused: list[tuple[str, str]] = field(default_factory=list)


def _never(rel: str, name: str, is_dir: bool) -> str | None:
    if is_dir and name in _VCS_DIRS:
        return "version control history"
    if not is_dir and (name == ".env" or (name.startswith(".env.") and name != ".env.example")):
        return "local env file (may hold secrets); use project.env or 'secrets set'"
    if rel == ".boxmunge":
        return "client connection config"
    if rel == IGNORE_FILE:
        return "bundle ignore rules"
    return None


def _default_excluded(rel: str, name: str, is_dir: bool, project: str) -> str | None:
    if is_dir and name in _DEFAULT_EXCLUDED_DIRS:
        return _DEFAULT_EXCLUDED_DIRS[name]
    if is_dir and rel in _SERVER_MANAGED_DIRS:
        return _SERVER_MANAGED_DIRS[rel]
    if not is_dir and (name.endswith(".pyc") or name == ".DS_Store"):
        return "local build artefact"
    if not is_dir and "/" not in rel and fnmatch.fnmatchcase(name, f"{project}-*.tar.gz"):
        return "earlier bundle"
    return None


def _symlink_problem(root: Path, path: Path) -> str | None:
    target = os.readlink(path)
    if os.path.isabs(target):
        return f"absolute symlink -> {target}"
    resolved = os.path.realpath(path)
    real_root = os.path.realpath(root)
    if resolved != real_root and not resolved.startswith(real_root + os.sep):
        return f"symlink leaves the project tree -> {target}"
    return None


def _refused(root: Path, path: Path, rel: str, name: str, mode: int) -> str | None:
    if name == "secrets.env":
        return ("secrets.env must not ship: it would replace the server's secrets. "
                "Set secrets on the server with 'secrets set'")
    if stat.S_ISLNK(mode):
        return _symlink_problem(root, path)
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return "special file (device, FIFO or socket)"
    if rel == "repo" and stat.S_ISDIR(mode):
        return "a top-level repo/ switches the project to git mode on the server"
    return None


def plan_bundle(root: Path, project: str, skip: Path | None = None) -> BundlePlan:
    """Walk root and decide the fate of every entry. Nothing is written."""
    rules = IgnoreRules.from_file(root / IGNORE_FILE)
    plan = BundlePlan(root=root)
    skip_resolved = skip.resolve() if skip is not None else None

    def visit(dir_path: Path) -> None:
        for entry in sorted(os.scandir(dir_path), key=lambda e: e.name):
            path = Path(entry.path)
            rel = path.relative_to(root).as_posix()
            mode = os.lstat(path).st_mode
            is_dir = stat.S_ISDIR(mode)
            if skip_resolved is not None and path.resolve() == skip_resolved:
                plan.excluded.append((rel, "bundle being written"))
                continue
            reason = _never(rel, entry.name, is_dir)
            if reason:
                plan.excluded.append((rel + ("/" if is_dir else ""), reason))
                continue
            verdict = rules.match(rel, is_dir)
            if verdict is True:
                plan.excluded.append((rel + ("/" if is_dir else ""), f"listed in {IGNORE_FILE}"))
                continue
            if verdict is None:
                reason = _default_excluded(rel, entry.name, is_dir, project)
                if reason:
                    plan.excluded.append((rel + ("/" if is_dir else ""), reason))
                    continue
            problem = _refused(root, path, rel, entry.name, mode)
            if problem:
                plan.refused.append((rel, problem))
                continue
            plan.shipped.append(rel)
            if is_dir:
                visit(path)

    visit(root)
    return plan


def _normalise(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Drop local identity (uid/gid/user names) and special mode bits."""
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode &= 0o777
    return info


def write_bundle(plan: BundlePlan, arc_root: str, bundle_path: Path) -> None:
    """Write exactly the planned entries, under a single arc_root/ directory."""
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(plan.root, arcname=arc_root, recursive=False, filter=_normalise)
        for rel in plan.shipped:
            tar.add(plan.root / rel, arcname=f"{arc_root}/{rel}",
                    recursive=False, filter=_normalise)

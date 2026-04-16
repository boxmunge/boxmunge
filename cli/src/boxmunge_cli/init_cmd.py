# SPDX-License-Identifier: Apache-2.0
"""boxmunge init — create .boxmunge config and scaffold a new project."""

from __future__ import annotations

import re
import sys
from importlib import resources
from pathlib import Path

import yaml

_VALID_PROJECT = re.compile(r'^[a-z0-9][a-z0-9\-]{0,62}$')

_SCAFFOLD_FILES = {
    "manifest.yml": "manifest.yml",
    "compose.yml": "compose.yml",
    "boxmunge-scripts/smoke.sh": "smoke.sh",
    ".env.example": "env.example",
}


def _load_template(name: str) -> str:
    """Load a scaffold template from package data."""
    ref = resources.files("boxmunge_cli") / "templates" / name
    return ref.read_text(encoding="utf-8")


def _scaffold(target_dir: Path, project_name: str) -> None:
    """Create project skeleton files that don't already exist."""
    for dest_rel, template_name in _SCAFFOLD_FILES.items():
        dest = target_dir / dest_rel
        if dest.exists():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        content = _load_template(template_name).replace("{project}", project_name)
        dest.write_text(content)


def run_init(
    target_dir: Path,
    server: str,
    port: int = 922,
    user: str = "deploy",
    project: str | None = None,
    force: bool = False,
    no_scaffold: bool = False,
    force_scaffold: bool = False,
) -> int:
    """Create .boxmunge config and optionally scaffold project files."""
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    project_name = project or target_dir.name
    if not _VALID_PROJECT.match(project_name):
        print(
            f"ERROR: Invalid project name: {project_name!r}. "
            "Must be lowercase alphanumeric with hyphens, 1-63 chars.",
            file=sys.stderr,
        )
        return 1

    config_path = target_dir / ".boxmunge"
    if config_path.exists() and not force:
        print(
            f"ERROR: {config_path} already exists. Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1

    config = {
        "server": server,
        "port": port,
        "user": user,
        "project": project_name,
    }
    config_path.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))
    print(f"Created {config_path}")

    if no_scaffold:
        pass
    elif force_scaffold or not (target_dir / "manifest.yml").exists():
        _scaffold(target_dir, project_name)
        print("Scaffolded project files.")

    print("Tip: add .boxmunge to .gitignore if connection details vary per developer.")
    return 0


def cmd_init(args: list[str]) -> None:
    """CLI entry point for init command."""
    server = None
    port = 922
    user = "deploy"
    project = None
    force = False
    no_scaffold = False
    force_scaffold = False

    i = 0
    while i < len(args):
        if args[i] == "--server" and i + 1 < len(args):
            server = args[i + 1]
            i += 2
        elif args[i] == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif args[i] == "--user" and i + 1 < len(args):
            user = args[i + 1]
            i += 2
        elif args[i] == "--project" and i + 1 < len(args):
            project = args[i + 1]
            i += 2
        elif args[i] == "--force":
            force = True
            i += 1
        elif args[i] == "--no-scaffold":
            no_scaffold = True
            i += 1
        elif args[i] == "--force-scaffold":
            force_scaffold = True
            i += 1
        else:
            i += 1

    if not server:
        print("Usage: boxmunge init --server <hostname> [--port PORT] [--user USER] [--project NAME]",
              file=sys.stderr)
        sys.exit(2)

    sys.exit(run_init(
        Path.cwd(), server=server, port=port, user=user, project=project,
        force=force, no_scaffold=no_scaffold, force_scaffold=force_scaffold,
    ))

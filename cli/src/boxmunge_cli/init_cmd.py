# SPDX-License-Identifier: Apache-2.0
"""boxmunge init — create .boxmunge config and scaffold a new project."""

from __future__ import annotations

import argparse
import re
import sys
from importlib import resources
from pathlib import Path

import yaml

from boxmunge_cli.config import ConfigError, validate_config
from boxmunge_cli.manifest import placeholder_host, valid_host
from boxmunge_cli.ulid import generate_ulid

_VALID_PROJECT = re.compile(r'^[a-z0-9][a-z0-9\-]{0,62}$')

# destination -> (template, mode)
_SCAFFOLD_FILES = {
    "manifest.yml": ("manifest.yml", 0o644),
    "compose.yml": ("compose.yml", 0o644),
    "Dockerfile": ("Dockerfile", 0o644),
    "site/index.html": ("index.html", 0o644),
    "project.env": ("project.env", 0o644),
    "boxmunge-scripts/smoke.sh": ("smoke.sh", 0o755),
}


def _load_template(name: str) -> str:
    """Load a scaffold template from package data."""
    ref = resources.files("boxmunge_cli") / "templates" / name
    return ref.read_text(encoding="utf-8")


def _scaffold(target_dir: Path, project_name: str, host: str) -> None:
    """Create project skeleton files that don't already exist."""
    for dest_rel, (template_name, mode) in _SCAFFOLD_FILES.items():
        dest = target_dir / dest_rel
        if dest.exists():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        content = (
            _load_template(template_name)
            .replace("{project}", project_name)
            .replace("{host}", host)
            .replace("{ulid}", generate_ulid())
        )
        dest.write_text(content)
        dest.chmod(mode)


def run_init(
    target_dir: Path,
    server: str,
    port: int = 922,
    user: str = "deploy",
    project: str | None = None,
    force: bool = False,
    no_scaffold: bool = False,
    force_scaffold: bool = False,
    host: str | None = None,
) -> int:
    """Create .boxmunge config and optionally scaffold project files."""
    target_dir = target_dir.resolve()

    project_name = project or target_dir.name
    if not _VALID_PROJECT.match(project_name):
        print(
            f"ERROR: Invalid project name: {project_name!r}. "
            "Must be lowercase alphanumeric with hyphens, 1-63 chars.",
            file=sys.stderr,
        )
        return 1

    if host is not None and not valid_host(host):
        print(f"ERROR: Invalid --host {host!r}: expected a lowercase DNS name such as "
              f"{project_name}.example.com.", file=sys.stderr)
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
    try:
        validate_config(config)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    target_dir.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))
    print(f"Created {config_path}")

    if no_scaffold:
        pass
    elif force_scaffold or not (target_dir / "manifest.yml").exists():
        _scaffold(target_dir, project_name, host or placeholder_host(project_name))
        print("Scaffolded project files.")
        if host is None:
            print("Next: set your real hostname under 'hosts:' in manifest.yml "
                  "(bundling refuses the placeholder).")

    print("Tip: add .boxmunge to .gitignore if connection details vary per developer.")
    return 0


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"must be 1-65535: {value!r}")
    return port


def _cmd_init(args: argparse.Namespace) -> int:
    return run_init(
        Path.cwd(), server=args.server, port=args.port, user=args.user,
        project=args.project, force=args.force, no_scaffold=args.no_scaffold,
        force_scaffold=args.force_scaffold, host=args.host,
    )


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "init", help="Create .boxmunge and scaffold a project",
        description="Write .boxmunge (server connection details) in the current "
                    "directory and scaffold manifest.yml, compose.yml and "
                    "boxmunge-scripts/smoke.sh if no manifest exists yet.")
    p.add_argument("--server", required=True, metavar="HOST",
                   help="Server hostname or IP")
    p.add_argument("--port", type=_port, default=922,
                   help="Server SSH port (default: 922)")
    p.add_argument("--user", default="deploy", help="SSH user (default: deploy)")
    p.add_argument("--project", metavar="NAME",
                   help="Project name (default: the directory name)")
    p.add_argument("--host", metavar="NAME",
                   help="Public hostname the project serves (default: a placeholder "
                        "you must replace in manifest.yml)")
    p.add_argument("--force", action="store_true", help="Overwrite an existing .boxmunge")
    scaffold = p.add_mutually_exclusive_group()
    scaffold.add_argument("--no-scaffold", action="store_true",
                          help="Only write .boxmunge")
    scaffold.add_argument("--force-scaffold", action="store_true",
                          help="Scaffold missing files even if manifest.yml exists")
    p.set_defaults(func=_cmd_init)

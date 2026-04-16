"""boxmunge add-project <name> — scaffold a new project from template."""

import os
import shutil
import stat
import sys
from pathlib import Path

from boxmunge.paths import BoxPaths


PLACEHOLDER = "__PROJECT_NAME__"


def run_add_project(name: str, paths: BoxPaths) -> int:
    """Create a new project directory from the template.

    Returns 0 on success, 1 on failure.
    """
    project_dir = paths.project_dir(name)

    if project_dir.exists():
        print(f"ERROR: Project directory already exists: {project_dir}")
        return 1

    template_dir = paths.templates
    if not template_dir.exists():
        print(f"ERROR: Project template not found: {template_dir}")
        return 1

    shutil.copytree(template_dir, project_dir)

    for root, _dirs, files in os.walk(project_dir):
        for filename in files:
            filepath = Path(root) / filename
            if PLACEHOLDER in filename:
                new_name = filename.replace(PLACEHOLDER, name)
                new_path = Path(root) / new_name
                filepath.rename(new_path)
                filepath = new_path

            try:
                content = filepath.read_text()
                if PLACEHOLDER in content:
                    filepath.write_text(content.replace(PLACEHOLDER, name))
            except (UnicodeDecodeError, ValueError):
                pass

    for path in project_dir.rglob("*.template"):
        path.rename(path.with_suffix(""))

    for sh_file in project_dir.rglob("*.sh"):
        sh_file.chmod(sh_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    (project_dir / "backups").mkdir(exist_ok=True)
    (project_dir / "data").mkdir(exist_ok=True)

    print(f"Project '{name}' created at {project_dir}")
    print(f"Next steps:")
    print(f"  1. Edit {project_dir / 'manifest.yml'}")
    print(f"  2. Copy project.env.example to project.env and fill in secrets")
    print(f"  3. Configure boxmunge-scripts/smoke.sh")
    print(f"  4. Run: boxmunge validate {name}")
    return 0


def cmd_add_project(args: list[str]) -> None:
    """CLI entry point."""
    if not args:
        print("Usage: boxmunge add-project <name>", file=sys.stderr)
        sys.exit(2)
    paths = BoxPaths()
    sys.exit(run_add_project(args[0], paths))

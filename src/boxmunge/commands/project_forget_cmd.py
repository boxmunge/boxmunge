# SPDX-License-Identifier: Apache-2.0
"""boxmunge-server project-forget <project> — drop a registry entry whose
project directory is gone.

A project-delete that did not finish, or a directory removed by hand, leaves
the name in the registry with nothing behind it. This removes the entry and
the project's leftover state files. It refuses while the project directory
exists (project-delete is the way to remove a project) or while containers
of the project do. Operator-only: run it as root, as boxmunge-server.
"""
import sys

from boxmunge import docker_containers
from boxmunge.commands.project_delete_cmd import remove_project_state
from boxmunge.docker import DockerError
from boxmunge.fileutil import LockError, project_lock
from boxmunge.lifecycle import migration_refusal
from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import is_registered, remove_project


def run_project_forget(project: str, paths: BoxPaths) -> int:
    if not is_registered(project, paths):
        print(f"ERROR: project '{project}' is not registered.", file=sys.stderr)
        return 1
    if paths.project_dir(project).exists():
        print(f"ERROR: {paths.project_dir(project)} exists, so '{project}' is not "
              f"forgotten. To remove the project, run: project-delete {project}",
              file=sys.stderr)
        return 1
    refusal = migration_refusal(f"Forgetting '{project}'", paths)
    if refusal:
        print(f"ERROR: {refusal}", file=sys.stderr)
        return 1
    try:
        with project_lock(project, paths):
            containers = [c.name for p in (project, f"{project}-staging")
                          for c in docker_containers.project_containers(p)]
            if containers:
                print(f"ERROR: containers of '{project}' still exist "
                      f"({', '.join(containers)}). Remove them with: project-delete "
                      f"{project}", file=sys.stderr)
                return 1
            remove_project_state(paths, project)
            remove_project(project, paths)
    except (LockError, DockerError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    log_operation("project-forget", "Registry entry dropped (no project directory)",
                  paths, project=project)
    print(f"Project '{project}' forgotten: removed from the registry, with its "
          f"leftover state files.")
    return 0


def cmd_project_forget(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args("project-forget", args, min_positional=1, max_positional=1)
    project = require_project_name("project-forget", parsed.positional[0])
    sys.exit(run_project_forget(project, BoxPaths()))

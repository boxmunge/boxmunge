# SPDX-License-Identifier: Apache-2.0
"""Release intake: unpack and validate a candidate tree before it goes live.

Every bundle is extracted into ``<project>/.releases/incoming/`` and checked
there (manifest, identity, user compose hardening). Only a candidate that
passes every check is installed over the live project tree, so a rejected
bundle never reaches the files that root timers later ``compose up``
(audit C-01 / A-02).
"""
from __future__ import annotations

import os
import shlex
import shutil
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from boxmunge.bundle import check_bundle_contents, extract_bundle
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.identity import check_project_identity
from boxmunge.log import log_error
from boxmunge.manifest import (
    ManifestError, at_current_schema, load_manifest_as_written, validate_manifest,
)
from boxmunge.commit_scripts import SCRIPTS, links_refusal, script_links
from boxmunge.security_overlay import services_with_off_profile
from boxmunge.user_entries import USER_ENTRIES

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# Exit code reserved for compose hardening rejections (audit H-N2).
EXIT_COMPOSE_REJECTED = 3


class IntakeError(Exception):
    """A candidate release was refused. Carries the command's exit code."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@contextmanager
def incoming_workspace(paths: BoxPaths, project_name: str) -> Iterator[Path]:
    """Yield an empty ``.releases/incoming/`` dir, removed again on exit.

    Directories this creates (the project dir of a first deploy, the
    ``.releases`` dir) are removed too if they end up empty, so a refused
    first deploy leaves nothing behind. The caller holds the project lock,
    so a leftover ``incoming/`` can only be debris from a crashed run.
    """
    project_dir = paths.project_dir(project_name)
    releases = paths.project_releases(project_name)
    created_project = not project_dir.exists()
    created_releases = not releases.exists()
    incoming = releases / "incoming"
    if incoming.exists():
        shutil.rmtree(incoming)
    incoming.mkdir(parents=True)
    try:
        yield incoming
    finally:
        shutil.rmtree(incoming)
        if created_releases and not any(releases.iterdir()):
            releases.rmdir()
        if created_project and not any(project_dir.iterdir()):
            project_dir.rmdir()


def extract_candidate(bundle_path: Path, workspace: Path) -> Path:
    """Extract a bundle into the workspace and apply the content policy.

    Returns the project tree. A bundle carrying box-owned state
    (secrets.env, security/, data/, backups/) is refused here.
    """
    try:
        tree = extract_bundle(bundle_path, workspace)
        notes = check_bundle_contents(tree)
    except ValueError as e:
        raise IntakeError(str(e)) from e
    for note in notes:
        print(f"  {note}")
    return tree


def validate_release_tree(
    tree: Path, project_name: str, paths: BoxPaths, component: str,
    *, lenient_values: bool = False,
) -> dict[str, Any]:
    """Run every pre-install check on a release tree; return its manifest.

    `lenient_values` (see validate_manifest) is for re-checking a release that
    is already installed, as a start of its containers or a rollback does.

    Raises IntakeError (exit 1, or 3 for a compose hardening rejection).
    Warnings are printed; nothing on disk is changed.
    """
    manifest_path = tree / "manifest.yml"
    if not manifest_path.exists():
        raise IntakeError("Release is missing manifest.yml")
    if not (tree / "compose.yml").exists():
        raise IntakeError("Release is missing compose.yml")
    # Validated as written, so the schema gates (a block that needs a newer
    # schema_version) apply to the author's file; used at the current schema.
    try:
        written = load_manifest_as_written(manifest_path)
    except ManifestError as e:
        raise IntakeError(str(e)) from e

    errors, warnings = validate_manifest(
        written, project_name, lenient_values=lenient_values)
    if errors:
        detail = "\n".join(f"  {err}" for err in errors)
        raise IntakeError(f"Manifest validation failed:\n{detail}")
    for w in warnings:
        print(f"  WARN: {w}")
    try:
        manifest = at_current_schema(written, manifest_path)
    except ManifestError as e:
        raise IntakeError(str(e)) from e

    try:
        check_project_identity(project_name, manifest.get("id", ""), paths)
    except ValueError as e:
        raise IntakeError(str(e)) from e

    # A start of an installed release (lenient) is not refused for a script
    # it was deployed without: its smoke check says so instead.
    problems = [] if lenient_values else scripts_problems(tree, manifest)
    if problems:
        raise IntakeError("\n".join(problems))
    try:
        check_release_compose(tree, project_name, paths, manifest,
                              lenient_values=lenient_values)
    except ComposeSecurityError as e:
        log_error(component, f"Compose validation rejected: {e}",
                  paths, project=project_name)
        raise IntakeError(str(e), exit_code=EXIT_COMPOSE_REJECTED) from e
    return manifest


def check_release_compose(tree: Path, project_name: str, paths: BoxPaths,
                          manifest: dict[str, Any], *, lenient_values: bool = False) -> None:
    """The release's compose.yml against the hardening, isolation and
    posture rules (compose_validate.validate_user_compose), with the
    manifest (at the current schema) it would deploy with. Deploy and
    `validate` both run it. Raises ComposeSecurityError.

    User compose is checked against silent-floor-defeating keys before any
    overlay exists: compose's multi-file merge would otherwise let a user
    `privileged: true` win over the boxmunge baseline."""
    validate_user_compose(
        tree / "compose.yml", paths,
        off_services={svc for svc, _ in services_with_off_profile(manifest)},
        project_name=project_name,
        cve_policy=manifest.get("security"),
        manifest_services=manifest.get("services"),
        user_entries=manifest.get(USER_ENTRIES),
        lenient_values=lenient_values,
    )


def scripts_problems(tree: Path, manifest: dict[str, Any]) -> list[str]:
    """Each script the manifest runs that the release does not have as a
    regular file (a link is not one: it dangles in the container).

    A smoke check runs ``/boxmunge-scripts/<its file name>`` in the
    container, which mounts the release's ``boxmunge-scripts/``, and a
    relative pre_deploy command is run from the release's top directory.
    A git project's ``boxmunge-scripts/`` is its commit's when the commit
    has one (in ``repo/``; commit_scripts.install_commit_scripts copies it
    beside), else the project directory's own. Refused before compose runs:
    Docker would otherwise create a missing ``boxmunge-scripts/`` as an
    empty root-owned directory."""
    git = (tree / "repo").is_dir()
    from_repo = git and os.path.lexists(tree / "repo" / SCRIPTS)
    if from_repo:
        links = script_links(tree / "repo" / SCRIPTS)
        if links:
            return [links_refusal(links, "the repository")]
    problems = []
    services = manifest.get("services")
    for name, svc in (services.items() if isinstance(services, dict) else ()):
        smoke = svc.get("smoke") if isinstance(svc, dict) else None
        if isinstance(smoke, str) and smoke:
            rel = f"{SCRIPTS}/{PurePosixPath(smoke).name}"
            if not _has(tree, rel, from_repo):
                problems.append(f"service {name}: smoke {smoke!r} runs /{rel} in its "
                                f"container, but {_missing(rel, git, from_repo)}")
    program = _pre_deploy_program(manifest.get("deploy"))
    if "/" in program and not program.startswith("/"):
        rel = os.path.normpath(program)
        if not _has(tree, rel, from_repo):
            problems.append(f"deploy.pre_deploy runs {program!r} from the project "
                            f"directory, but {_missing(rel, git, from_repo)}")
    return problems


def _pre_deploy_program(deploy: object) -> str:
    hook = deploy.get("pre_deploy") if isinstance(deploy, dict) else None
    try:
        words = shlex.split(hook) if isinstance(hook, str) else []
    except ValueError:
        return ""  # validate_manifest names the quoting problem
    return words[0] if words else ""


def _has(tree: Path, rel: str, from_repo: bool) -> bool:
    """``rel`` is a regular file, not a link (lstat), in the release."""
    path = tree / "repo" / rel if from_repo and rel.split("/")[0] == SCRIPTS else tree / rel
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _missing(rel: str, git: bool, from_repo: bool) -> str:
    if not git:
        return (f"the release has no {rel}: add it to the project, then upload a new "
                f"bundle and deploy it")
    if rel.split("/")[0] == SCRIPTS:
        where = ("the repository has" if from_repo else
                 f"the commit has no {SCRIPTS}/, and the project directory has")
        return (f"{where} no {rel} as a regular file: commit it in the repository, then "
                f"deploy that commit")
    return (f"the project directory has no {rel}: of a git project's repository, only "
            f"{SCRIPTS}/ is put there, so commit the script under {SCRIPTS}/ and name it "
            f"as {SCRIPTS}/<script>")
def check_installable(tree: Path, project_dir: Path) -> None:
    """Refuse, before anything changes, a release install_release would refuse."""
    from boxmunge.release import check_install
    try:
        check_install(tree, project_dir)
    except ValueError as e:
        raise IntakeError(str(e)) from e


def report_refusal(e: IntakeError) -> int:
    """Print an intake refusal to stderr and return its exit code."""
    print(f"ERROR: {e}", file=sys.stderr)
    return e.exit_code

# SPDX-License-Identifier: Apache-2.0
"""Is this box ready for the release whose code runs this? (upgrade-readiness)

evaluate() checks the box and every deployed project against this release's
rules and returns a readiness_contract.Readiness. The upgrade check runs the
*target* release's copy, as the deploy user, under ProtectSystem=strict, so:

- It writes, logs and locks nothing: the log file is left alone (entries go
  to stderr), and no project lock is taken; a project mid-deploy is reported
  as left as is, which is what the apply does with it. (Run unconfined by
  hand, compose_resolve may create and remove an empty placeholder for an
  env file a compose.yml names and the project lacks: shared validation
  code, which the confinement stops.)
- It asks Docker only to inspect: `compose config`, `compose version`,
  `image inspect` and the dry run's renders. Never create, pull or build.
- It is never laxer than `upgrade --dry-run`: the floor and the dry run are
  rules here, so a box the dry run refuses is blocked.
- It opens a project file only once its stat says it is a regular file: a
  FIFO, device or link loop among a project's control files makes that
  project unreadable (a block) instead of stalling the check. No data tree
  is walked; a later rule that walks one must cap the walk.
"""
from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from boxmunge import docker_containers
from boxmunge.commands.upgrade_report import REFUSED, DryRunLine, check_upgrade, left_as_is
from boxmunge.commands.upgrade_steps import _compose_files, _project_dirs, require_manifest
from boxmunge.commands.validate import gather_validation
from boxmunge.compose_resolve import ComposeResolveError
from boxmunge.compose_version import MIN_COMPOSE_VERSION, UPGRADE_COMMAND, compose_version_problem
from boxmunge.deploy_dirs import fix_command
from boxmunge.deployed_inventory import InventoryError, started_images
from boxmunge.docker_run import DockerError
from boxmunge.log import no_log_file
from boxmunge.manifest import ManifestError, load_manifest_as_written
from boxmunge.paths import BoxPaths, InvalidProjectName, validate_project_name
from boxmunge.readiness_contract import Finding, ProjectReadiness, Readiness
from boxmunge.redeploy_hint import redeploy_or_bare
from boxmunge.state import read_state
from boxmunge.upgrade_floor import (
    BRIDGE_COMMAND, BRIDGE_RELEASE, RECORD_RE, STARTS_FROM, BelowUpgradeFloor,
    require_upgrade_floor,
)
from boxmunge.version import FALLBACK_VERSION, get_build_version, parse_version_string

UPGRADE_FLOOR = "box.upgrade_floor"
COMPOSE_VERSION = "box.compose_version"
DRY_RUN = "box.dry_run"
DOCKER = "box.docker"
VALIDATE = "project.validate"
COMPOSE = "project.compose"
LEFT_AS_IS = "project.left_as_is"
UNREADABLE = "project.unreadable"
IMAGE_MISSING = "project.image_missing"

# The files a project's rules open by name (Compose reads .env to interpolate).
_CONTROL_FILES = ("manifest.yml", "compose.yml", "compose.boxmunge.yml", ".env")
_RECHECK = "then run `upgrade-check` again"


def _block(rule: str, message: str, remedy: str) -> Finding:
    return Finding(rule, "block", "before", message, remedy)


def _todo(rule: str, message: str, remedy: str) -> Finding:
    return Finding(rule, "todo", "before", message, remedy)


@dataclass
class _Docker:
    """The first time Docker could not be asked: one box.docker block, and
    no image check after it."""
    error: DockerError | None = None

    def failed(self, error: DockerError) -> None:
        if self.error is None:
            self.error = error

    def finding(self) -> list[Finding]:
        if self.error is None:
            return []
        return [_block(DOCKER, f"Docker could not be asked: {self.error}",
                       f"make Docker answer the deploy user (as root: `systemctl start "
                       f"docker`), {_RECHECK}")]


def _installed(paths: BoxPaths) -> str | None:
    """The release config/version records, or None when it records none
    (the floor rule then blocks, saying why)."""
    try:
        held = RECORD_RE.fullmatch(paths.version_file.read_bytes())
    except OSError:
        return None
    return held["release"].decode() if held is not None else None


def _floor(paths: BoxPaths, installed: str | None) -> list[Finding]:
    record = paths.version_file
    try:
        require_upgrade_floor(paths, get_build_version())
        return []
    except OSError as e:
        found = f"it cannot be read: {e.strerror or e}"
    except BelowUpgradeFloor as e:
        if installed is not None:
            # Its first line: the rest is about the blocklist entry the
            # upgrade's own dry run leaves, which this check does not.
            return [_block(UPGRADE_FLOOR, str(e).split("\n", 1)[0],
                           f"upgrade to {BRIDGE_RELEASE} first: `upgrade --target "
                           f"{BRIDGE_RELEASE}` from the deploy shell, or `{BRIDGE_COMMAND}`, "
                           f"{_RECHECK}")]
        found = "it is missing" if not os.path.lexists(record) else "it holds something else"
    return [_block(UPGRADE_FLOOR,
                   f"{record} does not record the release this box runs as one line like "
                   f"{BRIDGE_RELEASE} ({found}), and {STARTS_FROM}",
                   f"as root, write the release this box runs into {record} as X.Y.Z alone "
                   f"(`/opt/boxmunge/env-active/bin/boxmunge-server --version` prints it "
                   f"after the word boxmunge), {_RECHECK}")]


def _compose_version() -> list[Finding]:
    problem = compose_version_problem()
    if problem is None:
        return []
    want = ".".join(map(str, MIN_COMPOSE_VERSION))
    return [_block(COMPOSE_VERSION, problem,
                   f"install Docker Compose {want} or newer, as root: {UPGRADE_COMMAND}")]


def _control_file_problem(project_dir: Path) -> str | None:
    """Why one of the project's control files must not be opened, from its
    stat alone (following links: a git project's link into repo/), or None.
    A missing one is left to the rules that need it."""
    for name in _CONTROL_FILES:
        path = project_dir / name
        try:
            mode = os.stat(path).st_mode
        except FileNotFoundError:
            continue
        except OSError as e:
            return f"{path} cannot be read: {e.strerror}"
        if not stat.S_ISREG(mode):
            return f"{path} is not a regular file (mode {oct(mode)}), so it is not opened"
    return None


def _unenterable(paths: BoxPaths) -> dict[str, Finding]:
    """project.unreadable for each project directory this user cannot enter.
    The dry run passes over one (os.path.lexists is False on EACCES), but the
    upgrade itself runs as root and reads it: skipping it here would pass
    what the upgrade checks."""
    found = {}
    for entry in sorted(paths.projects.iterdir()) if paths.projects.is_dir() else ():
        try:
            validate_project_name(entry.name)
        except InvalidProjectName:
            continue  # unmanageable at all; the upgrade reports it and goes on
        if entry.is_dir() and not os.access(entry, os.R_OK | os.X_OK):
            found[entry.name] = _block(
                UNREADABLE, f"{entry} cannot be read by the user this check runs as, "
                            f"so its files cannot be checked",
                f"give it back to the deploy user (`{fix_command(entry)}`), {_RECHECK}")
    return found


def _unnamed(name: str, text: str) -> str:
    """A dry-run line as a project finding's message: without the `<name>: `
    the dry run starts it with. A finding is listed under its project, and
    the shim's summary names the project before it."""
    return text.removeprefix(f"{name}: ")


def _unreadable_remedy(paths: BoxPaths, name: str) -> str:
    return (f"restore the project's files: `{redeploy_or_bare(paths, name)}` deploys its "
            f"installed release again, or `project-delete {name}` removes the project")


def _unreadable(paths: BoxPaths, project_dir: Path) -> Finding | None:
    """project.unreadable, before anything else reads the project."""
    problem = _control_file_problem(project_dir)
    if problem is None:
        try:
            load_manifest_as_written(require_manifest(project_dir))
        except ManifestError as e:
            problem = str(e)
    if problem is None:
        return None
    return _block(UNREADABLE, problem, _unreadable_remedy(paths, project_dir.name))


def _dry_run(paths: BoxPaths, skip: set[str],
             docker: _Docker) -> tuple[dict[str, list[DryRunLine]], list[Finding]]:
    """The upgrade's own dry run: ({project: its refused lines}, box findings)."""
    try:
        lines = check_upgrade(paths, skip=skip)
    except DockerError as e:
        docker.failed(e)
        return {}, []
    except Exception as e:  # noqa: BLE001 — as `upgrade --dry-run`: any failure fails it
        return {}, [_block(DRY_RUN, f"the upgrade's dry run fails: {e}",
                           f"fix what the message names, {_RECHECK}")]
    refused: dict[str, list[DryRunLine]] = {}
    for line in lines:
        if line.kind == REFUSED and line.project is not None:
            refused.setdefault(line.project, []).append(line)
    return refused, []


def _ever_deployed(paths: BoxPaths, name: str) -> bool:
    """Whether a deploy recorded a release for it. A git project added but
    not yet deployed has a manifest (a link into repo/) and no images until
    its first deploy builds or pulls them: nothing of it is missing."""
    ref = read_state(paths.project_deploy_state(name)).get("current_ref")
    return isinstance(ref, str) and bool(ref)


def _missing_images(paths: BoxPaths, name: str, docker: _Docker) -> list[Finding]:
    if docker.error is not None or not _ever_deployed(paths, name):
        return []
    project_dir = paths.project_dir(name)
    try:
        images = started_images(project_dir, _compose_files(paths, name), name)
    except (ComposeResolveError, InventoryError) as e:
        return [_block(UNREADABLE, f"its deployed compose model cannot be resolved: {e}",
                       _unreadable_remedy(paths, name))]
    missing = []
    for service, ref in sorted(images.items()):
        try:
            present = docker_containers.local_image(ref) is not None
        except DockerError as e:
            docker.failed(e)
            return []
        if not present:
            missing.append(_block(
                IMAGE_MISSING, f"service {service} starts from image {ref}, which is not "
                               f"on this box, so the project cannot be started as deployed",
                f"`{redeploy_or_bare(paths, name)}` pulls or builds it again, or "
                f"`project-delete {name}` removes the project"))
    return missing


def _project(paths: BoxPaths, name: str, refused: list[DryRunLine],
             docker: _Docker) -> ProjectReadiness:
    findings = [_todo(COMPOSE, _unnamed(name, line.text), str(line.remedy)) for line in refused]
    findings += [_todo(VALIDATE, error,
                       f"fix it in the project's source and deploy the fixed release: "
                       f"`prod-deploy {name}` after uploading it, or once the fix is on a "
                       f"git project's ref; `validate {name}` lists every problem, and "
                       f"the next deploy is refused until they are fixed")
                 for error in gather_validation(name, paths)[0]]
    return ProjectReadiness(name, tuple(findings + _missing_images(paths, name, docker)))


def _crash(what: str, e: Exception) -> str:
    return f"{what} could not be checked: {type(e).__name__}: {e}"


def _box_rule(rule: str, check: Callable[[], list[Finding]]) -> list[Finding]:
    """A box rule's findings; one that fails is a block naming the failure,
    never a missing verdict (stdout must stay one contract-1 object)."""
    try:
        return check()
    except Exception as e:  # noqa: BLE001 — reported as a block, never swallowed
        return [_block(rule, _crash(rule, e), f"fix what the message names, {_RECHECK}")]


def _project_rule(paths: BoxPaths, name: str, check: Callable[[], ProjectReadiness | None]
                  ) -> ProjectReadiness | None:
    """A project's findings; a check that fails on it is project.unreadable
    naming the failure and the project."""
    try:
        return check()
    except Exception as e:  # noqa: BLE001 — reported as a block, never swallowed
        return ProjectReadiness(name, (_block(UNREADABLE, _crash(f"project {name}", e),
                                              _unreadable_remedy(paths, name)),))


def _settled(paths: BoxPaths, name: str) -> ProjectReadiness | None:
    """The project's verdict when nothing more of it is to be read, or None.
    Mid-deploy, it is left as is, as the dry run and the apply leave it:
    its files are not read at all. Otherwise, unreadable files block it
    before anything opens them."""
    left = left_as_is(paths, name)
    if left is not None:
        return ProjectReadiness(name, (_todo(LEFT_AS_IS, _unnamed(name, left.text),
                                             str(left.remedy)),))
    finding = _unreadable(paths, paths.project_dir(name))
    return None if finding is None else ProjectReadiness(name, (finding,))


def _evaluate(paths: BoxPaths) -> Readiness:
    installed = _installed(paths)
    box = (_box_rule(UPGRADE_FLOOR, lambda: _floor(paths, installed))
           + _box_rule(COMPOSE_VERSION, _compose_version))
    docker = _Docker()
    try:
        unenterable = _unenterable(paths)
        names = sorted({d.name for d in _project_dirs(paths)} | set(unenterable))
    except Exception as e:  # noqa: BLE001 — as the dry run, which lists them first
        box += [_block(DRY_RUN, _crash("the projects", e), f"fix what the message names, "
                                                           f"{_RECHECK}")]
        unenterable, names = {}, []
    settled = {name: ProjectReadiness(name, (unenterable[name],)) if name in unenterable
               else _project_rule(paths, name, lambda name=name: _settled(paths, name))
               for name in names}
    refused, failed = _dry_run(paths, {n for n, p in settled.items() if p is not None}, docker)
    projects = tuple(
        settled[name] or _project_rule(paths, name, lambda name=name: _project(
            paths, name, refused.get(name, []), docker))
        for name in names)
    return Readiness(release=parse_version_string(get_build_version())[0],
                     installed=installed or FALLBACK_VERSION,
                     box=tuple(box + failed + docker.finding()), projects=projects)


def evaluate(paths: BoxPaths) -> Readiness:
    """The box and every project with a manifest (a pre-registered one has
    none), against this release's rules. `installed` is 0.0.0 when
    config/version records no release, and box.upgrade_floor then blocks."""
    with no_log_file(paths):
        return _evaluate(paths)

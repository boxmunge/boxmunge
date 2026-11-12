# SPDX-License-Identifier: Apache-2.0
"""The upgrade's dry run (`upgrade --dry-run`), as structured lines.

check_upgrade renders every project's migrated manifest and configs in
memory, as the apply (upgrade_exclusions, upgrade_steps) would, and writes,
locks and logs nothing of its own. Each DryRunLine names its project and
its kind, and a refused or left line carries what clears it, so the
readiness check (boxmunge.readiness) can list them; the dry run prints the
text, which is unchanged.
"""
from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.caddy import generate_caddy_config, override_refusal
from boxmunge.commands.upgrade_offline import (
    UnreadableRecord, in_memory_line, offline_exit, offline_refusal, render_overlay,
)
from boxmunge.commands.upgrade_steps import (
    _links_into_repository, _migrated, _project_dirs, _unreadable_release_files,
    compose_refusal, exclusion, install_exclusion_text, refuse_unresolved_stages,
    require_manifest,
)
from boxmunge.git_layout import relink_advice, repo_ownership_advice, unlinked_files
from boxmunge.lifecycle import is_blocked
from boxmunge.manifest import CURRENT_SCHEMA_VERSION, load_manifest_as_written
from boxmunge.pause import render_maintenance_caddy_config
from boxmunge.paths import BoxPaths
from boxmunge.redeploy_hint import redeploy_or_bare
from boxmunge.release_txn import InstallTxn
from boxmunge.user_entries import split_user_entries

OK = "ok"              # renders as the apply will write it
WARNING = "warning"    # renders, with something the operator should fix
REFUSED = "refused"    # the apply leaves it on its current configs and containers
LEFT = "left"          # the apply leaves it exactly as it is (an open install, say)
KINDS = (OK, WARNING, REFUSED, LEFT)


@dataclass(frozen=True)
class DryRunLine:
    """One line of the dry run. `remedy` (refused and left lines only) is
    what clears it, naming the commands."""
    project: str | None
    kind: str
    text: str
    remedy: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"dry-run line kind {self.kind!r} is not one of {KINDS}")
        if (self.kind in (REFUSED, LEFT)) != (self.remedy is not None):
            raise ValueError(f"a {self.kind} dry-run line has a remedy exactly when it "
                             f"is refused or left: {self.text}")


def left_as_is(paths: BoxPaths, name: str) -> DryRunLine | None:
    """The line for a project the apply will leave as it is (exclusion), or
    None. Its files are neither rendered nor checked, so such a project can
    never fail the dry run. The remedy is what the apply reports for it."""
    why = exclusion(paths, name)
    if why is None:
        return None
    if isinstance(why, InstallTxn):
        line = f"{name}: an install ({why.ref}, {why.phase}) is open; the project will be left as is"
        unreadable = _unreadable_release_files(paths, name, why)[1]
        return DryRunLine(name, LEFT, line if unreadable is None else f"{line} ({unreadable})",
                          install_exclusion_text(paths, name, why))
    if isinstance(why, UnreadableRecord):
        return DryRunLine(name, LEFT, f"{name}: the project will be left as is: {why.text}",
                          why.text)
    return DryRunLine(name, LEFT, f"{name}: {why}; the project will be left as is", str(why))


def _compose_refused(name: str, refusal: str) -> DryRunLine:
    return DryRunLine(
        name, REFUSED,
        f"{name}: would be refused by this release's compose validator and left on its "
        f"current configs and containers, not restarted: {refusal}",
        f"fix compose.yml as the message says, then deploy the fixed release: "
        f"`prod-deploy {name}` (after uploading it, or once the fix is on a git "
        f"project's ref)")


def _offline(paths: BoxPaths, name: str, manifest: dict[str, Any], reason: str) -> DryRunLine:
    refusal = offline_refusal(paths, name, manifest)
    if refusal is None:
        return DryRunLine(name, OK, f"{name}: {reason}; keeps its maintenance page, "
                                    f"overlay renders OK")
    return DryRunLine(name, REFUSED, f"{name}: {reason}; keeps its maintenance page; would "
                                     f"be refused: {refusal}", offline_exit(paths, name))


def _rendered(paths: BoxPaths, name: str, manifest: dict[str, Any]) -> DryRunLine:
    """Render the project's configs as the apply would write them."""
    block = is_blocked(name, paths)
    if block and manifest.get("hosts"):
        render_maintenance_caddy_config(manifest["hosts"])
    refusal = compose_refusal(paths, name, manifest)
    if refusal is not None:
        return _compose_refused(name, refusal)
    if block:
        return _offline(paths, name, manifest, block.reason.value)
    refusal = override_refusal(paths, name)
    if refusal is not None:
        return DryRunLine(name, REFUSED, f"{name}: would be left on its current configs and "
                                         f"containers, not restarted: {refusal}",
                          f"fix the override as the message says, then "
                          f"`{redeploy_or_bare(paths, name)}`")
    if not paths.project_caddy_override(name).exists():
        generate_caddy_config(manifest)
    render_overlay(paths, name, manifest)
    return DryRunLine(name, OK, f"{name}: configs render OK")


def _project_lines(paths: BoxPaths, project_dir: Path) -> list[DryRunLine]:
    name = project_dir.name
    lines = []
    owner = repo_ownership_advice(project_dir)
    if owner is not None:
        lines.append(DryRunLine(name, WARNING, f"WARNING {owner}"))
    left = left_as_is(paths, name)
    if left is not None:
        return [*lines, left]
    manifest = load_manifest_as_written(require_manifest(project_dir))
    migrated = _migrated(project_dir, manifest)
    unlinked = unlinked_files(project_dir, manifest)
    if unlinked:
        lines.append(DryRunLine(name, WARNING, f"WARNING {relink_advice(project_dir, unlinked)}"))
    if migrated is not None:
        written = manifest.get("schema_version")
        if _links_into_repository(project_dir):
            lines.append(DryRunLine(name, WARNING, in_memory_line(name, written)))
        else:
            lines.append(DryRunLine(name, OK, f"{name}: migration OK (schema v{written or 1} "
                                              f"-> v{CURRENT_SCHEMA_VERSION})"))
        manifest = migrated
    lines.append(_rendered(paths, name, split_user_entries(manifest)))  # as loading does
    return lines


def check_upgrade(paths: BoxPaths, *, skip: Collection[str] = ()) -> list[DryRunLine]:
    """Dry run of migrate + regenerate: everything is rendered in memory and
    nothing is written, locked or logged. Raises on anything that would make
    --apply fail. Returns the lines, project by project.

    Projects in `skip` are not read: the readiness check found their files
    unreadable (a FIFO, say, which would stall the read) and blocks on them
    itself. `upgrade --dry-run` skips none."""
    project_dirs = list(_project_dirs(paths))
    refuse_unresolved_stages(paths, [project_dir.name for project_dir in project_dirs])
    return [line for project_dir in project_dirs if project_dir.name not in skip
            for line in _project_lines(paths, project_dir)]

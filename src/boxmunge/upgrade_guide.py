# SPDX-License-Identifier: Apache-2.0
"""The upgrade guide `upgrade-howto` prints, composed on the box.

Its only source is the target release's upgrade-notes.json, which the root
shim's `guide` verb prints once the release's cosign-signed SHA256SUMS
verifies it. The notes must be the target's own: the signing identity
accepts any release tag, so a signed older release's notes could be served
under a newer release's name, and compose_guide refuses them.

What the guide prints is printable characters and newlines only, whatever
the notes hold (release-lint refuses anything else; this is the second
line).
"""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from boxmunge.upgrade_notes import FILES, Entry, Guide, NotesError, parse_notes, select, version_key
from boxmunge.upgrade_shim import printable

FORMAT = 1
# upgrade_notes reads at most five digits a version part, so no release
# lies between X.(Y-1).99999 and X.Y.0.
_PART_MAX = 99999

BASE_IMAGES = (
    "Use the smallest official image for each project's stack (-slim or distroless), "
    "pinned by digest, and a multi-stage build that keeps compilers and package caches "
    "in the builder stage. Every OS package in an image is CVE surface: slimming an "
    "image beats suppressing its findings. More: agent-help images.")


def notes_baseline(installed: str) -> str:
    """The X.Y.Z that select() compares with: the release itself; for a
    pre-release X.Y.Z-pre, which comes before X.Y.Z, the last version before
    X.Y.Z, so the entries X.Y.Z introduced are shown (0.0.0 has none before
    it, and no entry is introduced there)."""
    core, _, pre = installed.partition("-")
    major, minor, patch = version_key(core)
    if not pre or (major, minor, patch) == (0, 0, 0):
        return core
    if patch:
        return f"{major}.{minor}.{patch - 1}"
    if minor:
        return f"{major}.{minor - 1}.{_PART_MAX}"
    return f"{major - 1}.{_PART_MAX}.{_PART_MAX}"


def compose_guide(raw: bytes, target: str, installed: str) -> Guide:
    """The guide for an upgrade from `installed` (the box's release, +build
    dropped) to `target`, from the target's verified upgrade-notes.json.
    Raises NotesError for notes that are not usable, or not the target's."""
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError) as e:  # JSONDecodeError, UnicodeDecodeError
        raise NotesError(f"not readable JSON ({type(e).__name__})") from None
    notes = parse_notes(doc)
    if notes.release != target:
        raise NotesError(f"they are the notes of release {notes.release}, not {target}, the "
                         f"release asked for; refusing them")
    return replace(select(notes, notes_baseline(installed)), installed=installed)


def _indented(text: str, indent: str) -> list[str]:
    """Not splitlines(): a control character must not start a line."""
    return [indent + line for line in printable(text).split("\n")]


def _entry_lines(e: Entry, bullet: str, indent: str) -> list[str]:
    return ([f"{bullet}[{e.kind}] {e.title}"] + _indented(e.change, indent)
            + _indented(f"Verify: {e.verify}", indent))


def _box_section(title: str, entries: tuple[Entry, ...]) -> list[str]:
    if not entries:
        return []
    lines = [f"{title}:"]
    for e in entries:
        lines += _entry_lines(e, "  - ", "      ")
    return lines + [""]


def _project_section(title: str, entries: tuple[Entry, ...]) -> list[str]:
    """A checklist per project file. An entry about several files is
    described under the first and pointed to from the others."""
    if not entries:
        return []
    lines = [f"{title}:"]
    for name in FILES:
        under = [e for e in entries if name in e.files]
        if not under:
            continue
        lines.append(f"  {name}:")
        for e in under:
            if e.files[0] == name:
                lines += _entry_lines(e, "    - [ ] ", "          ")
            else:
                lines.append(f"    - [ ] [{e.kind}] {e.title} (described under "
                             f"{e.files[0]})")
    return lines + [""]


def _next_steps(target: str) -> list[str]:
    check, upgrade = f"upgrade-check --version {target}", f"upgrade --target {target}"
    return [
        "Next steps:",
        "  1. Bring each project up to date with the checklists above, and deploy it.",
        "  2. Then, by what the person asked:",
        "     - \"Get ready for an upgrade\": stop, and tell the person the upgrade",
        f"       command: {upgrade}",
        f"     - \"Prepare, then do it\": run {check}, and only if its",
        f"       result is PASS, run {upgrade}",
        "  3. If the check fails, do not upgrade; report per project. Never force: forcing",
        "     is the operator's decision (force-target).",
    ]


def _below_floor_text(g: Guide) -> str:
    return (f"This box runs {g.installed}, below the upgrade floor {g.floor}: an upgrade to "
            f"{g.target} must start from {g.floor} or later. Upgrade by hand to {g.bridge} "
            f"first (the last release that installs over a box below {g.floor}), following "
            f"its release notes (from the deploy shell: upgrade --target {g.bridge}); then "
            f"run upgrade-howto again.")


def render_guide(guide: Guide) -> str:
    """The guide as text, sections in a fixed order, empty ones left out."""
    if guide.below_floor:
        return printable(_below_floor_text(guide))
    lines = [f"Upgrade guide: boxmunge {guide.installed} -> {guide.target}",
             f"From the signed release notes of {guide.target} (cosign-verified).", ""]
    lines += _box_section("Box, before the upgrade", guide.box_before)
    lines += _project_section("Each project, before the upgrade", guide.project_before)
    lines += _project_section("Each project, after the upgrade", guide.project_after)
    lines += _box_section("Box, after the upgrade", guide.box_after)
    if not (guide.box_before or guide.project_before or guide.project_after
            or guide.box_after):
        lines += ["The release notes ask nothing of this box or its projects.", ""]
    if guide.no_action:
        lines += [f"No project action needed for: {', '.join(guide.no_action)}", ""]
    lines += ["Base images:", f"  {BASE_IMAGES}", ""]
    lines += _next_steps(guide.target)
    return printable("\n".join(lines))


def up_to_date_text(installed: str, *, newest: bool) -> str:
    if newest:
        return f"This box runs {installed}, the newest release; nothing to prepare."
    return f"This box already runs {installed}; nothing to prepare."


def _entry_json(e: Entry) -> dict[str, Any]:
    return {"introduced": e.introduced, "id": e.id, "scope": e.scope, "when": e.when,
            "kind": e.kind, "title": printable(e.title), "change": printable(e.change),
            "verify": printable(e.verify), "files": list(e.files), "refs": list(e.refs)}


def _doc(installed: str, target: str, status: str, text: str, guide: Guide | None) -> dict:
    sections = ("box_before", "project_before", "project_after", "box_after")
    return {"guide": FORMAT, "installed": installed, "target": target, "status": status,
            "floor": guide.floor if guide else None, "bridge": guide.bridge if guide else None,
            **{s: [_entry_json(e) for e in getattr(guide, s)] if guide else []
               for s in sections},
            "no_action": list(guide.no_action) if guide else [], "text": text}


def guide_to_json(guide: Guide) -> dict[str, Any]:
    """`upgrade-howto --json`: the sections as data, and the guide as text."""
    return _doc(guide.installed, guide.target,
                "below_floor" if guide.below_floor else "guide", render_guide(guide), guide)


def up_to_date_json(installed: str, *, newest: bool) -> dict[str, Any]:
    return _doc(installed, installed, "up_to_date", up_to_date_text(installed, newest=newest),
                None)

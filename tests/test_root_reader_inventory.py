# SPDX-License-Identifier: Apache-2.0
"""The reader inventory: no reader of deploy-writable state is added
without being checked. Every call of a read helper in src/ is exercised by
a row of test_root_state_reads.py or named in ELSEWHERE, and is listed in
docs/DEVELOPMENT.md ("Reader and lock inventory"); a read that goes around
the helpers raises a module's count past RAW_READS. F11 was a reader none of these knew about."""
from __future__ import annotations

import ast
import os
import re
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from boxmunge import fs_nofollow
from tests.test_root_state_reads import DANGLING_ONLY, READERS, _outcome

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "boxmunge"
DOC = REPO / "docs" / "DEVELOPMENT.md"
TEXT_HELPERS = {"read_text_nofollow_or_none", "read_text_nofollow", "read_bytes_nofollow"}
OPENERS = {"open_regular_nofollow", "open_resolved_nofollow"}
Site = tuple[str, str]   # (module under src/boxmunge, function the call is in)


def _calls() -> Iterator[tuple[str, str, ast.Call]]:
    """(module, enclosing function, call) for every call in src/boxmunge."""
    for file in sorted(SRC.rglob("*.py")):
        todo: list[tuple[str, ast.AST]] = [("<module>", ast.parse(file.read_text()))]
        while todo:
            scope, node = todo.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = node.name
            if isinstance(node, ast.Call):
                yield file.relative_to(SRC).as_posix(), scope, node
            todo.extend((scope, child) for child in ast.iter_child_nodes(node))


def _name(call: ast.Call) -> str | None:
    return call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", None)


def _sites(helpers: set[str], *, read_only: bool = False) -> set[Site]:
    return {(module, fn) for module, fn, call in _calls()
            if _name(call) in helpers and module != "fs_nofollow.py"
            and (not read_only or ast.unparse(call.args[1]) == "os.O_RDONLY")}


# Readers whose refusals are tested somewhere other than a row above.
ELSEWHERE: dict[Site, str] = {
    ("health_checks/upgrade_slot.py", "check_upgrade_slot"): "test_health_checks/test_upgrade_slot.py",
    ("legacy_stage.py", "_json_doc"): "test_root_reads_nofollow.py",
    ("legacy_stage.py", "_state_active"): "test_root_reads_nofollow.py",
    ("legacy_stage.py", "stage_time"): "test_root_reads_nofollow.py",
    ("release_keep.py", "_reads_as"): "test_release_record_reads.py",
    ("release_txn.py", "_sha"): "test_release_record_reads.py",
    ("start_alerts.py", "record"): "test_root_state_reads.py (recorded over a link)",
}


def test_every_text_reader_is_checked_here_or_named(paths, tmp_path, monkeypatch) -> None:
    """A new reader of deploy-writable state gets a row in READERS (or in
    DANGLING_ONLY), so the link, FIFO and dangling-link tests run on it."""
    reached: set[Site] = set()
    real = fs_nofollow.read_bytes_nofollow

    def recording(path: Path, **kwargs: Any) -> bytes:
        frame = sys._getframe(1)
        while frame.f_code.co_filename == fs_nofollow.__file__:
            frame = frame.f_back
        module = Path(frame.f_code.co_filename).relative_to(Path(fs_nofollow.__file__).parent)
        reached.add((module.as_posix(), frame.f_code.co_name))
        return real(path, **kwargs)

    monkeypatch.setattr(fs_nofollow, "read_bytes_nofollow", recording)
    rows = [(r.path, r.read) for r in READERS] + [(path, read) for _n, path, read in DANGLING_ONLY]
    for path, read in rows:
        link = path(paths)
        link.parent.mkdir(parents=True, exist_ok=True)
        if not os.path.lexists(link):
            link.symlink_to(tmp_path / "gone.json")
        _outcome(lambda: read(paths))
    unchecked = _sites(TEXT_HELPERS) - reached
    assert unchecked == set(ELSEWHERE), (
        "a reader of deploy-writable state is not exercised by this file: add a row to "
        f"READERS in test_root_state_reads.py for it, or name its test in ELSEWHERE: {sorted(unchecked ^ set(ELSEWHERE))}")


def test_the_inventory_in_development_md_lists_every_reader() -> None:
    """A row's first cell is the module, its second the functions."""
    section = DOC.read_text().split("## Reader and lock inventory", 1)[1].split("\n## ", 1)[0]
    listed = {(module, fn) for module, fns in re.findall(r"^\| `([\w/]+\.py)` \| ([^|]+)\|",
                                                         section, re.M)
              for fn in re.findall(r"`(\w+)`", fns)}
    readers = _sites(TEXT_HELPERS) | _sites(OPENERS, read_only=True)
    assert listed == readers, (
        f"docs/DEVELOPMENT.md's reader inventory is out of date: {sorted(listed ^ readers)}")


def _goes_around_the_helpers(call: ast.Call) -> bool:
    """open(), Path.read_text(), Path.read_bytes() or Path.open()."""
    if isinstance(call.func, ast.Name):
        return call.func.id == "open"
    if not isinstance(call.func, ast.Attribute):
        return False
    on_module = isinstance(call.func.value, ast.Name) and call.func.value.id in {
        "os", "tarfile", "gzip"}
    return call.func.attr in {"read_text", "read_bytes"} or (
        call.func.attr == "open" and not on_module)


# Reads that go around the helpers, counted per module, as they stood when
# the inventory was taken (0.11.9). A baseline, not a certificate for each
# one: the count makes a new one a decision somebody has to take. Only a
# rise fails. A lower count is welcome, and the baseline may be lowered to
# match when convenient.
RAW_READS: dict[str, int] = {
    "api/actions/logs.py": 1, "api/dev/fixture_host.py": 3, "api/jobs.py": 2, "backup.py": 1,
    "bind_mounts.py": 1, "commands/bundle_cmd.py": 1, "commands/caddy_status.py": 1,
    "commands/diff_cmd.py": 2, "commands/doctor.py": 1, "commands/health_cmd.py": 1,
    "commands/help.py": 1, "commands/log_cmd.py": 1, "commands/logs.py": 1,
    "commands/quarantine_gate.py": 1, "commands/quarantine_lift.py": 1, "commands/stage_cmd.py": 1,
    "compose_references.py": 1, "compose_resolve.py": 3, "compose_up_steps.py": 1,
    "compose_validate.py": 1, "config.py": 1, "cve/kev_refresh.py": 1,
    "health_checks/projects.py": 1, "health_checks/sshd.py": 2, "health_checks/userns.py": 1,
    "manifest.py": 1, "secrets.py": 1, "staging_cleanup.py": 1, "staging_compose.py": 1,
    "staging_isolation.py": 2, "staging_prepare.py": 1, "system_container.py": 1,
    "tui/project_detail.py": 2, "upgrade_discovery.py": 1, "userns/marker.py": 1,
    "userns/offset.py": 6, "userns/preflight.py": 1, "userns/shift.py": 1, "userns/steps.py": 1,
    "version.py": 1,
}


def test_no_new_read_goes_around_the_helpers() -> None:
    found = dict(Counter(module for module, _fn, call in _calls()
                         if _goes_around_the_helpers(call) and module != "fs_nofollow.py"))
    grown = sorted(m for m, count in found.items() if count > RAW_READS.get(m, 0))
    assert not grown, (
        f"new reads go around fs_nofollow in {grown}. If deploy can write the path and "
        "root may read it, read it with fs_nofollow.read_text_nofollow_or_none and add a "
        "row to READERS in test_root_state_reads.py. Otherwise set the module's count in "
        f"RAW_READS: { {m: found[m] for m in grown} }")

"""Every rename in the modules that keep the slot, the transaction and the
legacy and stash state goes through a durable fileutil helper, and every
tree built aside is synced before it is renamed into place."""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src" / "boxmunge"
MODULES = ["staged_release.py", "release_txn.py", "release_keep.py", "stage_slot.py",
           "legacy_stage.py", "legacy_stage_ops.py", "stash_rewrite.py",
           # The commands that build, swap and drop the slot and the transaction.
           "commands/stage_cmd.py", "commands/unstage_cmd.py", "commands/promote_cmd.py",
           "commands/deploy_tree.py", "commands/install_abandon.py",
           "commands/install_txn_cmd.py", "commands/rollback.py"]
RAW = {"rename", "renames", "replace", "move"}


def _raw_rename(node: ast.AST) -> bool:
    if isinstance(node, ast.ImportFrom) and node.module in ("os", "shutil"):
        return any(alias.name in RAW for alias in node.names)
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr in ("rename", "renames"):
        return True
    # str.replace and dataclasses.replace are not renames; os.replace and
    # shutil.move are.
    return (isinstance(node.func.value, ast.Name)
            and (node.func.value.id, node.func.attr) in (("os", "replace"), ("shutil", "move")))


def test_no_raw_renames() -> None:
    offenders = []
    for name in MODULES:
        path = SRC / name
        if not path.exists():
            continue  # legacy_stage_ops and stash_rewrite arrive in PR D
        offenders += [f"{name}:{node.lineno}" for node in ast.walk(ast.parse(path.read_text()))
                      if _raw_rename(node)]
    assert offenders == [], f"use fileutil.durable_rename_dir / durable_rename: {offenders}"


def test_the_census_sees_a_raw_rename() -> None:
    tree = ast.parse("import os, shutil\nfrom os import replace\n"
                     "p.rename(q)\nos.replace(a, b)\nshutil.move(a, b)\n'x'.replace('a', 'b')\n")
    assert sum(_raw_rename(node) for node in ast.walk(tree)) == 4


def test_slot_is_synced_before_it_is_swapped_in(paths) -> None:
    from boxmunge import stage_slot, staged_release
    from tests.stage_helpers import prod_and_stage
    order: list[str] = []
    real_sync, real_swap = stage_slot.sync_tree, staged_release.swap_in
    with patch.object(stage_slot, "sync_tree", lambda p: (order.append("sync"), real_sync(p))), \
            patch("boxmunge.commands.stage_cmd.swap_in",
                  lambda pa, p: (order.append("swap"), real_swap(pa, p))):
        prod_and_stage(paths)
    assert order == ["sync", "swap"]


def _building(path: Path) -> Path | None:
    return next((p for p in (path, *path.parents) if p.name.endswith(".building")), None)


def test_every_built_tree_is_synced_before_its_rename(paths) -> None:
    """A tree built aside (``*.building``) is renamed into place only after
    sync_tree of it; a rename into a tree still being built precedes that
    tree's sync. Moves of trees already in place (aside, back) need none."""
    from boxmunge import fileutil
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.commands.promote_cmd import run_promote
    from boxmunge.commands.stage_cmd import run_stage
    from tests.bundle_helpers import place_bundle
    from tests.stage_helpers import V3, prod_and_stage, staging_docker_off
    events: list[tuple[str, Path, Path | None]] = []
    real_sync, real_rename = fileutil.sync_tree, fileutil.durable_rename_dir

    def sync(path):
        events.append(("sync", Path(path), None))
        real_sync(path)

    def rename(src, dest):
        events.append(("rename", Path(src), Path(dest)))
        real_rename(src, dest)

    seams = [patch.object(mod, attr, fake) for name, mod in list(sys.modules.items())
             if name.startswith("boxmunge")
             for attr, real, fake in (("sync_tree", real_sync, sync),
                                      ("durable_rename_dir", real_rename, rename))
             if getattr(mod, attr, None) is real]
    for seam in seams:
        seam.start()
    try:
        prod_and_stage(paths)
        place_bundle(paths, timestamp=V3)
        place_bundle(paths, timestamp="2026-10-16T120000000000")
        with staging_docker_off():
            assert run_stage("myapp", paths, ref=V3) == 0      # swaps over a slot
            assert run_promote("myapp", paths) == 0             # keeps previous/
            assert run_deploy("myapp", paths, ref="2026-10-16T120000000000") == 0  # supersedes it
    finally:
        for seam in seams:
            seam.stop()
    syncs = [(i, path) for i, (kind, path, _) in enumerate(events) if kind == "sync"]
    renames = [(i, src, dest) for i, (kind, src, dest) in enumerate(events) if kind == "rename"]
    built = [src.name for _, src, _ in renames if src.name.endswith(".building")]
    assert {"staged.building", "previous.building"} <= set(built), built
    assert any(src.name == "previous" for _, src, _ in renames), "no superseding keep ran"
    for i, src, dest in renames:
        if src.name.endswith(".building"):
            assert any(j < i and path == src for j, path in syncs), f"{src} renamed unsynced"
        inside = _building(dest)
        if inside is not None and inside != dest:
            assert any(j > i and path == inside for j, path in syncs), f"{inside} never synced"

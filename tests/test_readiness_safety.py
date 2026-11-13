# SPDX-License-Identifier: Apache-2.0
"""The readiness check runs the target release's code against the live box,
as the deploy user under ProtectSystem=strict: it must write nothing, ask
Docker only to inspect, never stall on what a project directory holds (a
FIFO, a link loop, a huge data tree) and never quote a file's content.

Also: `upgrade --dry-run` prints what it printed before its lines gained a
project and a kind."""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from boxmunge import docker_containers
from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_report import check_upgrade
from boxmunge.fs_nofollow import read_bytes_following
from boxmunge.manifest import ManifestError, load_manifest_as_written
from boxmunge.readiness import evaluate
from boxmunge.readiness_contract import to_json
from boxmunge.release_txn import load_txn
from tests.readiness_helpers import (
    IMAGE, Recorder, add_project, ids, make_box, open_install, tree_state,
)

REAL_LOCAL_IMAGE = docker_containers.local_image
FORBIDDEN = {"create", "pull", "build", "run", "up", "start", "rm", "tag", "load", "commit"}


@pytest.fixture
def recorder(monkeypatch) -> Recorder:
    rec = Recorder()
    monkeypatch.setattr("boxmunge.docker_run.subprocess.run", rec)
    return rec


@pytest.fixture
def box(tmp_path: Path, recorder):
    return make_box(tmp_path / "bm")


def _evaluate_within(paths, seconds: float = 20):
    """evaluate() in a thread: a read that blocks fails the test instead of
    hanging it."""
    out: dict = {}
    worker = threading.Thread(target=lambda: out.update(r=evaluate(paths)), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), "the readiness check stalled"
    return out["r"]


def _a_busy_box(paths) -> None:
    """One project per kind of dry-run line, and one per finding."""
    add_project(paths, "alpha")
    add_project(paths, "beta", compose=f"name: other\nservices:\n  web:\n    image: {IMAGE}\n")
    add_project(paths, "gamma", compose=f"services:\n  web:\n    image: {IMAGE}\n"
                                        f"    pull_policy: always\n")
    add_project(paths, "delta")
    open_install(paths, "delta")
    add_project(paths, "omega")
    paths.project_manifest("omega").write_text("- not\n- a mapping\n")


def test_writes_nothing(box, fake_containers) -> None:
    _a_busy_box(box)
    fake_containers.images[IMAGE] = None
    before = tree_state(box.root)
    r = evaluate(box)
    assert {rule for _, rule in ids(r)} >= {
        "project.compose", "project.validate", "project.left_as_is", "project.unreadable",
        "project.image_missing"}
    assert tree_state(box.root) == before


def test_only_inspection_docker_calls(box, recorder, monkeypatch) -> None:
    """Every command is run captured (subprocess.run); a streamed one
    (Popen: up, pull, build) is never started."""
    import subprocess
    started = []

    def popen(cmd, *args, **kwargs):
        started.append([str(part) for part in cmd])
        raise AssertionError(f"started {cmd}")
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr("boxmunge.docker_containers.local_image", REAL_LOCAL_IMAGE)
    _a_busy_box(box)
    add_project(box, "paused")
    box.project_paused_state("paused").write_text('{"reason": "maintenance"}')
    evaluate(box)
    docker = recorder.docker()
    assert ["docker", "image", "inspect", IMAGE] in docker
    assert ["docker", "compose", "version", "--short"] in docker
    for argv in docker:
        assert not FORBIDDEN & set(argv), argv
    assert started == []


def test_fifo_manifest_does_not_block(box) -> None:
    pdir = add_project(box, "shop")
    (pdir / "manifest.yml").unlink()
    os.mkfifo(pdir / "manifest.yml")
    r = _evaluate_within(box)
    assert ids(r) == [("shop", "project.unreadable")]
    assert "not a regular file" in r.projects[0].findings[0].message


@pytest.mark.parametrize("name", ["compose.yml", ".env", "compose.boxmunge.yml"])
def test_a_fifo_control_file_does_not_block(box, name) -> None:
    pdir = add_project(box, "shop")
    (pdir / name).unlink(missing_ok=True)
    os.mkfifo(pdir / name)
    assert ids(_evaluate_within(box)) == [("shop", "project.unreadable")]


def test_symlink_loop_compose_is_unreadable_not_hang(box) -> None:
    pdir = add_project(box, "shop")
    (pdir / "compose.yml").unlink()
    (pdir / "a").symlink_to(pdir / "b")
    (pdir / "b").symlink_to(pdir / "a")
    (pdir / "compose.yml").symlink_to(pdir / "a")
    r = _evaluate_within(box)
    assert ids(r) == [("shop", "project.unreadable")]


def test_message_never_quotes_a_linked_files_content(box, tmp_path) -> None:
    secret = tmp_path / "elsewhere.yml"
    secret.write_text("project: shop\npassword: SECRET-MARKER: [unclosed\n")
    pdir = add_project(box, "shop")
    (pdir / "manifest.yml").unlink()
    (pdir / "manifest.yml").symlink_to(secret)
    r = evaluate(box)
    assert ids(r) == [("shop", "project.unreadable")]
    assert "outside the project" in r.projects[0].findings[0].message  # refused, not read
    assert "SECRET-MARKER" not in str(to_json(r))


def test_no_data_tree_walk(box, monkeypatch) -> None:
    add_project(box, "shop")
    data = box.project_data("shop")
    data.mkdir()
    os.mkfifo(data / "pipe")
    (data / "loop").symlink_to(data / "loop")
    many = data / "many"
    many.mkdir()
    for i in range(50_000):
        os.close(os.open(many / f"f{i}", os.O_CREAT | os.O_WRONLY, 0o644))

    def guarded(real):
        def walk(path=".", *args, **kwargs):
            if str(os.fspath(path)).startswith(str(data)):
                raise AssertionError(f"walked the data tree: {path}")
            return real(path, *args, **kwargs)
        return walk
    for name in ("scandir", "walk", "listdir"):
        monkeypatch.setattr(os, name, guarded(getattr(os, name)))
    r = _evaluate_within(box, seconds=60)
    assert r.result == "pass", ids(r)


def test_manifest_loader_refuses_a_fifo_and_caps_the_size(tmp_path) -> None:
    fifo = tmp_path / "manifest.yml"
    os.mkfifo(fifo)
    with pytest.raises(ManifestError, match="not a regular file"):
        load_manifest_as_written(fifo)
    with pytest.raises(OSError, match="not a regular file"):
        read_bytes_following(tmp_path)
    big = tmp_path / "big.yml"
    big.write_text("project: shop\n" + "# padding\n" * 20)
    with pytest.raises(OSError, match="larger than 64 bytes"):
        read_bytes_following(big, limit=64)
    assert read_bytes_following(big, limit=1024).startswith(b"project: shop")
    huge = tmp_path / "huge.yml"
    with open(huge, "wb") as f:
        f.truncate(1024 * 1024 + 1)
    with pytest.raises(ManifestError, match="larger than 1048576 bytes"):
        load_manifest_as_written(huge)


def test_a_fifo_swapped_in_between_stat_and_open_is_refused_not_waited_on(
        tmp_path, monkeypatch) -> None:
    """The open is non-blocking and checked again after it: without either,
    this stalls (a blocking open of a FIFO) or reads it as empty."""
    target = tmp_path / "manifest.yml"
    target.write_text("project: x\n")
    real_stat, swapped = os.stat, []

    def stat_then_swap(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        if os.fspath(path) == str(target) and not swapped:
            swapped.append(True)
            os.unlink(target)
            os.mkfifo(target)
        return st
    monkeypatch.setattr(os, "stat", stat_then_swap)
    out: dict = {}

    def read() -> None:
        try:
            out["data"] = read_bytes_following(target)
        except OSError as e:
            out["error"] = e
    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "the open waited on the FIFO"
    assert swapped and "not a regular file" in str(out.get("error")), out


def test_dry_run_output_unchanged(box, capsys) -> None:
    """`upgrade --dry-run` prints each line's text, as before."""
    add_project(box, "alpha")
    add_project(box, "beta", compose=f"name: other\nservices:\n  web:\n    image: {IMAGE}\n")
    add_project(box, "delta")
    open_install(box, "delta")
    assert run_upgrade(box, dry_run=True) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[:3] == ["boxmunge upgrade --dry-run", "==========================", ""]
    assert out[3] == "  alpha: configs render OK"
    assert out[4].startswith("  beta: would be refused by this release's compose validator "
                             "and left on its current configs and containers, not "
                             "restarted: compose.yml sets a top-level name: 'other'.")
    phase = load_txn(box, "delta").phase
    assert out[5] == f"  delta: an install (delta-x, {phase}) is open; the project will be left as is"
    assert out[6:] == ["", "Dry-run complete. Nothing was written."]
    assert [f"  {line.text}" for line in check_upgrade(box)] == out[3:6]
    assert [line.kind for line in check_upgrade(box)] == ["ok", "refused", "left"]

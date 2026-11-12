"""Reviewer repros (never committed)."""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, os.environ["R215_PLUG"])
import r215_compare as old  # noqa: E402
from boxmunge import docker_containers as _dc  # noqa: E402
REAL_LI = _dc.local_image

from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_report import check_upgrade
from boxmunge.fs_nofollow import read_bytes_following
from boxmunge.manifest import ManifestError, load_manifest_as_written
from boxmunge.readiness import evaluate
from boxmunge.readiness_contract import to_json
from tests.readiness_helpers import Recorder, add_project, ids, make_box, open_install


@pytest.fixture
def recorder(monkeypatch) -> Recorder:
    rec = Recorder()
    monkeypatch.setattr("boxmunge.docker_run.subprocess.run", rec)
    return rec


@pytest.fixture
def box(tmp_path: Path, recorder):
    return make_box(tmp_path / "bm")


def test_open_install_with_corrupt_pause_record(box, capsys):
    add_project(box, "delta")
    open_install(box, "delta")
    box.project_paused_state("delta").write_text("{not json")
    try:
        print("OLD:", old._old_check(box))
    except Exception as e:
        print("OLD raised:", repr(e))
    try:
        print("NEW:", [l.text for l in check_upgrade(box)])
    except Exception as e:
        print("NEW raised:", repr(e))
    rc = run_upgrade(box, dry_run=True)
    print("NEW upgrade --dry-run rc:", rc)
    try:
        r = evaluate(box)
        print("READINESS:", json.dumps(to_json(r)))
    except Exception as e:
        print("READINESS raised:", repr(e))
    out = capsys.readouterr()
    sys.__stdout__.write(out.out + "\nERR:" + out.err + "\n")


@pytest.mark.parametrize("content", [
    "project: shop\npassword: !SECRET-TAG-MARKER value\n",
    "project: shop\npassword: *SECRET-ALIAS-MARKER\n",
    "project: shop\nkey: \"SECRET-ESC-MARKER\\q\"\n",
    "project: shop\n? [SECRET-KEY-MARKER]\n: x\n",
    b"project: shop\npassword: SECRET\xff\xfeMARKER\n",
])
def test_yaml_errors_quote(tmp_path, content):
    p = tmp_path / "manifest.yml"
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content)
    with pytest.raises(ManifestError) as e:
        load_manifest_as_written(p)
    sys.__stdout__.write(f"\nYAML ERR: {e.value}\n")


def test_device_via_link_refused(tmp_path):
    link = tmp_path / "manifest.yml"
    link.symlink_to("/dev/zero")
    with pytest.raises(OSError, match="not a regular file"):
        read_bytes_following(link)
    link2 = tmp_path / "m2.yml"
    link2.symlink_to("/dev/stdin")
    with pytest.raises(OSError):
        read_bytes_following(link2)


def test_swap_to_fifo_between_stat_and_open(tmp_path, monkeypatch):
    target = tmp_path / "manifest.yml"
    target.write_text("project: x\n")
    real_stat = os.stat
    calls = []

    def stat_then_swap(path, *a, **k):
        st = real_stat(path, *a, **k)
        if not calls:
            calls.append(1)
            target.unlink()
            os.mkfifo(target)
        return st
    monkeypatch.setattr(os, "stat", stat_then_swap)
    out = {}

    def run():
        try:
            read_bytes_following(target)
        except OSError as e:
            out["e"] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "stalled"
    assert "not a regular file" in str(out["e"])


def test_huge_file_cap(tmp_path):
    big = tmp_path / "manifest.yml"
    with open(big, "wb") as f:
        f.truncate(200 * 1024 * 1024)
    with pytest.raises(ManifestError, match="larger than"):
        load_manifest_as_written(big)


def test_unreadable_compose_as_this_user(box):
    pdir = add_project(box, "shop")
    (pdir / "compose.yml").chmod(0)
    try:
        r = evaluate(box)
        sys.__stdout__.write("\nUNREADABLE COMPOSE: " + json.dumps(to_json(r)) + "\n")
    finally:
        (pdir / "compose.yml").chmod(0o644)


def test_unreadable_env_as_this_user(box):
    pdir = add_project(box, "shop")
    (pdir / ".env").write_text("A=1\n")
    (pdir / ".env").chmod(0)
    try:
        r = evaluate(box)
        sys.__stdout__.write("\nUNREADABLE ENV: " + json.dumps(to_json(r)) + "\n")
    finally:
        (pdir / ".env").chmod(0o644)


def test_mid_deploy_with_bad_manifest(box):
    pdir = add_project(box, "delta")
    open_install(box, "delta")
    (pdir / "manifest.yml").write_text("- not a mapping\n")
    rc = run_upgrade(box, dry_run=True)
    r = evaluate(box)
    sys.__stdout__.write(f"\nMID-DEPLOY BAD MANIFEST: dry-run rc={rc}; readiness {ids(r)} {r.result}\n")


def test_apply_with_open_install_and_corrupt_pause(box):
    from boxmunge.upgrade_exclusions import apply_projects
    add_project(box, "delta")
    open_install(box, "delta")
    box.project_paused_state("delta").write_text("{not json")
    try:
        apply_projects(box)
        sys.__stdout__.write("\nAPPLY: ok\n")
    except Exception as e:
        sys.__stdout__.write(f"\nAPPLY raised: {e!r}\n")


def test_cli_crash_shape(box, monkeypatch, capsys):
    from boxmunge.commands.readiness_cmd import cmd_upgrade_readiness
    add_project(box, "delta")
    open_install(box, "delta")
    box.project_paused_state("delta").write_text("{not json")
    monkeypatch.setattr("boxmunge.commands.readiness_cmd.BoxPaths", lambda: box)
    try:
        cmd_upgrade_readiness(["--json"])
    except SystemExit as e:
        sys.__stdout__.write(f"\nCLI exit {e.code}\n")
    except Exception as e:
        sys.__stdout__.write(f"\nCLI raised {e!r}; stdout={capsys.readouterr().out!r}\n")


@pytest.mark.parametrize("extra", ["env_files: 5\n", "env_files: [5]\n", "services: [a]\n",
                                   "hosts: 7\n", "services:\n  web: 3\n"])
def test_malformed_manifest_values(box, extra):
    pdir = add_project(box, "shop")
    text = (pdir / "manifest.yml").read_text()
    import yaml
    doc = yaml.safe_load(text)
    doc.update(yaml.safe_load(extra))
    (pdir / "manifest.yml").write_text(yaml.dump(doc))
    rc = run_upgrade(box, dry_run=True)
    try:
        r = evaluate(box)
        res = f"{ids(r)} {r.result}"
    except Exception as e:
        res = f"raised {e!r}"
    sys.__stdout__.write(f"\nMALFORMED {extra!r}: dry-run rc={rc}; readiness {res}\n")


def test_no_popen_on_busy_box(box, recorder, monkeypatch):
    import subprocess
    from boxmunge import docker_containers
    from tests.test_readiness_safety import REAL_LOCAL_IMAGE, _a_busy_box
    seen = []

    def popen(cmd, *a, **k):
        seen.append(list(map(str, cmd)))
        raise AssertionError(f"Popen {cmd}")
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr("boxmunge.docker_containers.local_image", REAL_LI)
    _a_busy_box(box)
    # also paused + quarantined projects, a git project and an override
    add_project(box, "paused1")
    box.project_paused_state("paused1").write_text('{"reason": "x"}')
    r = evaluate(box)
    sys.__stdout__.write(f"\nPOPEN seen={seen}; ids={ids(r)}\nALL ARGV={sorted(set(' '.join(a[:3]) for a in recorder.argvs))}\n")
    assert not seen


def test_debug_argv(box, recorder, monkeypatch):
    from tests.test_readiness_safety import REAL_LOCAL_IMAGE, _a_busy_box
    monkeypatch.setattr("boxmunge.docker_containers.local_image", REAL_LI)
    _a_busy_box(box)
    r = evaluate(box)
    sys.__stdout__.write(f"\nDEBUG ids={ids(r)}\nARGV={recorder.argvs}\n")


@pytest.mark.parametrize("compose,fifo", [
    ("include:\n  - other.yml\nservices:\n  web:\n    image: nginx:1.25\n", "other.yml"),
    ("services:\n  web:\n    image: nginx:1.25\n    extends:\n      file: base.yml\n      service: b\n", "base.yml"),
    ("services:\n  web:\n    image: nginx:1.25\n    env_file: app.env\n", "app.env"),
    ("services:\n  web:\n    image: nginx:1.25\n    build: .\n", "Dockerfile"),
])
def test_fifo_referenced_file(box, compose, fifo):
    pdir = add_project(box, "shop", compose=compose)
    os.mkfifo(pdir / fifo)
    out = {}
    t = threading.Thread(target=lambda: out.update(r=evaluate(box)), daemon=True)
    t.start()
    t.join(15)
    if t.is_alive():
        sys.__stdout__.write(f"\nFIFO {fifo}: STALLED >15s\n")
        # unblock: open the fifo for writing a few times to release readers
        for _ in range(5):
            try:
                fd = os.open(pdir / fifo, os.O_WRONLY | os.O_NONBLOCK)
                os.close(fd)
            except OSError:
                pass
        t.join(5)
        pytest.fail("stalled")
    sys.__stdout__.write(f"\nFIFO {fifo}: {ids(out['r'])} {out['r'].result}\n")


def test_never_deployed_git_project(box, fake_containers):
    import yaml
    from boxmunge.manifest import CURRENT_SCHEMA_VERSION
    pdir = box.project_dir("fresh")
    repo = pdir / "repo"
    repo.mkdir(parents=True)
    (repo / "manifest.yml").write_text(yaml.dump({
        "schema_version": CURRENT_SCHEMA_VERSION, "project": "fresh", "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "git", "hosts": ["fresh.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}}}))
    (repo / "compose.yml").write_text("services:\n  web:\n    image: fresh/app:1\n")
    (pdir / "manifest.yml").symlink_to(repo / "manifest.yml")
    (pdir / "compose.yml").symlink_to(repo / "compose.yml")
    fake_containers.images["fresh/app:1"] = None
    rc = run_upgrade(box, dry_run=True)
    r = evaluate(box)
    sys.__stdout__.write(f"\nNEVER-DEPLOYED: dry-run rc={rc}; readiness {r.result} "
                         f"{[(p.name, f.id, f.message[:120]) for p in r.projects for f in p.findings]}\n")

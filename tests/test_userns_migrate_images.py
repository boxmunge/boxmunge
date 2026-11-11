"""A migration runs `docker save` once per image: the tar it keeps is the one
it reads for ids above 65535 (the preflight no longer streams each image)."""
from __future__ import annotations

import io

import pytest

from boxmunge.userns import engine as en
from boxmunge.userns import images as im
from boxmunge.userns import layers
from boxmunge.userns import preflight_checks as checks
from boxmunge.userns.inventory import ImageEntry, Inventory
from boxmunge.userns.journal import load_journal
from boxmunge.userns.preflight import Report
from boxmunge.userns.rollback import _refuse as rollback_accepts
from tests.integration.userns.dockerd import FakeTimers
from tests.test_userns_engine import _Daemon, box, flushes  # noqa: F401  (fixtures)
from tests.test_userns_layers import _layer, _save


def test_a_migration_saves_each_image_once(paths, box, monkeypatch, tmp_path) -> None:  # noqa: F811
    tar = _save(("blobs/sha256/a", _layer(0))).getvalue()
    inv = Inventory("overlay2", "", str(tmp_path / "docker"), "29.9.0", projects=["shop"],
                    images=[ImageEntry("sha256:" + "a" * 64, ["shop:1"], 1, True),
                            ImageEntry("sha256:" + "b" * 64, ["db:1", "db:latest"], 1, True)])
    saves: list[list[str]] = []

    def run(cmd, capture=False, timeout=None):
        saves.append(cmd)
        open(cmd[3], "wb").write(tar)

    class Streamed:  # `docker save <id>` to a pipe, as layers.image_high_ids runs it
        returncode = 0

        def __init__(self, cmd, **kw) -> None:
            saves.append(cmd)
            self.stdout = io.BytesIO(tar)

        def communicate(self, timeout=None):
            return b"", b""

    def image_checks(paths, inv, **kw) -> Report:  # preflight()'s call of them
        report = Report()
        checks.images(inv, report, scan=kw["scan_images"])
        return report
    monkeypatch.setattr(en, "take_inventory", lambda p: inv)
    monkeypatch.setattr(en, "preflight", image_checks)
    monkeypatch.setattr(en, "save_all", im.save_all)
    monkeypatch.setattr(im, "_run", run)
    monkeypatch.setattr(layers.subprocess, "Popen", Streamed)
    j = en.migrate(paths, daemon=_Daemon(), timers=FakeTimers(), images_dir=tmp_path / "b" / "img")
    assert j.phase == "applied"
    assert [c[:3] for c in saves] == [["docker", "save", "-o"]] * 2


def test_a_high_id_image_stops_the_migration_before_anything_is_stopped(
        paths, box, monkeypatch, tmp_path) -> None:  # noqa: F811
    """What the box sees now that the tar is what is read: the report says
    ready, the journal exists at `started`, the clean images' tars are kept,
    and an alert names the two commands, both of which this state accepts.
    No backup, no marker, no timer or container stopped, the daemon as it was."""
    calls, _ = box
    tars = {"shop:1": _save(("blobs/sha256/a", _layer(0))).getvalue(),
            "db:1": _save(("blobs/sha256/b", _layer(70000))).getvalue()}
    inv = Inventory("overlay2", "", str(tmp_path / "docker"), "29.9.0", projects=["shop"],
                    images=[ImageEntry("sha256:" + "a" * 64, ["shop:1"], 1, True),
                            ImageEntry("sha256:" + "b" * 64, ["db:1"], 1, True)])
    alerts = []
    monkeypatch.setattr(en, "take_inventory", lambda p: inv)
    monkeypatch.setattr(en, "save_all", im.save_all)
    monkeypatch.setattr(im, "_run", lambda cmd, capture=False, timeout=None:
                        open(cmd[3], "wb").write(tars[cmd[4]]))
    monkeypatch.setattr(en, "notify", lambda paths, title, body, **kw: alerts.append((title, body)))
    timers, daemon, images_dir = FakeTimers(), _Daemon(), tmp_path / "b" / "img"
    with pytest.raises(im.ImageError, match="image db:1 has files owned by ids above 65535"):
        en.migrate(paths, daemon=daemon, timers=timers, images_dir=images_dir)
    j = load_journal(paths)
    assert j.phase == "started" and j.failed.startswith("started: image db:1 has files")
    assert j.items == {f"image:sha256:{'a' * 64}": "saved"}
    assert [f.name for f in images_dir.iterdir()] == [f"{'a' * 64}.tar"]
    assert calls == [] and timers.calls == [] and daemon.calls == []  # no step after the save
    assert not paths.userns_marker.exists()
    (title, body), = alerts
    assert title == "userns migration stopped" and "timers are stopped" not in body
    assert body.endswith("Re-run userns-migrate to resume, or userns-rollback.")
    assert en._refuse_rerun(j) is j and rollback_accepts(j) is j

"""Patch records and the autofixing marker (cve.autofix_record)."""
from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.cve.autofix_record import (
    PackageChange, PatchRecord, clear_autofixing, clear_records,
    mark_autofixing, read_autofixing, read_records, write_records,
)
from boxmunge.state import StateError

P = "shop"
IMG = "sha256:" + "a" * 64


def _record(service: str = "web", **over) -> PatchRecord:
    rec = PatchRecord(
        project=P, service=service, base_ref="nginx:1.27", base_digest="sha256:" + "b" * 64,
        patched_ref=f"boxmunge.invalid/{P}/{service}:autofix-{'a' * 12}", patched_image_id=IMG,
        packages=(PackageChange("openssl", "3.0.1-1", "3.0.2-1"),), cves=("CVE-2026-1",),
        created_at=datetime.now(timezone.utc) - timedelta(minutes=5), trigger="urgent")
    return replace(rec, **over)


def test_round_trip(paths) -> None:
    recs = (_record("web"), _record("worker", trigger="nightly"))
    assert read_records(paths, P) == ()
    write_records(paths, P, recs)
    assert read_records(paths, P) == recs
    clear_records(paths, P)
    assert read_records(paths, P) == ()
    clear_records(paths, P)   # nothing there: not an error


@pytest.mark.parametrize("mangle", [
    lambda d: d.update(version=2),
    lambda d: d["records"][0].update(patched_image_id="sha256:short"),
    lambda d: d["records"][0].update(patched_ref="nginx:evil"),
    lambda d: d["records"][0].update(trigger="weekly"),
    lambda d: d["records"][0].update(created_at="2026-01-01T00:00:00"),
    lambda d: d["records"][0].update(
        created_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()),
    lambda d: d["records"][0].update(packages=[{"name": "x"}]),
    lambda d: d["records"][0].update(project="blog"),
    lambda d: d["records"].append(dict(d["records"][0])),
    lambda d: d.update(records=[]),
])
def test_bad_record_raises_state_error(paths, mangle) -> None:
    write_records(paths, P, (_record(),))
    path = paths.project_autofix_records(P)
    doc = json.loads(path.read_text())
    mangle(doc)
    path.write_text(json.dumps(doc))
    with pytest.raises(StateError, match=str(path)):
        read_records(paths, P)


def test_non_json_and_link_raise_state_error(paths) -> None:
    path = paths.project_autofix_records(P)
    path.parent.mkdir(parents=True)
    path.write_text("not json")
    with pytest.raises(StateError, match=str(path)):
        read_records(paths, P)
    path.unlink()
    os.symlink("/etc/hostname", path)
    with pytest.raises(StateError, match=str(path)):
        read_records(paths, P)


def test_marker_lifecycle(paths) -> None:
    assert read_autofixing(paths, P) is None
    marker = mark_autofixing(paths, P, ("CVE-2026-1", "CVE-2026-2"), downtime=True)
    assert marker.downtime and marker.cves == ("CVE-2026-1", "CVE-2026-2")
    assert read_autofixing(paths, P) == marker
    clear_autofixing(paths, P)
    assert read_autofixing(paths, P) is None
    clear_autofixing(paths, P)


def test_bad_marker_raises_state_error(paths) -> None:
    path = paths.project_autofix_marker(P)
    path.parent.mkdir(parents=True)
    for bad in ("{", json.dumps({"started_at": "2026-01-01T00:00:00", "cves": [], "downtime": False}),
                json.dumps({"started_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                            "cves": [], "downtime": False}),
                json.dumps({"started_at": datetime.now(timezone.utc).isoformat(),
                            "cves": [], "downtime": "yes"})):
        path.write_text(bad)
        with pytest.raises(StateError, match=str(path)):
            read_autofixing(paths, P)


def test_marker_link_raises_state_error(paths) -> None:
    path = paths.project_autofix_marker(P)
    path.parent.mkdir(parents=True)
    os.symlink("/etc/hostname", path)
    with pytest.raises(StateError, match=str(path)):
        read_autofixing(paths, P)


@pytest.mark.parametrize("bad", [
    {"patched_image_id": "sha256:short"},
    {"patched_ref": "nginx:evil"},
    {"patched_ref": f"boxmunge.invalid/blog/web:autofix-{'a' * 12}"},
    {"trigger": "weekly"},
    {"created_at": datetime(2026, 1, 1)},
    {"created_at": datetime.now(timezone.utc) + timedelta(hours=1)},
    {"cves": ("",)},
    {"base_ref": ""},
    {"packages": (PackageChange("x", "", "2"),)},
])
def test_a_bad_record_cannot_be_built(bad) -> None:
    """The rules live in PatchRecord, so a write can only be handed good ones."""
    with pytest.raises(ValueError):
        _record(**bad)


def test_write_rejects_another_projects_record(paths) -> None:
    other = _record(project="blog", patched_ref=f"boxmunge.invalid/blog/web:autofix-{'a' * 12}")
    with pytest.raises(StateError, match="refusing to write"):
        write_records(paths, P, (other,))
    assert not paths.project_autofix_records(P).exists()


def test_write_rejects_duplicate_services(paths) -> None:
    with pytest.raises(StateError, match="more than one record"):
        write_records(paths, P, (_record(), _record()))


def test_write_leaves_the_directory_deploy_owned(paths) -> None:
    from unittest.mock import patch
    chowned: list[str] = []
    with patch("boxmunge.fs_nofollow._chown_deploy", side_effect=chowned.append):
        write_records(paths, P, (_record(),))
        mark_autofixing(paths, P, ("CVE-2026-1",), downtime=False)
    assert str(paths.project_autofix_records(P).parent) in chowned

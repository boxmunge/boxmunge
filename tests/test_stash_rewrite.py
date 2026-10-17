"""D18: the latest stash is rewritten without symlink members, verified first."""
from __future__ import annotations

import io
import json
import os
import stat
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import stash_rewrite
from boxmunge.stash import META_FILENAME, create_stash, list_stashes
from boxmunge.stash_rewrite import REWRITE_PREFIX, sanitize_latest_stash


def _stash(paths, tmp_path, fmt: int = 1,
           name: str = "boxmunge-stash-2026-10-16T120000.tar.gz", meta_last: bool = True):
    """A stash as 0.10.1 writes it for a git project: compose.yml a link."""
    src = tmp_path / "src"
    (src / "repo").mkdir(parents=True, exist_ok=True)
    (src / "repo" / "compose.yml").write_text("services: {}\n")
    if not (src / "compose.yml").is_symlink():
        os.symlink(src / "repo" / "compose.yml", src / "compose.yml")
        (src / "project.env").write_text("A=1\n")
        os.link(src / "project.env", src / "linked.env")
    paths.stashes.mkdir(parents=True, exist_ok=True)
    archive = paths.stashes / name
    meta = json.dumps({"format_version": fmt}).encode()
    info = tarfile.TarInfo(META_FILENAME)
    info.size = len(meta)
    with tarfile.open(archive, "w:gz") as tar:
        if not meta_last:
            tar.addfile(info, io.BytesIO(meta))
        for member in ("compose.yml", "project.env", "linked.env"):
            tar.add(src / member, arcname=f"projects/g/{member}")
        if meta_last:
            tar.addfile(info, io.BytesIO(meta))
    return archive


def _members(archive):
    with tarfile.open(archive) as tar:
        return [(m.name, m.type,
                 b"" if m.issym() else (tar.extractfile(m) or io.BytesIO(b"")).read())
                for m in tar.getmembers()]


def _headers(archive):
    with tarfile.open(archive) as tar:
        return [(m.name, m.type, m.mode, m.uid, m.gid, m.uname, m.gname, m.mtime, m.linkname)
                for m in tar.getmembers()]


def test_symlinks_dropped_hardlinks_and_meta_kept(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path)
    before = _members(archive)
    headers = _headers(archive)
    with patch.object(stash_rewrite, "log_operation") as logged:
        result = sanitize_latest_stash(paths)
    assert result.changed and result.dropped == ["projects/g/compose.yml"] and not result.error
    after = _members(archive)
    assert after == [m for m in before if m[0] != "projects/g/compose.yml"]
    assert _headers(archive) == [h for h in headers if h[0] != "projects/g/compose.yml"]
    assert after[-1][0] == META_FILENAME
    assert dict((n, c) for n, _t, c in after)["projects/g/linked.env"] == b"A=1\n"
    assert [t for n, t, _c in after if n == "projects/g/linked.env"] == [tarfile.LNKTYPE]
    with tarfile.open(archive) as tar:
        for m in tar.getmembers():
            tarfile.data_filter(m, str(tmp_path / "restore"))   # 0.10.1's filter accepts all
    assert any("projects/g/compose.yml" in c.args[1] for c in logged.call_args_list)
    assert [p.name for p in paths.stashes.iterdir()] == [archive.name]


def test_the_rewrite_keeps_owner_and_is_private(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path)
    st = archive.stat()
    sanitize_latest_stash(paths)
    after = archive.stat()
    assert (after.st_uid, after.st_gid) == (st.st_uid, st.st_gid)
    assert stat.S_IMODE(after.st_mode) == 0o600 and after.st_ino != st.st_ino


def test_clean_stash_is_left_alone(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path)
    assert sanitize_latest_stash(paths).changed
    mtime = archive.stat().st_mtime_ns
    assert not sanitize_latest_stash(paths).changed and archive.stat().st_mtime_ns == mtime


def test_no_stash_is_nothing_to_do(paths) -> None:
    with patch.object(stash_rewrite, "notify") as alert:
        assert sanitize_latest_stash(paths) == stash_rewrite.SanitizeResult(False)
    alert.assert_not_called()


def test_only_the_latest_stash_is_rewritten(paths, tmp_path) -> None:
    older = _stash(paths, tmp_path, name="boxmunge-stash-2026-10-15T120000.tar.gz")
    before = older.read_bytes()
    _stash(paths, tmp_path)
    assert sanitize_latest_stash(paths).changed
    assert older.read_bytes() == before


def test_failed_verify_leaves_the_original_and_alerts(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path)
    before = archive.read_bytes()
    with patch.object(stash_rewrite, "_verify", side_effect=stash_rewrite.StashRewriteError("x")), \
            patch.object(stash_rewrite, "notify") as alert:
        result = sanitize_latest_stash(paths)
    assert not result.changed and result.error and archive.read_bytes() == before
    assert alert.call_args.kwargs["priority"] == 1
    assert "a rollback's stash restore may abort on git links" in alert.call_args.args[2]
    assert [p.name for p in paths.stashes.iterdir()] == [archive.name]


def test_failed_write_removes_the_partial_copy(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path)
    before = archive.read_bytes()
    with patch.object(stash_rewrite, "_copy_members", side_effect=OSError("disk full")), \
            patch.object(stash_rewrite, "notify") as alert:
        result = sanitize_latest_stash(paths)
    assert "disk full" in (result.error or "") and archive.read_bytes() == before
    assert alert.call_args.kwargs["priority"] == 1
    assert [p.name for p in paths.stashes.iterdir()] == [archive.name]


def test_an_unexpected_error_is_alerted_not_raised(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path)
    before = archive.read_bytes()
    with patch.object(stash_rewrite, "_copy_members", side_effect=KeyError("member")), \
            patch.object(stash_rewrite, "notify") as alert:
        result = sanitize_latest_stash(paths)
    assert result.error and not result.changed and archive.read_bytes() == before
    assert alert.called
    assert [p.name for p in paths.stashes.iterdir()] == [archive.name]


def test_verify_compares_member_for_member(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path)
    with tarfile.open(archive) as tar:
        want = [stash_rewrite._record(tar, m) for m in tar.getmembers() if not m.issym()]
    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(archive) as tar, tarfile.open(tampered, "w:gz") as out:
        for m in tar.getmembers():
            if m.issym():
                continue
            data = tar.extractfile(m).read() if m.isreg() else None
            if m.name == "projects/g/project.env":
                data = b"A=2\n"
            out.addfile(m, io.BytesIO(data) if data is not None else None)
    with pytest.raises(stash_rewrite.StashRewriteError, match="member for member"):
        stash_rewrite._verify(tampered, want)


def test_planted_temp_file_leaves_original_and_alerts(paths, tmp_path) -> None:
    """Review Focus 5: a name planted at the temp path after the sweep is
    refused (O_EXCL | O_NOFOLLOW), never written through."""
    archive = _stash(paths, tmp_path)
    before = archive.read_bytes()
    victim = tmp_path / "victim"
    victim.write_text("keep")
    planted = paths.stashes / f"{REWRITE_PREFIX}{os.getpid()}.tmp"
    os.symlink(victim, planted)
    with patch.object(stash_rewrite, "notify") as alert, \
            patch.object(stash_rewrite, "_sweep_stale"):
        result = sanitize_latest_stash(paths)
    assert result.error and not result.changed
    assert archive.read_bytes() == before and victim.read_text() == "keep"
    assert planted.is_symlink() and os.readlink(planted) == str(victim)
    assert alert.called and alert.call_args.kwargs["priority"] == 1


def test_a_symlinked_stash_is_refused(paths, tmp_path) -> None:
    real = _stash(paths, tmp_path, name="elsewhere.tar.gz")
    link = paths.stashes / "boxmunge-stash-2026-10-16T120000.tar.gz"
    os.symlink(real, link)
    before = real.read_bytes()
    with patch.object(stash_rewrite, "notify") as alert:
        result = sanitize_latest_stash(paths)
    assert result.error and link.is_symlink() and real.read_bytes() == before
    assert alert.called


def test_other_format_is_left_alone(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path, fmt=2)
    before = archive.read_bytes()
    with patch.object(stash_rewrite, "notify") as alert:
        assert sanitize_latest_stash(paths).error
    assert archive.read_bytes() == before and alert.call_args.kwargs["priority"] == 1


def test_meta_not_last_is_left_alone(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path, meta_last=False)
    before = archive.read_bytes()
    with patch.object(stash_rewrite, "notify") as alert:
        assert "last" in (sanitize_latest_stash(paths).error or "")
    assert archive.read_bytes() == before and alert.called


def test_temp_name_is_outside_the_stash_glob(paths, tmp_path) -> None:
    _stash(paths, tmp_path)
    (paths.stashes / f"{REWRITE_PREFIX}1.tmp").write_text("x")
    assert all(p.name.startswith("boxmunge-stash-") for p in list_stashes(paths))


def test_create_stash_writes_no_symlink_members(paths) -> None:
    pdir = paths.project_dir("g")
    (pdir / "repo").mkdir(parents=True)
    (pdir / "repo" / "manifest.yml").write_text("project: g\n")
    os.symlink(pdir / "repo" / "manifest.yml", pdir / "manifest.yml")
    with tarfile.open(create_stash(paths)) as tar:
        assert not any(m.issym() for m in tar.getmembers())


def test_the_rewritable_format_is_0_10_1s_not_the_create_format(paths, tmp_path) -> None:
    """A later create-format bump must not change which layout is rewritten."""
    archive = _stash(paths, tmp_path, fmt=1)
    with patch.object(stash_rewrite, "STASH_FORMAT_VERSION", 2, create=True):
        assert sanitize_latest_stash(paths).changed
    assert "projects/g/compose.yml" not in [n for n, _t, _c in _members(archive)]


def test_a_failed_directory_sync_reports_the_rewrite_truthfully(paths, tmp_path) -> None:
    archive = _stash(paths, tmp_path)
    with patch("boxmunge.fileutil.fsync_dir", side_effect=OSError("EIO")), \
            patch.object(stash_rewrite, "notify") as alert:
        result = sanitize_latest_stash(paths)
    assert result.changed and result.dropped == ["projects/g/compose.yml"]
    assert "EIO" in (result.error or "")
    assert "projects/g/compose.yml" not in [n for n, _t, _c in _members(archive)]
    body = alert.call_args.args[2]
    assert "was rewritten" in body and "left as it is" not in body
    assert alert.call_args.kwargs["priority"] == 1
    assert [p.name for p in paths.stashes.iterdir()] == [archive.name]


def test_stale_rewrite_temps_are_swept_first(paths, tmp_path) -> None:
    """A crash between the copy and the rename leaves a temp; a later run
    (same pid or not) removes it, never following a link."""
    archive = _stash(paths, tmp_path)
    victim = tmp_path / "victim"
    victim.write_text("keep")
    os.symlink(victim, paths.stashes / f"{REWRITE_PREFIX}{os.getpid()}.tmp")
    (paths.stashes / f"{REWRITE_PREFIX}1.tmp").write_bytes(b"stale copy")
    with patch.object(stash_rewrite, "log_warning") as warned, \
            patch.object(stash_rewrite, "notify") as alert:
        result = sanitize_latest_stash(paths)
    assert result.changed and not result.error and not alert.called
    assert victim.read_text() == "keep"
    assert [p.name for p in paths.stashes.iterdir()] == [archive.name]
    swept = " ".join(c.args[1] for c in warned.call_args_list)
    assert f"{REWRITE_PREFIX}1.tmp" in swept and f"{REWRITE_PREFIX}{os.getpid()}.tmp" in swept


def test_renames_go_through_fileutil() -> None:
    """Durable writes only through fileutil (plan Global Constraints)."""
    source = Path(stash_rewrite.__file__).read_text()
    assert "os.rename" not in source and ".rename(" not in source and "os.replace" not in source

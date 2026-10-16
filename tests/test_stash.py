"""Tests for platform stash — captures state for safe upgrades."""

import io
import json
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.stash import (
    STASH_FORMAT_VERSION,
    StashError,
    create_stash,
    list_stashes,
    prune_stashes,
    restore_stash,
)
from boxmunge.paths import BoxPaths
from boxmunge.version import write_installed_version


def _setup_project(paths: BoxPaths, name: str) -> None:
    """Create a minimal deployed project for stash testing."""
    project_dir = paths.project_dir(name)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": name,
        "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (project_dir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (project_dir / "secrets.env").write_text("SECRET=value\n")

    state_dir = paths.deploy_state
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / f"{name}.json").write_text(json.dumps({
        "current_ref": "abc123", "deployed_at": "2026-04-15T10:00:00Z",
    }))


class TestCreateStash:
    def test_creates_archive(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        archive = create_stash(paths)
        assert archive.exists()
        assert archive.name.startswith("boxmunge-stash-")
        assert archive.name.endswith(".tar.gz")

    def test_does_not_chmod_existing_dir(self, tmp_path: Path) -> None:
        """Regression: stash.create_stash must not chmod the dir.

        On real installs the stashes dir is owned by root with the deploy user
        in the group. A chmod from deploy context fails with EPERM and aborts
        the upgrade. We rely on install.sh to set perms once."""
        import os
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "logs"]:
            (paths.root / d).mkdir(parents=True)
        paths.stashes.mkdir(parents=True)
        os.chmod(paths.stashes, 0o770)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        before = paths.stashes.stat().st_mode & 0o777
        create_stash(paths)
        after = paths.stashes.stat().st_mode & 0o777
        assert before == after == 0o770

    def test_archive_contains_project_files(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        archive = create_stash(paths)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        assert any("myapp/manifest.yml" in n for n in names)
        assert any("myapp/compose.yml" in n for n in names)
        assert any("boxmunge.yml" in n for n in names)

    def test_archive_contains_version(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        archive = create_stash(paths)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        assert any("version" in n for n in names)


class TestListStashes:
    def test_lists_by_date_descending(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        (paths.stashes / "boxmunge-stash-2026-04-14T100000.tar.gz").write_text("")
        (paths.stashes / "boxmunge-stash-2026-04-15T100000.tar.gz").write_text("")
        stashes = list_stashes(paths)
        assert len(stashes) == 2
        assert "2026-04-15" in stashes[0].name

    def test_empty_when_none(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        assert list_stashes(paths) == []


class TestPruneStashes:
    def test_keeps_n_most_recent(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        for i in range(5):
            (paths.stashes / f"boxmunge-stash-2026-04-{10+i}T100000.tar.gz").write_text("")
        pruned = prune_stashes(paths, keep=3)
        assert len(pruned) == 2
        remaining = list_stashes(paths)
        assert len(remaining) == 3


class TestRestoreStash:
    def test_restore_recovers_config(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        archive = create_stash(paths)

        # Corrupt config to verify restore fixes it
        paths.config_file.write_text("hostname: corrupted\n")
        (paths.project_manifest("myapp")).write_text("corrupted: true\n")

        restore_stash(paths, archive)

        assert "hostname: test" in paths.config_file.read_text()
        assert "schema_version" in paths.project_manifest("myapp").read_text()

    def test_restore_latest(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        create_stash(paths)  # older
        import time; time.sleep(0.1)
        paths.config_file.write_text("hostname: latest\nadmin_email: t@t\n")
        create_stash(paths)  # newer

        paths.config_file.write_text("hostname: corrupted\n")
        restore_stash(paths)  # no archive arg = latest

        assert "hostname: latest" in paths.config_file.read_text()

    def test_restore_nonexistent_raises(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        with pytest.raises(FileNotFoundError):
            restore_stash(paths, tmp_path / "nope.tar.gz")

    def test_restore_no_stashes_raises(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        with pytest.raises(FileNotFoundError):
            restore_stash(paths)


def _make_paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
        (paths.root / d).mkdir(parents=True)
    return paths


def _build_malicious_archive(
    archive_path: Path,
    members: list[tuple[tarfile.TarInfo, bytes | None]],
    include_meta: bool = True,
) -> None:
    """Build a tarball with arbitrary members for traversal/symlink tests."""
    with tarfile.open(archive_path, "w:gz") as tar:
        if include_meta:
            payload = json.dumps({
                "format_version": STASH_FORMAT_VERSION,
                "platform_version": "test",
                "created_at": "2026-05-05T00:00:00+00:00",
            }).encode()
            info = tarfile.TarInfo(name="boxmunge-stash-meta.json")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        for info, data in members:
            if data is None:
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))


class TestStashTraversalGuards:
    def test_rejects_dotdot_segment(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "malicious.tar.gz"
        info = tarfile.TarInfo(name="config/../../etc/evil")
        _build_malicious_archive(archive, [(info, b"pwn")])
        with pytest.raises(StashError, match="suspicious"):
            restore_stash(paths, archive)

    def test_rejects_absolute_path(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "malicious.tar.gz"
        info = tarfile.TarInfo(name="/etc/evil")
        _build_malicious_archive(archive, [(info, b"pwn")])
        with pytest.raises(StashError, match="suspicious"):
            restore_stash(paths, archive)

    def test_allows_dotdot_substring_in_name(self, tmp_path: Path) -> None:
        """foo..bar (no path separator) should not trigger guard."""
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "ok.tar.gz"
        info = tarfile.TarInfo(name="config/foo..bar")
        _build_malicious_archive(archive, [(info, b"hello")])
        # Should restore without raising
        restore_stash(paths, archive)
        assert (paths.config / "foo..bar").read_bytes() == b"hello"

    def test_symlink_member_is_never_created(self, tmp_path: Path) -> None:
        """A link member is skipped, not extracted: nothing is created at its
        name and its target is never touched."""
        paths = _make_paths(tmp_path)
        victim = tmp_path / "victim"
        victim.write_text("untouched")
        archive = paths.stashes / "symlink.tar.gz"
        info = tarfile.TarInfo(name="config/evil")
        info.type = tarfile.SYMTYPE
        info.linkname = str(victim)
        _build_malicious_archive(archive, [(info, None)])
        restore_stash(paths, archive)
        assert not (paths.config / "evil").exists()
        assert not (paths.config / "evil").is_symlink()
        assert victim.read_text() == "untouched"

    def test_symlink_member_with_traversal_name_still_refused(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "symlink.tar.gz"
        info = tarfile.TarInfo(name="config/../../evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        _build_malicious_archive(archive, [(info, None)])
        with pytest.raises(StashError, match="suspicious"):
            restore_stash(paths, archive)


class TestGitProjectLinks:
    """A git project's manifest.yml and compose.yml are symlinks into repo/.
    They are never stashed, and restore leaves them alone: an older stash
    that holds them as link members must not abort a rollback."""

    def _git_project(self, paths: BoxPaths) -> Path:
        pdir = paths.project_dir("gitapp")
        repo = pdir / "repo"
        repo.mkdir(parents=True)
        for name in ("manifest.yml", "compose.yml"):
            (repo / name).write_text(f"# {name} from the repository\n")
            (pdir / name).symlink_to(repo / name)
        (pdir / "secrets.env").write_text("SECRET=stashed\n")
        (pdir / "project.env").write_text("MODE=stashed\n")
        return repo

    def test_stash_holds_no_link_members(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        self._git_project(paths)
        with tarfile.open(create_stash(paths)) as tar:
            members = {m.name: m for m in tar.getmembers()}
        assert not [m.name for m in members.values() if m.issym() or m.islnk()]
        assert "projects/gitapp/manifest.yml" not in members
        assert "projects/gitapp/secrets.env" in members
        assert "projects/gitapp/project.env" in members

    def test_round_trip_keeps_links_and_restores_files(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        repo = self._git_project(paths)
        archive = create_stash(paths)
        pdir = paths.project_dir("gitapp")
        (pdir / "secrets.env").write_text("SECRET=changed\n")
        (repo / "manifest.yml").write_text("# moved on in the repository\n")
        restore_stash(paths, archive)
        for name in ("manifest.yml", "compose.yml"):
            assert (pdir / name).is_symlink()
            assert (pdir / name).resolve() == (repo / name).resolve()
        assert (repo / "manifest.yml").read_text() == "# moved on in the repository\n"
        assert (pdir / "secrets.env").read_text() == "SECRET=stashed\n"

    def test_older_stash_with_link_members_restores(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        repo = self._git_project(paths)
        pdir = paths.project_dir("gitapp")
        link = tarfile.TarInfo(name="projects/gitapp/manifest.yml")
        link.type = tarfile.SYMTYPE
        link.linkname = str(repo / "manifest.yml")
        secrets = tarfile.TarInfo(name="projects/gitapp/secrets.env")
        secrets.mode = 0o600
        archive = paths.stashes / "boxmunge-stash-old.tar.gz"
        _build_malicious_archive(archive, [(link, None), (secrets, b"SECRET=old\n")])
        restore_stash(paths, archive)
        assert (pdir / "manifest.yml").is_symlink()
        assert (pdir / "manifest.yml").resolve() == (repo / "manifest.yml").resolve()
        assert (pdir / "secrets.env").read_text() == "SECRET=old\n"
        log = paths.log_file.read_text()
        assert "projects/gitapp/manifest.yml" in log and "symlink" in log


class TestStashAtomicWrites:
    def test_rename_failure_keeps_target_intact(self, tmp_path: Path) -> None:
        """When os.rename fails mid-restore, original target file untouched."""
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: original\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")
        archive = create_stash(paths)

        # Mutate target so restore would change it
        paths.config_file.write_text("hostname: corrupt\n")

        with patch("boxmunge.fileutil.os.rename", side_effect=OSError("simulated SIGKILL")):
            with pytest.raises(OSError):
                restore_stash(paths, archive)

        # Target intact (still corrupt content, not partial bytes)
        assert paths.config_file.read_text() == "hostname: corrupt\n"
        # No leftover temp files
        temps = list(paths.config.glob(".*tmp"))
        assert temps == []


class TestStashSchemaVersion:
    def test_create_writes_meta_file(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: t\nadmin_email: t@t\n")
        write_installed_version(paths, "0.5.3", "deadbee")
        _setup_project(paths, "myapp")
        archive = create_stash(paths)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
            assert "boxmunge-stash-meta.json" in names
            extracted = tar.extractfile("boxmunge-stash-meta.json")
            assert extracted is not None
            meta = json.loads(extracted.read())
        assert meta["format_version"] == STASH_FORMAT_VERSION
        assert meta["platform_version"] == "0.5.3+deadbee"
        assert "created_at" in meta

    def test_restore_with_current_version(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: t\nadmin_email: t@t\n")
        write_installed_version(paths, "0.5.3", "deadbee")
        _setup_project(paths, "myapp")
        archive = create_stash(paths)
        # Should restore without raising
        restore_stash(paths, archive)

    def test_restore_with_newer_version_raises(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "future.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            payload = json.dumps({
                "format_version": STASH_FORMAT_VERSION + 1,
                "platform_version": "9.9.9",
                "created_at": "2099-01-01T00:00:00+00:00",
            }).encode()
            info = tarfile.TarInfo(name="boxmunge-stash-meta.json")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        with pytest.raises(StashError, match="newer than this installation"):
            restore_stash(paths, archive)

    def test_restore_legacy_no_meta_warns(self, tmp_path: Path) -> None:
        """Legacy stashes (created before meta file existed) restore w/ warning."""
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "legacy.tar.gz"
        # Build a legacy-format stash (no meta file) using direct tarfile
        with tarfile.open(archive, "w:gz") as tar:
            payload = b"hostname: legacy\nadmin_email: t@t\n"
            info = tarfile.TarInfo(name="config/boxmunge.yml")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        with patch("boxmunge.stash.log_warning") as mock_warn:
            restore_stash(paths, archive)
        assert mock_warn.called
        # Verify the warning mentions absent format marker
        call_args = mock_warn.call_args
        assert "format_version" in call_args.args[1] or "format_version" in str(call_args)
        # And the file actually got restored
        assert paths.config_file.read_text() == "hostname: legacy\nadmin_email: t@t\n"


class TestStashLogging:
    def test_create_emits_log_operation(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: t\nadmin_email: t@t\n")
        write_installed_version(paths, "0.5.3", "deadbee")
        _setup_project(paths, "myapp")
        with patch("boxmunge.stash.log_operation") as mock_log:
            create_stash(paths)
        assert mock_log.called
        # First positional arg is component
        assert mock_log.call_args.args[0] == "stash"
        # Detail should include format_version
        kwargs = mock_log.call_args.kwargs
        assert kwargs.get("detail", {}).get("format_version") == STASH_FORMAT_VERSION

    def test_restore_emits_log_operation(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: t\nadmin_email: t@t\n")
        write_installed_version(paths, "0.5.3", "deadbee")
        _setup_project(paths, "myapp")
        archive = create_stash(paths)
        with patch("boxmunge.stash.log_operation") as mock_log:
            restore_stash(paths, archive)
        assert mock_log.called
        # Verify "restored" message
        msgs = [c.args[1] for c in mock_log.call_args_list]
        assert any("restored" in m.lower() for m in msgs)


class TestRestoreSecretsLocking:
    """Restoring a secrets file takes the same lock as `secrets set`, so a
    concurrent set cannot write the pre-restore contents back over it."""

    @pytest.mark.parametrize("scope", ["host", "project"])
    def test_restore_waits_for_the_secrets_lock(self, tmp_path: Path, scope: str) -> None:
        import threading
        from boxmunge.secrets import SecretsFile

        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")
        paths.host_secrets.write_text("HOST='v'\n")
        secrets = (SecretsFile.host(paths) if scope == "host"
                   else SecretsFile.project(paths, "myapp"))
        original = secrets.path.read_text()
        archive = create_stash(paths)
        secrets.path.write_text("CHANGED='x'\n")

        with secrets.locked():
            restorer = threading.Thread(target=restore_stash, args=(paths, archive))
            restorer.start()
            restorer.join(timeout=0.5)
            assert restorer.is_alive()
            assert secrets.path.read_text() == "CHANGED='x'\n"
        restorer.join(timeout=10)
        assert not restorer.is_alive()
        assert secrets.path.read_text() == original


class TestOtherSymlinksRefused:
    """Only a git project's links into repo/ are left out; any other symlink
    in the stash set stops the stash before anything is written."""

    @pytest.mark.parametrize("where", [
        "projects/app/secrets.env", "projects/app/manifest.yml",
        "projects/app/boxmunge-scripts", "projects/app/boxmunge-scripts/smoke.sh",
        "state/deploy/app.json", "config/boxmunge.yml",
    ])
    def test_refused_with_the_path(self, tmp_path: Path, where: str) -> None:
        paths = _make_paths(tmp_path)
        _setup_project(paths, "app")
        (paths.project_dir("app") / "boxmunge-scripts").mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "f").write_text("x\n")
        link = paths.root / where
        if link.is_dir():
            link.rename(tmp_path / "moved")
        else:
            link.unlink(missing_ok=True)
        link.symlink_to(elsewhere if where.endswith("scripts") else elsewhere / "f")
        with pytest.raises(StashError, match="symlinks") as exc:
            create_stash(paths)
        assert str(link) in str(exc.value)
        assert "Nothing has been changed" in str(exc.value)
        assert list(paths.stashes.iterdir()) == []

    def test_git_named_link_outside_repo_is_refused(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        pdir = paths.project_dir("gitapp")
        (pdir / "repo").mkdir(parents=True)
        (tmp_path / "other.yml").write_text("x: 1\n")
        (pdir / "compose.yml").symlink_to(tmp_path / "other.yml")
        with pytest.raises(StashError, match="compose.yml"):
            create_stash(paths)

    def test_restore_leaves_a_relinked_git_file(self, tmp_path: Path) -> None:
        """A stash taken while the link was a frozen file does not undo a re-link."""
        paths = _make_paths(tmp_path)
        pdir = paths.project_dir("gitapp")
        repo = pdir / "repo"
        repo.mkdir(parents=True)
        (repo / "manifest.yml").write_text("# repository\n")
        frozen = tarfile.TarInfo(name="projects/gitapp/manifest.yml")
        frozen.mode = 0o644
        archive = paths.stashes / "boxmunge-stash-frozen.tar.gz"
        _build_malicious_archive(archive, [(frozen, b"# frozen copy\n")])
        (pdir / "manifest.yml").symlink_to("repo/manifest.yml")
        restore_stash(paths, archive)
        assert (pdir / "manifest.yml").is_symlink()
        assert (repo / "manifest.yml").read_text() == "# repository\n"
        assert "links into the project's repo/" in paths.log_file.read_text()

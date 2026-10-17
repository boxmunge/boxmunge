# SPDX-License-Identifier: Apache-2.0
"""The helper container's argv and its operations (no Docker)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge import data_helper
from boxmunge.data_helper import HELPER_IMAGE, HelperError, helper_argv
from boxmunge.docker_run import DockerError


class _Docker:
    def __init__(self, monkeypatch, *, rc: int = 0, fail: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.rc, self.fail = rc, fail
        monkeypatch.setattr(data_helper, "_run", self)

    def __call__(self, cmd, capture=False, check=True, timeout=None):
        self.calls.append(cmd)
        if cmd[:2] == ["docker", "run"] and self.fail:
            raise DockerError(self.fail)

        class Done:
            returncode = self.rc if cmd[:2] == ["docker", "run"] else 0
            stdout = ""
        return Done()


def test_argv_is_the_hardened_helper() -> None:
    argv = helper_argv("boxmunge-helper-x", ["-v", "/a:/x"], "true")
    joined = " ".join(argv)
    for part in ("--user 0:0", "--network none", "--read-only", "--cap-drop ALL",
                 "--cap-add CHOWN", "--cap-add DAC_OVERRIDE", "--cap-add FOWNER",
                 "--cap-add FSETID", "--pull never", "--entrypoint sh",
                 "--security-opt no-new-privileges"):
        assert part in joined
    assert joined.count("--cap-add") == 4
    assert "--userns" not in joined and "--privileged" not in joined
    assert argv[-3:] == [HELPER_IMAGE, "-c", "true"]
    assert HELPER_IMAGE == "boxmunge.invalid/system/system"


def test_every_run_is_named_and_force_removed(monkeypatch) -> None:
    docker = _Docker(monkeypatch, fail="cp: write error")
    with pytest.raises(DockerError):
        data_helper.run_helper("myapp-copy", [], "true")
    run, rm = docker.calls
    name = run[run.index("--name") + 1]
    assert name.startswith("boxmunge-myapp-copy-") and rm == ["docker", "rm", "-f", name]


def test_missing_image_says_how_to_build_it(monkeypatch) -> None:
    _Docker(monkeypatch, fail="docker: Error response from daemon: No such image: "
                              "boxmunge.invalid/system/system")
    with pytest.raises(HelperError, match="docker compose -f /opt/boxmunge/system/compose.yml build"):
        data_helper.run_helper("x", [], "true")


def test_empty_dir_removes_hidden_entries_and_proves_it(monkeypatch, tmp_path) -> None:
    docker = _Docker(monkeypatch)
    data_helper.empty_dir("x", tmp_path)
    run = docker.calls[0]
    assert run[run.index("-v") + 1] == f"{tmp_path}:/x"
    assert "/x/.[!.]*" in run[-1] and "ls -A /x" in run[-1]


def test_copy_into_volume_reads_the_source_read_only(monkeypatch) -> None:
    docker = _Docker(monkeypatch)
    data_helper.copy_into_volume("x", "anon", "myapp_pgdata")
    run = " ".join(docker.calls[0])
    assert "type=volume,src=anon,dst=/src,readonly" in run
    assert "type=volume,src=myapp_pgdata,dst=/dst " in run
    assert "/dst/.[!.]*" in run and run.endswith("cp -a /src/. /dst/")


@pytest.mark.parametrize("rc, empty", [(0, True), (3, False)])
def test_volume_is_empty(monkeypatch, rc, empty) -> None:
    _Docker(monkeypatch, rc=rc)
    assert data_helper.volume_is_empty("x", "myapp_data") is empty


def test_volume_is_empty_refuses_to_guess_on_other_failures(monkeypatch) -> None:
    _Docker(monkeypatch, rc=125)
    with pytest.raises(HelperError, match="exit 125"):
        data_helper.volume_is_empty("x", "myapp_data")


def test_empty_under_mounts_the_root_and_resolves_inside_the_helper(monkeypatch,
                                                                    tmp_path) -> None:
    """The daemon follows links in a -v host path as root; the project
    directory itself is one no container can write, so it is the mount, and
    the walk below it happens inside the helper's own namespace."""
    docker = _Docker(monkeypatch)
    data_helper.empty_under("x", tmp_path, Path("data/my pg"))
    run = docker.calls[0]
    assert run[run.index("-v") + 1] == f"{tmp_path}:/p"
    script = run[-1]
    assert script.startswith("t='/p/data/my pg' && ")
    assert '[ "$(readlink -f "$t")" = "$t" ]' in script
    assert '"$t"/.[!.]*' in script and 'ls -A "$t"' in script


@pytest.mark.parametrize("rel", ["", ".", "../other", "/etc", "data/../../x"])
def test_empty_under_refuses_paths_outside_the_root(monkeypatch, tmp_path, rel) -> None:
    docker = _Docker(monkeypatch)
    with pytest.raises(ValueError):
        data_helper.empty_under("x", tmp_path, Path(rel))
    assert docker.calls == []


def test_container_owned_dirs_finds_the_topmost_foreign_dirs(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "c").mkdir()
    (tmp_path / "mine" / "d").mkdir(parents=True)
    os.symlink("/", tmp_path / "link")
    me = os.geteuid()
    real_lstat = os.lstat

    def lstat(path):
        st = real_lstat(path)
        if Path(path).name in ("a", "c", "d"):
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, me + 1,
                                   st.st_gid, st.st_size, 0, 0, 0))
        return st
    monkeypatch.setattr(data_helper.os, "lstat", lstat)
    assert data_helper.container_owned_dirs(tmp_path) == [
        tmp_path / "a", tmp_path / "c", tmp_path / "mine" / "d"]


def test_root_needs_no_helper_to_delete(tmp_path: Path, monkeypatch) -> None:
    """Root removes anything itself; on a remapped box the helper could not
    even empty a directory holding deploy's files."""
    (tmp_path / "a").mkdir()
    monkeypatch.setattr(data_helper.os, "geteuid", lambda: 0)
    assert data_helper.container_owned_dirs(tmp_path) == []


def test_a_foreign_unreadable_dir_is_selected_without_being_listed(tmp_path: Path,
                                                                   monkeypatch) -> None:
    """pgdata (999, 0700) directly in the project directory is selected as
    it is: deploy cannot list it, so the walk must not try."""
    (tmp_path / "pgdata" / "base").mkdir(parents=True)
    (tmp_path / "code").mkdir()
    me = os.geteuid()
    real_lstat = os.lstat

    def lstat(path):
        st = real_lstat(path)
        if Path(path).name == "pgdata":
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 999,
                                   999, st.st_size, 0, 0, 0))
        return st
    monkeypatch.setattr(data_helper.os, "lstat", lstat)
    (tmp_path / "pgdata").chmod(0)
    try:
        assert data_helper.container_owned_dirs(tmp_path) == [tmp_path / "pgdata"]
    finally:
        (tmp_path / "pgdata").chmod(0o755)
    assert me != 999

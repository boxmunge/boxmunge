"""The control-file hash reader refuses a link to a special file promptly
(it must never block on a FIFO) and refuses an oversized control file."""
from __future__ import annotations

import os
import signal

import pytest

from boxmunge import bind_sources
from boxmunge.compose_guard import ComposeRefused, check_kept_files
from tests import test_compose_guard as guard
from tests.test_compose_guard import _deploy

box = guard.box


@pytest.fixture(autouse=True)
def _no_hang():
    """A regression blocks in open(); turn that into a failure."""
    def boom(*_):
        # BaseException: the reader's own `except OSError` must not swallow it.
        raise KeyboardInterrupt("control hash reader blocked")
    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(5)
    yield
    signal.alarm(0)
    signal.signal(signal.SIGALRM, old)


def _link_env_to(project_dir, target) -> None:
    (project_dir / ".env").unlink(missing_ok=True)
    os.symlink(target, project_dir / ".env")


def test_a_link_to_a_fifo_is_refused_not_blocked_on(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    os.mkfifo(project_dir / "pipe")
    _link_env_to(project_dir, project_dir / "pipe")
    with pytest.raises(ComposeRefused, match="not a plain regular file"):
        check_kept_files(paths, guard.NAME, component="upgrade")


def test_a_link_to_a_device_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    _link_env_to(project_dir, "/dev/null")
    with pytest.raises(ComposeRefused, match="outside the project"):
        check_kept_files(paths, guard.NAME, component="upgrade")


def test_a_link_to_an_in_project_file_still_hashes(box) -> None:
    paths, project_dir, *_ = box
    (project_dir / "real.env").write_text("A=1\n")
    _link_env_to(project_dir, project_dir / "real.env")
    _deploy(paths)
    check_kept_files(paths, guard.NAME, component="upgrade")


def test_an_oversized_control_file_is_refused(box, monkeypatch) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    monkeypatch.setattr(bind_sources, "MAX_CONTROL_FILE_BYTES", 8)
    (project_dir / ".env").write_text("A" * 9)
    with pytest.raises(ComposeRefused, match="larger than"):
        check_kept_files(paths, guard.NAME, component="upgrade")

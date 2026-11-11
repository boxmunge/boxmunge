# SPDX-License-Identifier: Apache-2.0
"""F11: state/projects.txt is deploy-writable and root's timers read it, so
it is read like every other state record: no link followed, no FIFO waited
on, no more than REGISTRY_LIMIT_BYTES taken in. Anything at the name that is
not a readable registry is refused by every reader, never taken for "no
registry yet" (which rebuilds it from the project directories)."""
from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from boxmunge import project_registry
from boxmunge.health_checks.registry import check_registry_drift
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import (
    ProjectRegistryError, add_project, is_registered, load_registered_projects, read_registry,
    remove_project,
)

READERS: list[Callable[[BoxPaths], Any]] = [
    read_registry,
    load_registered_projects,
    lambda p: is_registered("myapp", p),
    lambda p: add_project("newapp", p),
    lambda p: remove_project("myapp", p),
    check_registry_drift,                      # the health timer, as root
]


def _registry(paths: BoxPaths) -> Path:
    paths.state.mkdir(parents=True, exist_ok=True)
    return paths.state / "projects.txt"


def _deployed(paths: BoxPaths, name: str) -> None:
    paths.project_dir(name).mkdir(parents=True)
    (paths.project_dir(name) / "manifest.yml").write_text(f"project: {name}\n")


def _within(fn: Callable[[], Any], fifo: Path, seconds: float = 5.0) -> Any:
    """fn's exception (or None); a call still blocked after `seconds` is
    released by opening the FIFO for writing, and fails the test."""
    out: list[BaseException | None] = []

    def run() -> None:
        try:
            fn()
            out.append(None)
        except Exception as e:  # noqa: BLE001 - handed back to the test
            out.append(e)
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        os.close(os.open(fifo, os.O_RDWR | os.O_NONBLOCK))
        worker.join(seconds)
        pytest.fail(f"the registry read blocked on the FIFO at {fifo}")
    return out[0]


def _every_reader_refuses(paths: BoxPaths, match: str) -> None:
    for read in READERS:
        with pytest.raises(ProjectRegistryError, match=match) as refusal:
            read(paths)
        # The refusal names the file and what to do about it.
        assert str(_registry(paths)) in str(refusal.value)
        assert f"sudo rm {_registry(paths)}" in str(refusal.value)


def test_a_link_to_a_file_outside_state_is_not_the_registry(paths) -> None:
    """The audit's probe: the names in a file outside state/ were accepted."""
    foreign = paths.root / "foreign-file"
    foreign.write_text("outside-registry\n")
    registry = _registry(paths)
    registry.symlink_to(foreign)
    _every_reader_refuses(paths, "symlink")
    assert registry.is_symlink()                          # add/remove wrote nothing
    assert foreign.read_text() == "outside-registry\n"


def test_removing_the_link_rebuilds_the_registry_from_the_deployed_projects(paths) -> None:
    """What the refusal tells the operator to do works, and nothing the
    link pointed at is registered afterwards."""
    _deployed(paths, "myapp")
    foreign = paths.root / "foreign-file"
    foreign.write_text("outside-registry\n")
    registry = _registry(paths)
    registry.symlink_to(foreign)
    with pytest.raises(ProjectRegistryError):
        read_registry(paths)
    registry.unlink()
    assert read_registry(paths).names == frozenset({"myapp"})
    assert not registry.is_symlink() and registry.read_text() == "myapp\n"
    add_project("newapp", paths)
    assert load_registered_projects(paths) == {"myapp", "newapp"}


def test_a_dangling_link_is_not_no_registry_yet(paths, tmp_path) -> None:
    """Path.exists() follows the link, so a dangling one read as absent and
    the registry was rebuilt over it."""
    _deployed(paths, "myapp")
    registry = _registry(paths)
    registry.symlink_to(tmp_path / "gone")
    _every_reader_refuses(paths, "symlink")
    assert registry.is_symlink() and not (tmp_path / "gone").exists()


def test_a_fifo_is_refused_without_waiting_for_a_writer(paths) -> None:
    registry = _registry(paths)
    os.mkfifo(registry)
    for read in READERS:
        refusal = _within(lambda: read(paths), registry)
        assert isinstance(refusal, ProjectRegistryError), refusal
        assert "not a plain regular file" in str(refusal)


def test_a_registry_past_the_cap_is_refused_and_left_alone(paths, monkeypatch) -> None:
    monkeypatch.setattr(project_registry, "REGISTRY_LIMIT_BYTES", 64)
    registry = _registry(paths)
    text = "".join(f"project-{i}\n" for i in range(10))
    registry.write_text(text)
    _every_reader_refuses(paths, "larger than 64 bytes")
    assert registry.read_text() == text


def test_bytes_that_are_not_text_are_refused(paths) -> None:
    _registry(paths).write_bytes(b"myapp\n\xff\xfe\n")
    _every_reader_refuses(paths, "utf-8")


def test_the_cap_holds_thousands_of_projects(paths) -> None:
    """A name is at most 63 bytes: the cap must not refuse a real fleet."""
    names = {f"{'p' * 55}-{i:04d}" for i in range(5000)}
    _registry(paths).write_text("".join(f"{n}\n" for n in sorted(names)))
    assert read_registry(paths).names == names
    assert project_registry.REGISTRY_LIMIT_BYTES <= 4 * 1024 ** 2

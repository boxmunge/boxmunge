"""Kill a forked migration before its Nth change to the box.

A change is any call that alters the filesystem (rename, chown, chmod,
unlink, rmdir, mkdir, a file created, a tree removed) or runs a process
that does (docker other than its read-only verbs, the daemon's stop and
start, useradd and usermod). `count` runs a function in this process and
returns the changes it made, labelled; `crash_before` runs it in a forked
child that dies with os._exit (no cleanup, as a power cut) just before the
Nth change.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from contextlib import contextmanager
from typing import Callable, Iterator

_OS_CALLS = ("rename", "replace", "fchown", "chown", "lchown", "fchmod", "chmod", "unlink",
             "remove", "rmdir", "mkdir")
_DOCKER_CHANGES = {"up", "down", "stop", "start", "restart", "kill", "rm", "create", "load",
                   "pull", "run", "tag"}
_READERS = {"id", "pgrep", "stat", "cat"}
# An atomic write's temp file is invisible until its rename: a kill before
# its create, its chmod or its rename leaves the same box, so only the
# rename is counted.
_INSIDE_ATOMIC_WRITE = {"_mkstemp_inner", "atomic_write_bytes"}


def _label(kind: str) -> str:
    return f"{kind}@{sys._getframe(2).f_code.co_name}"


def _changes_box(argv) -> str | None:
    """The change label of a process, or None for one that only reads."""
    args = [str(a) for a in (argv if isinstance(argv, (list, tuple)) else [argv])]
    name = os.path.basename(args[0]) if args else ""
    if name == "docker":
        verbs = [a for a in args[1:] if a in _DOCKER_CHANGES]
        if verbs:
            return f"docker {verbs[0]}"
        return "docker save -o" if args[1:3] == ["save", "-o"] else None
    if name in _READERS or (name == "systemctl" and "is-active" in args):
        return None
    return name


@contextmanager
def _patched(record: Callable[[str], None]) -> Iterator[None]:
    def hit(label: str) -> None:
        if label.split("@")[1] not in _INSIDE_ATOMIC_WRITE:
            record(label)

    saved = {name: getattr(os, name) for name in _OS_CALLS}
    real_open, real_rmtree = os.open, shutil.rmtree
    real_run, real_popen = subprocess.run, subprocess.Popen

    def wrap(name):
        def call(*args, **kwargs):
            hit(_label(name))
            return saved[name](*args, **kwargs)
        return call

    def opened(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            hit(_label("create"))
        return real_open(path, flags, *args, **kwargs)

    def rmtree(*args, **kwargs):
        hit(_label("rmtree"))
        return real_rmtree(*args, **kwargs)

    def run(argv, *args, **kwargs):
        what = _changes_box(argv)
        if what:
            hit(_label(what))
        return real_run(argv, *args, **kwargs)

    class Popen(real_popen):  # type: ignore[misc, valid-type]
        def __init__(self, argv, *args, **kwargs):
            what = _changes_box(argv)
            if what:
                hit(_label(what))
            super().__init__(argv, *args, **kwargs)

    for name in _OS_CALLS:
        setattr(os, name, wrap(name))
    os.open, shutil.rmtree = opened, rmtree
    subprocess.run, subprocess.Popen = run, Popen
    try:
        yield
    finally:
        for name, fn in saved.items():
            setattr(os, name, fn)
        os.open, shutil.rmtree = real_open, real_rmtree
        subprocess.run, subprocess.Popen = real_run, real_popen


def count(fn: Callable[[], object]) -> list[str]:
    """Run fn here; return the label of every change it made, in order."""
    seen: list[str] = []
    with _patched(seen.append):
        fn()
    return seen


def crash_before(n: int, fn: Callable[[], object]) -> int:
    """Run fn in a forked child killed just before its nth change (1-based).
    Returns the child's exit code: 137 when killed, 0 when fn finished
    first, 1 when it raised."""
    pid = os.fork()
    if pid == 0:
        done = [0]

        def hit(_label: str) -> None:
            done[0] += 1
            if done[0] == n:
                os._exit(137)
        code = 0
        try:
            with _patched(hit):
                fn()
        except BaseException:  # noqa: BLE001 - the parent reads the exit code
            code = 1
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def crash_points(labels: list[str]) -> list[int]:
    """1-based change numbers worth a kill: the first and last of every run
    of one label (the first change of a step, the last before the next)."""
    points = set()
    for i, label in enumerate(labels):
        if i == 0 or labels[i - 1] != label:
            points.add(i + 1)
        if i == len(labels) - 1 or labels[i + 1] != label:
            points.add(i + 1)
    return sorted(points)

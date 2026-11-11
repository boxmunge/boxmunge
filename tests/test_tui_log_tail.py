# SPDX-License-Identifier: Apache-2.0
"""The console's log tab follows `docker compose logs --follow`, which never
ends by itself: switching tab, changing the filter, leaving the screen and
quitting the console each stop the follower (deep review S-11)."""
from __future__ import annotations

import asyncio
import sys

import pytest
import yaml

# The integration shards install no TUI extra; the console is not under test there.
pytest.importorskip("textual")

from boxmunge.tui import dashboard, project_detail  # noqa: E402
from boxmunge.tui.app import BoxmungeApp  # noqa: E402
from boxmunge.tui.data import HostInfo  # noqa: E402
from boxmunge.tui.project_detail import ProjectDetailScreen  # noqa: E402

# The overview asks Docker for health; here Docker answers nothing.
pytestmark = pytest.mark.usefixtures("docker_down")
SLEEPER = [sys.executable, "-c", "import time; time.sleep(120)"]


@pytest.fixture
def followers(paths, monkeypatch) -> list:
    """Every log follower started; each is a real process that never exits."""
    paths.project_dir("myapp").mkdir(parents=True)
    paths.project_manifest("myapp").write_text(yaml.dump({
        "project": "myapp", "hosts": ["myapp.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}}}))
    started: list = []
    real = asyncio.create_subprocess_exec

    async def spawn(*cmd, **kw):
        assert list(cmd[-3:]) == ["logs", "--tail=50", "--follow"] or "--follow" in cmd
        process = await real(*SLEEPER, stdout=kw["stdout"], stderr=kw["stderr"])
        started.append(process)
        return process

    monkeypatch.setattr(project_detail.asyncio, "create_subprocess_exec", spawn)
    return started


async def _settle(pilot, until) -> None:
    for _ in range(100):
        await pilot.pause(0.05)
        if until():
            return
    raise AssertionError("timed out waiting for the console")


def _drive(paths, steps) -> None:
    async def main() -> None:
        app = BoxmungeApp(paths)
        async with app.run_test() as pilot:
            app.push_screen_by_name("myapp")
            await _settle(pilot, lambda: isinstance(app.screen, ProjectDetailScreen))
            await steps(app, pilot)
    asyncio.run(main())


def _alive(followers) -> list:
    return [p for p in followers if p.returncode is None]


def test_leaving_the_screen_stops_the_follower(paths, followers) -> None:
    async def steps(app, pilot):
        await pilot.press("2")
        await _settle(pilot, lambda: len(followers) == 1)
        await pilot.press("escape")
        await _settle(pilot, lambda: not _alive(followers))
    _drive(paths, steps)


def test_a_tab_switch_and_each_filter_change_leave_one_follower_at_most(paths, followers) -> None:
    async def steps(app, pilot):
        await pilot.press("2")
        await _settle(pilot, lambda: len(followers) == 1)
        await pilot.press("f")
        await _settle(pilot, lambda: len(followers) == 2 and len(_alive(followers)) == 1)
        await pilot.press("f")
        await _settle(pilot, lambda: len(followers) == 3 and len(_alive(followers)) == 1)
        await pilot.press("1")
        await _settle(pilot, lambda: not _alive(followers))
    _drive(paths, steps)


def test_quitting_the_console_stops_the_follower(paths, followers) -> None:
    async def steps(app, pilot):
        await pilot.press("2")
        await _settle(pilot, lambda: len(followers) == 1)
        app.exit()
    _drive(paths, steps)
    (process,) = followers
    assert process.returncode is not None or _reaped_after_signal(process.pid)


def _reaped_after_signal(pid: int) -> bool:
    """The follower got its signal; the event loop closed before it was reaped."""
    import os
    import time
    for _ in range(50):
        try:
            done, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True     # already reaped
        if done:
            return True
        time.sleep(0.05)
    return False


def test_switching_away_from_logs_stops_the_follower(paths, monkeypatch) -> None:
    monkeypatch.setattr(dashboard, "load_host_info",
                        lambda paths: HostInfo("box", 1.0, False))
    script = "import time; print('line', flush=True); time.sleep(30)"
    monkeypatch.setattr(project_detail, "compose_command",
                        lambda *a, **k: [sys.executable, "-c", script])
    started: list = []
    real_exec = asyncio.create_subprocess_exec

    async def _exec(*args, **kwargs):
        started.append(await real_exec(*args, **kwargs))
        return started[-1]

    monkeypatch.setattr(project_detail.asyncio, "create_subprocess_exec", _exec)

    paths.project_dir("myapp").mkdir(parents=True)

    async def _go() -> None:
        app = BoxmungeApp(paths)
        async with app.run_test() as pilot:
            screen = ProjectDetailScreen("myapp", paths)
            app.push_screen(screen)
            await pilot.pause()
            task = asyncio.create_task(screen._tail_logs())
            for _ in range(100):
                if started or task.done():
                    break
                await asyncio.sleep(0.05)
            assert started, task.exception() if task.done() else "never started"
            await asyncio.sleep(0.2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(_go())
    assert started and started[0].returncode is not None

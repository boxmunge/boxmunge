# SPDX-License-Identifier: Apache-2.0
"""The TUI's log tail stops its `docker compose logs --follow` when the
tail is cancelled (a tab switch or a filter cycle), instead of leaving one
more follower running each time until the TUI exits."""
from __future__ import annotations

import asyncio
import sys

import pytest

pytest.importorskip("textual")

from boxmunge.tui import dashboard  # noqa: E402
from boxmunge.tui.app import BoxmungeApp  # noqa: E402
from boxmunge.tui.data import HostInfo  # noqa: E402
from boxmunge.tui.project_detail import ProjectDetailScreen  # noqa: E402


def test_switching_away_from_logs_stops_the_follower(paths, monkeypatch) -> None:
    from boxmunge.tui import project_detail

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

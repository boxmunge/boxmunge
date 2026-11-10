# SPDX-License-Identifier: Apache-2.0
"""Every TUI action that changes a project asks first.

A single mistyped key on the detail screen used to roll production back
(and restore its paired data snapshot) with no question asked, while the
CLI prompts and MCP demands confirm: true. Each mutating action now opens a
confirmation modal, and runs only on an explicit yes.
"""
from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from boxmunge.tui import actions as tui_actions  # noqa: E402
from boxmunge.tui import dashboard  # noqa: E402
from boxmunge.tui.app import BoxmungeApp  # noqa: E402
from boxmunge.tui.confirm import ConfirmScreen  # noqa: E402
from boxmunge.tui.data import HostInfo  # noqa: E402
from boxmunge.tui.project_detail import ProjectDetailScreen  # noqa: E402

MUTATING = ("deploy", "redeploy", "backup", "rollback")


@pytest.fixture
def ran(monkeypatch) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []

    def _run(action, project, paths):
        calls.append((action, project))
        return tui_actions.Outcome(True, f"{action} completed for {project}")

    monkeypatch.setattr(tui_actions, "run_action", _run)
    monkeypatch.setattr(dashboard, "load_host_info",
                        lambda paths: HostInfo("box", 1.0, False))
    return calls


def _drive(paths, action: str, key: str) -> tuple[bool, list]:
    """Ask for `action`, answer the modal with `key`; return whether the
    modal was shown and the screens left on the stack."""

    async def _go() -> tuple[bool, list]:
        app = BoxmungeApp(paths)
        async with app.run_test() as pilot:
            app.run_action_with_confirm(action, "myapp")
            await pilot.pause()
            shown = isinstance(app.screen, ConfirmScreen)
            await pilot.press(key)
            await pilot.pause()
            await app.workers.wait_for_complete()
            return shown, list(app.screen_stack)

    return asyncio.run(_go())


@pytest.mark.parametrize("action", MUTATING)
def test_a_mutating_action_waits_for_confirmation_and_no_runs_nothing(
        paths, ran, action) -> None:
    shown, stack = _drive(paths, action, "n")
    assert shown
    assert ran == []
    assert not any(isinstance(s, ConfirmScreen) for s in stack)


@pytest.mark.parametrize("action", MUTATING)
def test_a_mutating_action_runs_on_yes(paths, ran, action) -> None:
    shown, _ = _drive(paths, action, "y")
    assert shown
    assert ran == [(action, "myapp")]


def test_escape_cancels(paths, ran) -> None:
    shown, _ = _drive(paths, "rollback", "escape")
    assert shown and ran == []


def test_enter_on_the_default_button_cancels(paths, ran) -> None:
    """The focused button is the safe one: a stray Enter does not proceed."""
    shown, _ = _drive(paths, "rollback", "enter")
    assert shown and ran == []


def test_the_rollback_key_on_the_detail_screen_asks_first(paths, ran) -> None:
    async def _go() -> str:
        app = BoxmungeApp(paths)
        async with app.run_test() as pilot:
            app.push_screen(ProjectDetailScreen("myapp", paths))
            await pilot.pause()
            await pilot.press("r")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmScreen)
            return app.screen.prompt

    prompt = asyncio.run(_go())
    assert ran == []
    assert "Roll back myapp" in prompt and "snapshot" in prompt


def test_every_tui_action_has_a_prompt() -> None:
    assert set(tui_actions.PROMPTS) == set(MUTATING)

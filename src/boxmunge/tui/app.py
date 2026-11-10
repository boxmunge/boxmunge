"""BoxmungeApp — main Textual application."""

import asyncio

from textual.app import App

from boxmunge.paths import BoxPaths
from boxmunge.tui.confirm import ConfirmScreen
from boxmunge.tui.dashboard import DashboardScreen
from boxmunge.tui.project_detail import ProjectDetailScreen


class BoxmungeApp(App):
    """boxmunge TUI console."""

    TITLE = "boxmunge"
    CSS_PATH = "boxmunge.tcss"

    def __init__(self, paths: BoxPaths | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.paths = paths or BoxPaths()
        self._refresh_timer = None

    def on_mount(self) -> None:
        self.push_screen(DashboardScreen(self.paths))
        self._refresh_timer = self.set_interval(10, self._auto_refresh)

    def _auto_refresh(self) -> None:
        """Periodically refresh the dashboard if it's the active screen."""
        screen = self.screen
        if isinstance(screen, DashboardScreen):
            screen.action_refresh()

    def push_screen_by_name(self, project_name: str) -> None:
        """Push the project detail screen for a given project."""
        self.push_screen(ProjectDetailScreen(project_name, self.paths))

    def run_action_with_confirm(self, action: str, project_name: str) -> None:
        """Ask first; on an explicit yes, run the action in the background
        and report how it went."""
        from boxmunge.tui.actions import PROMPTS

        def _answered(proceed: bool | None) -> None:
            if proceed:
                self.run_worker(_do_action(), exclusive=True)

        async def _do_action() -> None:
            from boxmunge.tui.actions import run_action

            self.notify(f"Running {action} for {project_name}...")
            outcome = await asyncio.to_thread(run_action, action, project_name, self.paths)
            self.notify(outcome.message, severity="information" if outcome.ok else "error",
                        timeout=5 if outcome.ok else 30)
            for screen in self.screen_stack:
                if isinstance(screen, DashboardScreen):
                    screen.action_refresh()

        self.push_screen(ConfirmScreen(PROMPTS[action].format(project=project_name)),
                         _answered)

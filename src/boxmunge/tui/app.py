"""BoxmungeApp — main Textual application."""

import asyncio
from pathlib import Path

from textual.app import App, ComposeResult

from boxmunge.paths import BoxPaths
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
        """Run an action in the background with notification."""

        async def _do_action() -> None:
            from boxmunge.commands.backup_cmd import run_backup
            from boxmunge.commands.deploy import run_deploy
            from boxmunge.commands.rollback import run_rollback

            actions = {
                "deploy": lambda: run_deploy(project_name, self.paths),
                "backup": lambda: run_backup(project_name, self.paths),
                "rollback": lambda: run_rollback(project_name, self.paths, yes=True),
            }

            handler = actions.get(action)
            if handler:
                self.notify(f"Running {action} for {project_name}...")
                result = await asyncio.to_thread(handler)
                if result == 0:
                    self.notify(f"{action} completed for {project_name}", severity="information")
                else:
                    self.notify(f"{action} failed for {project_name}", severity="error")

                # Refresh dashboard
                for screen in self.screen_stack:
                    if isinstance(screen, DashboardScreen):
                        screen.action_refresh()

        self.run_worker(_do_action(), exclusive=True)

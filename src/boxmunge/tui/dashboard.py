"""Dashboard screen — project table with host status bar."""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from boxmunge.tui.data import (
    load_all_project_status,
    load_host_info,
    relative_time,
)
from boxmunge.tui.widgets import KeyBar
from boxmunge.paths import BoxPaths


STATUS_DISPLAY = {
    "ok": "● OK",
    "failing": "● FAILING",
    "critical_stopped": "● CRITICAL (stopped)",
    "unknown": "● UNKNOWN",
}


class HostBar(Static):
    """Bottom bar showing host-level information."""
    pass


class DashboardScreen(Screen):
    """Main dashboard showing all projects."""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "deploy_project", "Deploy"),
        ("b", "backup_project", "Backup"),
        ("r", "refresh", "Refresh"),
    ]

    def __init__(self, paths: BoxPaths, **kwargs) -> None:
        super().__init__(**kwargs)
        self.paths = paths
        self._selected_project: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield DataTable(id="project-table", cursor_type="row")
        yield HostBar(id="host-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("PROJECT", "STATUS", "LAST CHECK", "DEPLOYED", "REF")
        self._refresh_data()

    def _refresh_data(self) -> None:
        table = self.query_one(DataTable)
        table.clear()

        projects = load_all_project_status(self.paths)
        for p in projects:
            status_text = STATUS_DISPLAY.get(p.status, f"● {p.status.upper()}")
            table.add_row(
                p.name,
                status_text,
                relative_time(p.last_check),
                relative_time(p.deployed_at),
                p.current_ref or "-",
                key=p.name,
            )

        host = load_host_info(self.paths)
        caddy_status = "running" if host.caddy_running else "stopped"
        bar = self.query_one(HostBar)
        bar.update(
            f"{host.hostname} │ Disk: {host.disk_free_gb}GB free │ "
            f"Caddy: {caddy_status}"
        )

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        if event.row_key:
            self._selected_project = str(event.row_key.value)

    def on_data_table_row_selected(
        self, event: DataTable.RowSelected
    ) -> None:
        """Enter pressed on a row — open project detail."""
        if event.row_key:
            self.app.push_screen_by_name(str(event.row_key.value))

    def action_refresh(self) -> None:
        self._refresh_data()

    def action_deploy_project(self) -> None:
        if self._selected_project:
            self.app.run_action_with_confirm(
                "deploy", self._selected_project
            )

    def action_backup_project(self) -> None:
        if self._selected_project:
            self.app.run_action_with_confirm(
                "backup", self._selected_project
            )

    def action_quit(self) -> None:
        self.app.exit()

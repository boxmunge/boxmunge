"""Project detail screen — tabbed view with Overview, Logs, Backups, Config."""

import asyncio
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    DataTable, Footer, Header, Label, RichLog, Static,
    TabbedContent, TabPane,
)

from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state
from boxmunge.tui.data import (
    load_project_backups,
    load_project_services,
    relative_time,
)
from boxmunge.tui.widgets import StatusIndicator


STATUS_DISPLAY = {
    "ok": "[#4ade80]● OK[/]",
    "failing": "[#fbbf24]● FAILING[/]",
    "critical_stopped": "[#f87171]● CRITICAL (stopped)[/]",
    "unknown": "[#888888]● UNKNOWN[/]",
}


class ProjectHeader(Static):
    """Header showing project name, status, ref, deploy time."""
    pass


class ProjectDetailScreen(Screen):
    """Tabbed detail view for a single project."""

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("1", "show_tab('overview')", "Overview"),
        ("2", "show_tab('logs')", "Logs"),
        ("3", "show_tab('backups')", "Backups"),
        ("4", "show_tab('config')", "Config"),
        ("d", "deploy", "Deploy"),
        ("b", "backup", "Backup"),
        ("r", "rollback", "Rollback"),
        ("f", "filter_logs", "Filter"),
    ]

    def __init__(self, project_name: str, paths: BoxPaths, **kwargs) -> None:
        super().__init__(**kwargs)
        self.project_name = project_name
        self.paths = paths
        self._log_task: asyncio.Task | None = None
        self._log_services: list[str] = []
        self._log_filter_index = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield ProjectHeader(id="project-header")
        with TabbedContent(initial="overview", id="detail-content"):
            with TabPane("Overview", id="overview"):
                with VerticalScroll():
                    yield DataTable(id="services-table", cursor_type="none")
                    yield Static(id="health-summary")
                    yield Static(id="deploy-history")
            with TabPane("Logs", id="logs"):
                yield RichLog(id="log-view", highlight=True, markup=False)
            with TabPane("Backups", id="backups"):
                with VerticalScroll():
                    yield DataTable(id="backups-table", cursor_type="none")
                    yield Static(id="backup-info")
            with TabPane("Config", id="config"):
                with VerticalScroll():
                    yield Static(id="manifest-view")
                    yield Static(id="caddy-view")
        yield Footer()

    def on_mount(self) -> None:
        self._load_header()
        self._load_overview()
        self._load_backups()
        self._load_config()

    def _load_header(self) -> None:
        health = read_state(self.paths.project_health_state(self.project_name))
        deploy = read_state(self.paths.project_deploy_state(self.project_name))
        status = health.get("status", "unknown")
        ref = deploy.get("current_ref", "-")
        deployed = relative_time(deploy.get("deployed_at", ""))
        status_text = STATUS_DISPLAY.get(status, f"● {status.upper()}")

        header = self.query_one(ProjectHeader)
        header.update(
            f"[bold #7ec8e3]{self.project_name}[/]  {status_text}  "
            f"ref: {ref}  deployed: {deployed}"
        )

    def _load_overview(self) -> None:
        services = load_project_services(self.paths, self.project_name)
        table = self.query_one("#services-table", DataTable)
        table.add_columns("SERVICE", "TYPE", "PORT", "HEALTH", "ROUTE")
        for svc in services:
            health_str = svc.docker_health or "-"
            table.add_row(svc.name, svc.svc_type, str(svc.port), health_str, svc.route)

        self._log_services = [svc.name for svc in services]

        health = read_state(self.paths.project_health_state(self.project_name))
        parts = []
        if health.get("last_check"):
            parts.append(f"Last check: {relative_time(health['last_check'])}")
        consecutive = health.get("consecutive_failures", 0)
        if consecutive > 0:
            parts.append(f"Consecutive failures: {consecutive}")
        if health.get("failure_reason"):
            parts.append(f"Reason: {health['failure_reason']}")
        if health.get("last_success"):
            parts.append(f"Last OK: {relative_time(health['last_success'])}")

        summary = self.query_one("#health-summary", Static)
        summary.update("\n".join(parts) if parts else "No health data yet")

        deploy = read_state(self.paths.project_deploy_state(self.project_name))
        history = deploy.get("history", [])[:5]
        if history:
            lines = [f"  {h['ref']}  {relative_time(h.get('deployed_at', ''))}" for h in history]
            hist_text = "Deploy history:\n" + "\n".join(lines)
        else:
            hist_text = "No deploy history"

        self.query_one("#deploy-history", Static).update(hist_text)

    def _load_backups(self) -> None:
        backups = load_project_backups(self.paths, self.project_name)
        table = self.query_one("#backups-table", DataTable)
        table.add_columns("SNAPSHOT", "SIZE", "DATE")
        for b in backups:
            size = f"{b.size_bytes / 1024:.1f}KB" if b.size_bytes < 1048576 else f"{b.size_bytes / 1048576:.1f}MB"
            table.add_row(b.filename, size, relative_time(b.modified))

        try:
            manifest = load_manifest(self.paths.project_manifest(self.project_name))
            backup_conf = manifest.get("backup", {})
            info_parts = [
                f"Type: {backup_conf.get('type', 'none')}",
                f"Retention: {backup_conf.get('retention', 7)}",
            ]
            if backup_conf.get("dump_command"):
                info_parts.append(f"Dump: {backup_conf['dump_command']}")
            if backup_conf.get("restore_command"):
                info_parts.append(f"Restore: {backup_conf['restore_command']}")
        except ManifestError:
            info_parts = ["Could not load manifest"]

        self.query_one("#backup-info", Static).update("\n".join(info_parts))

    def _load_config(self) -> None:
        manifest_path = self.paths.project_manifest(self.project_name)
        if manifest_path.exists():
            content = manifest_path.read_text()
            self.query_one("#manifest-view", Static).update(
                f"[bold]manifest.yml[/]\n\n{content}"
            )
        else:
            self.query_one("#manifest-view", Static).update("manifest.yml not found")

        caddy_path = self.paths.project_caddy_site(self.project_name)
        override = self.paths.project_caddy_override(self.project_name)
        if override.exists():
            caddy_content = override.read_text()
            label = "[bold]caddy.override.conf[/] (custom override active)\n\n"
        elif caddy_path.exists():
            caddy_content = caddy_path.read_text()
            label = "[bold]Generated Caddy config[/]\n\n"
        else:
            caddy_content = ""
            label = "No Caddy config generated yet"

        self.query_one("#caddy-view", Static).update(label + caddy_content)

    async def _tail_logs(self, service: str | None = None) -> None:
        """Start tailing docker compose logs in the background."""
        log_widget = self.query_one("#log-view", RichLog)
        log_widget.clear()

        project_dir = self.paths.project_dir(self.project_name)
        cmd = ["docker", "compose", "-f", "compose.yml"]
        override = self.paths.project_compose_override(self.project_name)
        if override.exists():
            cmd.extend(["-f", "compose.boxmunge.yml"])
        cmd.extend(["logs", "--tail=50", "--follow"])
        if service:
            cmd.append(service)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, cwd=project_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                log_widget.write(line.decode("utf-8", errors="replace").rstrip())
        except (OSError, asyncio.CancelledError):
            pass

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        if event.tab.id and "logs" in str(event.pane.id):
            if self._log_task is None or self._log_task.done():
                self._log_task = asyncio.create_task(self._tail_logs())
        else:
            if self._log_task and not self._log_task.done():
                self._log_task.cancel()

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def action_go_back(self) -> None:
        if self._log_task and not self._log_task.done():
            self._log_task.cancel()
        self.app.pop_screen()

    def action_filter_logs(self) -> None:
        """Cycle through log service filters."""
        if not self._log_services:
            return
        options = [None] + self._log_services
        self._log_filter_index = (self._log_filter_index + 1) % len(options)
        service = options[self._log_filter_index]

        if self._log_task and not self._log_task.done():
            self._log_task.cancel()
        self._log_task = asyncio.create_task(self._tail_logs(service))

        log_widget = self.query_one("#log-view", RichLog)
        filter_label = service or "all"
        log_widget.write(f"--- Filtering: {filter_label} ---")

    def action_deploy(self) -> None:
        self.app.run_action_with_confirm("deploy", self.project_name)

    def action_backup(self) -> None:
        self.app.run_action_with_confirm("backup", self.project_name)

    def action_rollback(self) -> None:
        self.app.run_action_with_confirm("rollback", self.project_name)

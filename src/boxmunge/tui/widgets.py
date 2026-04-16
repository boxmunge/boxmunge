"""Reusable TUI widgets for boxmunge console."""

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static


STATUS_STYLES = {
    "ok": ("● OK", "status-ok"),
    "failing": ("● FAILING", "status-failing"),
    "critical_stopped": ("● CRITICAL", "status-critical"),
    "unknown": ("● UNKNOWN", "status-unknown"),
}


class StatusIndicator(Static):
    """Coloured status indicator dot + text."""

    def __init__(self, status: str = "unknown", **kwargs) -> None:
        text, css_class = STATUS_STYLES.get(status, STATUS_STYLES["unknown"])
        super().__init__(text, **kwargs)
        self.add_class(css_class)

    def update_status(self, status: str) -> None:
        text, css_class = STATUS_STYLES.get(status, STATUS_STYLES["unknown"])
        self.update(text)
        for cls in ("status-ok", "status-failing", "status-critical", "status-unknown"):
            self.remove_class(cls)
        self.add_class(css_class)


class KeyBar(Static):
    """Bottom bar showing keyboard shortcuts."""

    def __init__(self, keys: dict[str, str], **kwargs) -> None:
        parts = [f"{k}:{v}" for k, v in keys.items()]
        super().__init__("  ".join(parts), id="action-bar", **kwargs)

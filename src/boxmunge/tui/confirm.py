# SPDX-License-Identifier: Apache-2.0
"""The yes/no question the TUI asks before an action changes a project.

The CLI asks "Proceed? [y/N]" and MCP demands confirm: true; this is the
TUI's equivalent. The safe answer is the default: the focused button is
Cancel, so a stray Enter (or Escape, or n) changes nothing.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ConfirmScreen(ModalScreen[bool]):
    """Dismisses with True only on an explicit yes."""

    BINDINGS = [
        ("y", "answer(True)", "Proceed"),
        ("n", "answer(False)", "Cancel"),
        ("escape", "answer(False)", "Cancel"),
    ]

    def __init__(self, prompt: str) -> None:
        super().__init__()
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static(self.prompt, id="confirm-prompt")
            yield Static("Proceed? [y/N]", id="confirm-question")
            with Horizontal(id="confirm-buttons"):
                yield Button("Cancel (n)", id="confirm-no", variant="primary")
                yield Button("Proceed (y)", id="confirm-yes", variant="error")

    def on_mount(self) -> None:
        self.query_one("#confirm-no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")

    def action_answer(self, proceed: bool) -> None:
        self.dismiss(proceed)

# SPDX-License-Identifier: Apache-2.0
"""Progress marker parser and terminal renderer for init-host.sh output."""

from __future__ import annotations

_MARKER_PREFIX = "##BOXMUNGE:STEP:"


def parse_marker(line: str) -> tuple[int, int, str] | None:
    """Parse a progress marker line. Returns (current, total, description) or None."""
    if not line.startswith(_MARKER_PREFIX):
        return None
    rest = line[len(_MARKER_PREFIX):]
    parts = rest.split(":", 2)
    if len(parts) != 3:
        return None
    try:
        current = int(parts[0])
        total = int(parts[1])
    except ValueError:
        return None
    return current, total, parts[2].strip()


def render_progress_bar(current: int, total: int, description: str, width: int = 30) -> str:
    """Render a tqdm-style progress bar string."""
    if total == 0:
        pct = 0
    else:
        pct = int((current / total) * 100)
    filled = int(width * current / total) if total > 0 else 0
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    return f"[{bar}] {pct:>3}%  {description}..."

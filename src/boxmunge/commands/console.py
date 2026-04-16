"""boxmunge console — launch the TUI dashboard."""

import sys


def cmd_console(args: list[str]) -> None:
    """Launch the interactive TUI console."""
    try:
        from boxmunge.tui.app import BoxmungeApp
    except ImportError:
        print("ERROR: TUI requires textual. Install with: pip install boxmunge[tui]")
        sys.exit(1)

    from boxmunge.paths import BoxPaths
    app = BoxmungeApp(paths=BoxPaths())
    app.run()

"""boxmunge console — launch the TUI dashboard."""

import sys


def cmd_console(args: list[str]) -> None:
    """Launch the interactive TUI console."""
    from boxmunge.commands.argv import parse_args
    parse_args("console", args)
    try:
        from boxmunge.tui.app import BoxmungeApp
    except ImportError:
        print(
            "ERROR: TUI requires textual, which ships with boxmunge-server by "
            "default — this environment looks incomplete.\n"
            "Repair with: /opt/boxmunge/env-active/bin/pip install 'textual>=0.50'",
            file=sys.stderr,
        )
        sys.exit(1)

    from boxmunge.paths import BoxPaths
    app = BoxmungeApp(paths=BoxPaths())
    app.run()

"""boxmunge test-alert — send a test Pushover notification."""

import sys

from boxmunge.config import load_config, ConfigError
from boxmunge.notify import notify, pushover_credentials
from boxmunge.paths import BoxPaths


def cmd_test_alert(args: list[str]) -> None:
    """Send a test Pushover notification to verify alerting works."""
    from boxmunge.commands.argv import parse_args
    parse_args("test-alert", args)
    paths = BoxPaths()

    try:
        user_key, app_token = pushover_credentials(load_config(paths))
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if not user_key or not app_token:
        print("ERROR: Pushover credentials not configured in boxmunge.yml", file=sys.stderr)
        print("Set pushover.user_key and pushover.app_token")
        sys.exit(1)

    print("Sending test notification...")
    # Through notify, so the test exercises exactly what real alerts do.
    if notify(paths, "test alert",
              "If you see this, alerting from this box works.", component="test-alert"):
        print("Test alert sent successfully.")
        sys.exit(0)
    print("ERROR: Failed to send test alert. Check credentials and network.", file=sys.stderr)
    sys.exit(1)

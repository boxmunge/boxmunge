"""boxmunge test-alert — send a test Pushover notification."""

import sys

from boxmunge.config import load_config, ConfigError
from boxmunge.paths import BoxPaths
from boxmunge.pushover import send_notification


def cmd_test_alert(args: list[str]) -> None:
    """Send a test Pushover notification to verify alerting works."""
    paths = BoxPaths()

    try:
        config = load_config(paths)
    except ConfigError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    pushover = config.get("pushover", {})
    user_key = pushover.get("user_key", "")
    app_token = pushover.get("app_token", "")

    if not user_key or not app_token:
        print("ERROR: Pushover credentials not configured in boxmunge.yml")
        print("Set pushover.user_key and pushover.app_token")
        sys.exit(1)

    print("Sending test notification...")
    hostname = config.get("hostname", "unknown")
    success = send_notification(
        user_key=user_key,
        app_token=app_token,
        title=f"boxmunge test alert",
        message=f"Test notification from {hostname}. If you see this, alerting works.",
    )

    if success:
        print("Test alert sent successfully.")
        sys.exit(0)
    else:
        print("ERROR: Failed to send test alert. Check credentials and network.")
        sys.exit(1)

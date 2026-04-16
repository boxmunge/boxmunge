"""Pushover notification sending.

Uses urllib (stdlib) to POST to the Pushover API. No external HTTP library needed.
"""

import urllib.request
import urllib.error
import urllib.parse

PUSHOVER_API_URL = "https://api.pushover.net/1/messages.json"


def _post_pushover(data: dict) -> bool:
    """POST to the Pushover API. Returns True on success."""
    try:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(PUSHOVER_API_URL, data=encoded)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def format_alert(project: str, severity: str, message: str) -> tuple[str, str]:
    """Format an alert notification. Returns (title, body)."""
    sev = severity.upper()
    title = f"boxmunge [{sev}] {project}"
    body = f"Project: {project}\nSeverity: {sev}\n\n{message}"
    return title, body


def format_recovery(project: str) -> tuple[str, str]:
    """Format a recovery notification. Returns (title, body)."""
    title = f"boxmunge [RECOVERED] {project}"
    body = f"Project: {project}\n\nService has recovered and is healthy again."
    return title, body


def send_notification(
    user_key: str,
    app_token: str,
    title: str,
    message: str,
    priority: int = 0,
) -> bool:
    """Send a Pushover notification. Returns True on success."""
    if not user_key or not app_token:
        return False

    return _post_pushover({
        "user": user_key,
        "token": app_token,
        "title": title,
        "message": message,
        "priority": priority,
    })

"""Pushover notification sending.

Uses urllib (stdlib) to POST to the Pushover API. No external HTTP library needed.
"""

import logging
import urllib.request
import urllib.error
import urllib.parse

_LOGGER = logging.getLogger("boxmunge")

PUSHOVER_API_URL = "https://api.pushover.net/1/messages.json"
# Pushover's documented limits.
MESSAGE_LIMIT = 1024
TITLE_LIMIT = 250
_TRUNCATED = "\n... (truncated; see the boxmunge log)"


def _fit(text: str, limit: int, marker: str) -> str:
    """text, cut to limit characters with a marker saying it was cut."""
    if len(text) <= limit:
        return text
    return text[:limit - len(marker)] + marker


def _post_pushover(data: dict) -> bool:
    """POST to the Pushover API. Returns True on success; logs why not."""
    try:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(PUSHOVER_API_URL, data=encoded)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                return True
            _LOGGER.warning("Pushover API returned HTTP %s", resp.status)
            return False
    except (urllib.error.URLError, OSError) as e:
        _LOGGER.warning("Pushover API request failed: %s", e)
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
        "title": _fit(title, TITLE_LIMIT, "..."),
        "message": _fit(message, MESSAGE_LIMIT, _TRUNCATED),
        "priority": priority,
    })

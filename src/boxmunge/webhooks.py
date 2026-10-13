"""Webhook delivery — best-effort HTTP POST notifications.

Delivery is best-effort: a failed POST is logged as a warning and never
fails the operation that fired it. Delivery also never holds that
operation's project lock. ``webhook_safe`` loads config and selects the
matching hooks synchronously (so config errors surface at once), then POSTs
on a background thread and returns. The caller releases its lock without
waiting on the network. The thread is non-daemon, so a CLI process still
finishes delivering before it exits.
"""
from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from boxmunge.config import ConfigError, load_config
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths

_POST_TIMEOUT_SEC = 10


def build_payload(event: str, project: str, hostname: str,
                  details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "event": event,
        "project": project,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "details": details or {},
    }


def _matching_urls(event: str, config: dict[str, Any]) -> list[str]:
    return [
        hook.get("url", "") for hook in config.get("webhooks", [])
        if event in hook.get("events", [])
    ]


def _url_host(url: str) -> str:
    """Scheme and host only: webhook URL paths often carry secret tokens."""
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.hostname}" if parts.hostname else "<invalid url>"


def fire_webhook(event: str, project: str, config: dict[str, Any],
                 details: dict[str, Any] | None = None) -> list[str]:
    """POST the event to every matching hook, synchronously.

    Returns one description per failed delivery (empty if all succeeded).
    """
    urls = _matching_urls(event, config)
    if not urls:
        return []
    payload = build_payload(event, project, config.get("hostname", "unknown"), details)
    body = json.dumps(payload).encode("utf-8")
    failures: list[str] = []
    for url in urls:
        try:
            request = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=_POST_TIMEOUT_SEC):
                pass
        except Exception as e:  # noqa: BLE001 — best-effort delivery, logged by caller
            failures.append(f"{_url_host(url)}: {e}")
    return failures


def _deliver(event: str, name: str, config: dict[str, Any],
             details: dict[str, Any] | None, paths: BoxPaths) -> None:
    for failure in fire_webhook(event, name, config, details=details):
        log_warning("webhook", f"{event} webhook delivery failed: {failure}",
                    paths, project=name)


def webhook_safe(
    event: str,
    name: str,
    paths: BoxPaths,
    details: dict[str, Any] | None = None,
) -> threading.Thread | None:
    """Fire the event's webhooks in the background; return the delivery thread.

    Returns None when no hook subscribes to the event or config could not
    be loaded. ConfigError and OSError from loading config are logged as
    warnings; programming errors propagate so they surface during
    development instead of being silently dropped.
    """
    try:
        config = load_config(paths)
    except (ConfigError, OSError) as e:
        log_warning("webhook", f"failed to fire {event} webhook: {e}",
                    paths, project=name)
        return None
    if not _matching_urls(event, config):
        return None
    thread = threading.Thread(
        target=_deliver, args=(event, name, config, details, paths),
        name=f"webhook-{event}-{name}",
    )
    thread.start()
    return thread

"""Webhook delivery — fire-and-forget HTTP POST notifications."""
from __future__ import annotations
import json
import urllib.request
from datetime import datetime, timezone
from typing import Any

def build_payload(event: str, project: str, hostname: str,
                  details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "event": event,
        "project": project,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "details": details or {},
    }

def fire_webhook(event: str, project: str, config: dict[str, Any],
                 details: dict[str, Any] | None = None) -> None:
    webhooks = config.get("webhooks", [])
    if not webhooks:
        return
    hostname = config.get("hostname", "unknown")
    payload = build_payload(event, project, hostname, details)
    body = json.dumps(payload).encode("utf-8")
    for hook in webhooks:
        url = hook.get("url", "")
        events = hook.get("events", [])
        if event not in events:
            continue
        try:
            request = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=10)
        except Exception:
            pass  # fire-and-forget

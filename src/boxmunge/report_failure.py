"""Fire-and-forget failure reporting to the version-check service.

Reports are best-effort — network failures are swallowed. The local
blocklist protects the box regardless of whether the report succeeds.
"""
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

VERSION_CHECK_BASE = "https://boxmunge.dev"
REPORT_URL = f"{VERSION_CHECK_BASE}/v1/report-failure"

def report_failure(version: str, installed_from: str, stage: str) -> bool:
    """Report a failed upgrade to the version-check service.

    Stages: 'preflight', 'apply', 'health_immediate', 'health_probation'.
    Returns True if the report was accepted, False otherwise.
    Never raises — all errors are swallowed.
    """
    payload = json.dumps({
        "version": version,
        "installed_from": installed_from,
        "stage": stage,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }).encode("utf-8")

    req = urllib.request.Request(
        REPORT_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"boxmunge/{installed_from}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 204
    except Exception:
        return False

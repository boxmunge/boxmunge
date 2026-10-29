"""Best-effort failure reporting to the version-check service.

A failed report never fails the upgrade (the local blocklist protects the
box regardless), but it is not silent: one stderr line says why it was not sent.
"""
import json
import sys
import urllib.request
from datetime import datetime, timezone

from boxmunge.version_check_url import version_check_base

# The service rejects longer or non-printable detail, which would lose the report.
DETAIL_MAX = 200


def _printable_detail(detail: str) -> str:
    return "".join(c if " " <= c <= "~" else "?" for c in detail)[:DETAIL_MAX]


def report_failure(version: str, installed_from: str, stage: str, detail: str = "") -> bool:
    """Report a failed upgrade to the version-check service.

    Stages: 'preflight', 'apply', 'health_immediate', 'health_probation', ...
    `detail` is the reason (e.g. "system_upgrade_failed: install_sh_exit_100").
    Returns True if the report was accepted, False otherwise; never raises.
    """
    body = {
        "version": version,
        "installed_from": installed_from,
        "stage": stage,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if detail:
        body["detail"] = _printable_detail(detail)
    url = f"{version_check_base()}/v1/report-failure"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"boxmunge/{installed_from}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 204:
                return True
            reason = f"the service answered HTTP {resp.status}"
    except Exception as e:  # noqa: BLE001 — best-effort: any failure is reported, not raised
        reason = f"{type(e).__name__}: {e}"
    print(f"boxmunge: could not send the upgrade failure report to {url}: {reason}",
          file=sys.stderr)
    return False

"""Alert the maintainer when upgrade failures for a release pile up.

Failure reports are unauthenticated: anyone with addresses in a few networks
can send them. So they never hold a release (that would let anyone withhold
a security release from every box); the maintainer decides, and holds one
by hand. When reports for a release come from ALERT_NETWORKS or more distinct
networks (failure_store reporters) in failure_store.REPORT_WINDOW, and the
release is not already held, `python failure_alert.py DB` prints one line
naming each such release and exactly how to hold it, and exits 1.

The service's smoke script runs it, so boxmunge's health check turns that
line into a warning, alerting the box's operator through Pushover once per
distinct message (the line carries no counts, so new reports do not
re-alert). The warning clears, with a recovery alert, when the release is
held or its reports age out of the window; a later crossing alerts again.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import circuit_breaker
import failure_store

ALERT_NETWORKS = 2
SERVICE_URL = "https://boxmunge.dev"


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def crossing(db_path: Path, now: datetime) -> list[str]:
    """Releases over the alert threshold and not held, oldest first."""
    over = failure_store.versions_reported_by(db_path, now, ALERT_NETWORKS)
    return sorted(over - circuit_breaker.tripped_versions(db_path), key=_version_key)


def _hold_steps(version: str) -> str:
    return (f"curl -X POST -H \"Authorization: Bearer $CB_SECRET\" "
            f"'{SERVICE_URL}/v1/circuit-breaker/trip?version={version}' && "
            f"gh release edit v{version} --title "
            f"\"$(gh release view v{version} --json name -q .name) [held]\"")


def message(versions: list[str]) -> str:
    """One line for the health check: what crossed, and how to hold each."""
    hours = int(failure_store.REPORT_WINDOW.total_seconds() // 3600)
    holds = "; ".join(f"{v}: {_hold_steps(v)}" for v in versions)
    return (f"Upgrade failures reported from {ALERT_NETWORKS}+ networks in {hours}h for "
            f"{', '.join(versions)}, not held. Reports are unauthenticated: check them on "
            f"the admin stats page. To hold a release, run: {holds}")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: failure_alert.py DB", file=sys.stderr)
        return 1
    db_path = Path(argv[1])
    if not db_path.is_file():
        print(f"failure alert check: database {db_path} is missing", file=sys.stderr)
        return 1
    versions = crossing(db_path, datetime.now(timezone.utc))
    if versions:
        print(message(versions), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

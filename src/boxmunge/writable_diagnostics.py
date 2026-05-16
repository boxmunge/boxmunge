# SPDX-License-Identifier: Apache-2.0
"""Log-pattern matching for read-only-filesystem errors + hint formatter.

Pure module: no I/O, no logging. Consumed by deploy command (post-up scan),
health-check failure path, and `boxmunge log` highlighting.

Patterns target the common shapes the four container runtimes we care
about emit when an app writes to a read-only filesystem under boxmunge's
v0.8 hardening default:

  - nginx [emerg] mkdir()/open() ... Read-only file system
  - Python PermissionError: [Errno 30] Read-only file system: '<path>'
  - Shell `mkdir: cannot create directory '<path>': Read-only file system`
  - Raw EROFS errno strings with embedded paths

The scanner returns the offending path (or its parent directory, where
useful) so callers can suggest the right entry under
`services.<svc>.writable.ephemeral`.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from boxmunge.writable import WritableState, classify_state


@dataclass(frozen=True)
class WritableError:
    """One detected read-only-filesystem error."""

    path: str
    raw: str


# Ordered pattern set. First match wins for a given line. The regexes are
# anchored on the "Read-only file system" / EROFS signal to keep false
# positives low — the path-extraction group is positioned relative to that
# signal so generic text mentioning a path won't trigger.
#
# Each tuple is (regex, transform). The transform takes the captured path
# string and returns the path to record. Some patterns capture a file path
# (e.g. /var/cache/nginx/client_temp); we trim to the parent directory
# when the failure is mkdir/open under a missing writable dir.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # nginx mkdir() "..." failed (...: Read-only file system)
    # Capture the path; transform = trim to nginx-style parent (path itself
    # is e.g. /var/cache/nginx/client_temp, parent is /var/cache/nginx).
    (
        re.compile(
            r'mkdir\(\)\s*"([^"]+)"\s*failed\s*\([^)]*Read-only file system\)',
            re.IGNORECASE,
        ),
        "parent",
    ),
    # nginx open() "/var/run/nginx.pid" failed (...: Read-only file system)
    (
        re.compile(
            r'open\(\)\s*"([^"]+)"\s*failed\s*\([^)]*Read-only file system\)',
            re.IGNORECASE,
        ),
        "parent",
    ),
    # Shell mkdir: cannot create directory '<path>': Read-only file system
    # Here the path *is* the target directory — keep as-is.
    (
        re.compile(
            r"mkdir:\s*cannot create directory\s*'([^']+)':\s*Read-only file system",
            re.IGNORECASE,
        ),
        "exact",
    ),
    # Python PermissionError / OSError [Errno 30] Read-only file system: '<path>'
    (
        re.compile(
            r"\[Errno\s*30\]\s*Read-only file system:\s*'([^']+)'",
            re.IGNORECASE,
        ),
        "exact",
    ),
    # EROFS: read-only file system, open '<path>' / similar
    (
        re.compile(
            r"EROFS[^\n]*['\"]([^'\"]+)['\"]",
        ),
        "exact",
    ),
]


def _to_parent(path: str) -> str:
    """Trim to parent directory. /a/b/c → /a/b. /a → /. / stays /."""
    if "/" not in path or path == "/":
        return path
    parent = path.rsplit("/", 1)[0]
    return parent or "/"


def scan_line(line: str) -> WritableError | None:
    """Scan a single log line. Return WritableError on match, else None.

    Useful for `boxmunge log` streaming where we want per-line decoration.
    """
    for pattern, transform in _PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        raw_path = m.group(1)
        path = _to_parent(raw_path) if transform == "parent" else raw_path
        return WritableError(path=path, raw=line.rstrip("\n"))
    return None


def scan_logs(logs: str) -> list[WritableError]:
    """Scan a multi-line log block. Return one WritableError per unique path.

    De-duplication: many nginx errors fire for sibling temp directories
    under one parent (client_temp, proxy_temp, fastcgi_temp, ...). We
    collapse to one hint per parent directory so the operator gets a
    single actionable line instead of five duplicates.
    """
    seen_paths: set[str] = set()
    out: list[WritableError] = []
    for line in logs.splitlines():
        err = scan_line(line)
        if err is None:
            continue
        if err.path in seen_paths:
            continue
        seen_paths.add(err.path)
        out.append(err)
    return out


def format_hint(
    errors: list[WritableError],
    service: str,
    state: WritableState,
) -> str:
    """Format a deploy-time/health-failure hint block.

    Empty error list → empty string. Caller can append directly to
    operator output without conditional.
    """
    if not errors:
        return ""

    paths = sorted({e.path for e in errors})
    paths_list = ", ".join(repr(p) for p in paths)

    if state is WritableState.EXTERNAL:
        return (
            f"[HINT] services.{service} reports read-only filesystem errors "
            f"for path(s) {paths_list}.\n"
            f"       This service is externally-managed "
            f"(writable.external: true) — boxmunge\n"
            f"       does not own writability here. Add the path(s) "
            f"directly to your compose.yml as\n"
            f"       a `tmpfs:` (ephemeral) or `volumes:` (persistent) "
            f"entry on the service."
        )

    # DEFAULT and MANAGED both point at the manifest.
    return (
        f"[HINT] services.{service} reports read-only filesystem errors "
        f"for path(s) {paths_list}.\n"
        f"       Add the path(s) to manifest.yml at "
        f"services.{service}.writable.ephemeral\n"
        f"       (or .persistent if data should survive restart). "
        f"See: agent-help writable."
    )


# Default 8s sleep — long enough for container startup to start emitting
# real errors, short enough that operators don't lose focus on the deploy.
DEFAULT_SCAN_DELAY_SECONDS = 8


# Module-level sleep indirection. Production runs use time.sleep; the
# conftest in tests/ patches this to a no-op via monkeypatch so the unit
# suite doesn't burn 8s per real-deploy test.
_sleep_fn: Callable[[float], None] = time.sleep


def run_post_deploy_diagnostics(
    project_dir: Path,
    manifest: dict[str, Any],
    *,
    sleep_seconds: int = DEFAULT_SCAN_DELAY_SECONDS,
    sleep_fn: Callable[[float], None] | None = None,
    log_fetcher: Callable[[str], str] | None = None,
) -> dict[str, str]:
    """Sleep, fetch per-service logs, scan for read-only-fs errors,
    return per-service hint blocks.

    Returns {service_name: hint_string} for services with detected
    errors. Empty dict if all-clear or if log fetching fails.

    Dependencies are injectable:
      - sleep_fn: defaults to time.sleep. Tests pass a no-op.
      - log_fetcher: called with (service_name) -> log string. Defaults
        to compose_logs_capture against the project_dir.

    Never raises. Log-fetch failures are silently skipped on the
    grounds that diagnostics must not block a deploy — the deploy
    command keeps going regardless.
    """
    services = manifest.get("services", {}) or {}
    if not isinstance(services, dict) or not services:
        return {}

    # Filter services we should NOT diagnose:
    #   - EXTERNAL state (operator owns writability; hint would mislead)
    #   - profile: off (no read_only baseline enforced)
    targets: list[str] = []
    project_security = manifest.get("security") or {}
    project_off = (
        isinstance(project_security, dict)
        and project_security.get("profile") == "off"
    )
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if classify_state(svc) is WritableState.EXTERNAL:
            continue
        svc_security = svc.get("security") or {}
        svc_profile = (
            svc_security.get("profile")
            if isinstance(svc_security, dict) else None
        )
        # Service-level off wins over project-level. Default behaviour
        # (no service profile) inherits project profile.
        if svc_profile == "off":
            continue
        if svc_profile is None and project_off:
            continue
        targets.append(svc_name)

    if not targets:
        return {}

    if sleep_fn is None:
        sleep_fn = _sleep_fn
    sleep_fn(sleep_seconds)

    if log_fetcher is None:
        # Lazy import — keeps writable_diagnostics importable in
        # contexts where docker isn't installed (eg. CI unit tests).
        from boxmunge.docker import compose_logs_capture

        compose_files = ["compose.yml", "compose.boxmunge.yml"]

        def _default_fetch(svc: str) -> str:
            return compose_logs_capture(
                project_dir, service=svc, tail=200,
                compose_files=compose_files,
            )

        log_fetcher = _default_fetch

    hints: dict[str, str] = {}
    for svc_name in targets:
        try:
            logs = log_fetcher(svc_name)
        except Exception:
            continue
        if not logs:
            continue
        errors = scan_logs(logs)
        if not errors:
            continue
        svc_block = services[svc_name] if isinstance(services[svc_name], dict) else {}
        state = classify_state(svc_block)
        hint = format_hint(errors, service=svc_name, state=state)
        if hint:
            hints[svc_name] = hint
    return hints

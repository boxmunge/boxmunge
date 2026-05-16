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
from dataclasses import dataclass

from boxmunge.writable import WritableState


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

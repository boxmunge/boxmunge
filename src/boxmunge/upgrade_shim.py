# SPDX-License-Identifier: Apache-2.0
"""How unprivileged callers reach the root upgrade shim.

The deploy shell and the MCP server both run as deploy. A platform upgrade
needs root (venv swap, stash of root-owned config, probation), so both go
through the same sudo rule, which permits exactly these invocations.
See install-sudoers in scripts/boxmunge-upgrade.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# How sudo -n says the rule does not permit a command: no NOPASSWD rule
# matches, a rule names other commands, or the user has no rule at all.
_SUDO_REFUSED = re.compile(r"sudo: a password is required|Sorry, user \S+ is not allowed to "
                           r"execute |(?:sudo: )?\S+ is not in the sudoers file")


def shim_command(paths: BoxPaths, target: str | None = None) -> list[str]:
    """argv for `upgrade` (discover the latest) or `upgrade --target <version>`.

    The shim validates the version and refuses downgrades and blocklisted
    versions; this only builds the command line.
    """
    shim = str(paths.bin / "boxmunge-upgrade")
    if target is None:
        return ["sudo", "-n", shim, "auto"]
    return ["sudo", "-n", shim, "target", target]


def repair_deps_command(paths: BoxPaths) -> list[str]:
    """argv for `upgrade --repair-deps`: the shim installs the installed
    release's hash-pinned dependencies into the live venv, from that release's
    verified bundle. It is allowed during probation."""
    return ["sudo", "-n", str(paths.bin / "boxmunge-upgrade"), "repair-deps"]


def check_command(paths: BoxPaths, version: str) -> list[str]:
    """argv for `upgrade-check`: the shim runs release `version`'s own
    readiness check against this box and prints one JSON verdict."""
    return ["sudo", "-n", str(paths.bin / "boxmunge-upgrade"), "check", version]


def guide_command(paths: BoxPaths, version: str) -> list[str]:
    """argv for `upgrade-howto`: the shim prints release `version`'s
    upgrade-notes.json once its signed SHA256SUMS verifies it."""
    return ["sudo", "-n", str(paths.bin / "boxmunge-upgrade"), "guide", version]


def printable(text: str) -> str:
    """`text` with every character but printable ones and newlines dropped."""
    return "".join(c for c in text if c == "\n" or c.isprintable())


def printable_lines(text: str) -> list[str]:
    """`text` as printable lines, split at newlines only (not splitlines():
    no other control character may start a line)."""
    return printable(text).split("\n")


def stderr_tail(stderr: str, limit: int = 400) -> str:
    """The end of what the shim (or sudo) wrote to stderr, printable, one line."""
    text = " ".join(printable(stderr).split())
    return text[-limit:] if text else "(it wrote nothing to stderr)"


def sudo_refusal(stderr: str) -> str | None:
    """What to do when sudo itself refused (the deploy user's rule does not
    permit the verb yet), or None. Only sudo's refusals count, never its
    warnings ("unable to resolve host") or what the shim said."""
    if not any(map(_SUDO_REFUSED.match, stderr.splitlines())):
        return None
    return ("sudo refused: the deploy user's sudo rule does not permit this upgrade-shim "
            "verb. The operator installs the current rule as supervisor: sudo "
            "/opt/boxmunge/bin/boxmunge-upgrade install-sudoers")

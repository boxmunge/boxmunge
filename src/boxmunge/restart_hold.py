# SPDX-License-Identifier: Apache-2.0
"""Keep a deliberately stopped project stopped across a Docker restart.

`compose stop` is not enough to keep a project down: when the Docker daemon
starts (a reboot, a docker-ce upgrade) it restarts every stopped
`restart: always` container. Quarantine and pause both stop a project on
purpose, so both set each container's restart policy to "no" while it is
down and give the original back when it comes up (audit B-19).

The caller keeps the originals in its own state record (the quarantine or
pause record). Both functions raise DockerError; callers fail loudly.
"""
from __future__ import annotations

from collections.abc import Mapping

from boxmunge.docker import project_restart_policies, set_restart_policy


def hold(project_name: str, saved: Mapping[str, str]) -> dict[str, str]:
    """Set every project container's restart policy to "no".

    Returns ``saved`` plus the original policy of each container not yet in
    it. A policy already saved is kept: re-holding sees "no" everywhere and
    must not overwrite "always" with it.
    """
    current = project_restart_policies(project_name)
    set_restart_policy(sorted(n for n, p in current.items() if p != "no"), "no")
    merged = dict(saved)
    for name, policy in current.items():
        merged.setdefault(name, policy)
    return merged


def release(project_name: str, saved: Mapping[str, str]) -> None:
    """Give each still-existing container its saved policy back.

    A container that no longer exists is recreated by `compose up` with the
    compose file's policy.
    """
    present = project_restart_policies(project_name)
    by_policy: dict[str, list[str]] = {}
    for name, policy in saved.items():
        if name in present and policy != present[name]:
            by_policy.setdefault(policy, []).append(name)
    for policy, names in sorted(by_policy.items()):
        set_restart_policy(sorted(names), policy)


def originals(*records: Mapping[str, str]) -> dict[str, str]:
    """Combine saved policies from several records, preferring a real
    policy over a "no" that only reflects an earlier hold."""
    out: dict[str, str] = {}
    for record in records:
        for name, policy in record.items():
            if out.get(name, "no") == "no":
                out[name] = policy
    return out

# SPDX-License-Identifier: Apache-2.0
"""Quarantine enforcement in the scan flow, against the real quarantine code.

Only the Docker/Trivy primitives are stubbed: image scans, container
digests, Caddy reload and compose stop.
"""
from __future__ import annotations

import pytest

from boxmunge.commands import security_scan_core, security_scan_inputs
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve import quarantine as q
from boxmunge.cve.scanner import ScannerError
from boxmunge.docker import DockerError
from tests.test_commands.cve_helpers import CRIT, make_box, scan_result, seed_quarantine


class Docker:
    """Records the Docker primitives the quarantine action calls.

    ``fail`` maps a primitive name to how many upcoming calls should raise.
    """

    def __init__(self, monkeypatch) -> None:
        self.calls: list[str] = []
        self.fail: dict[str, int] = {}
        for name in ("caddy_reload", "compose_stop"):
            monkeypatch.setattr(q, name, self._recorder(name))

    def _recorder(self, name: str):
        def call(*args, **kwargs):
            self.calls.append(name)
            if self.fail.get(name, 0) > 0:
                self.fail[name] -= 1
                raise DockerError(f"{name} timed out")
        return call


@pytest.fixture
def docker(monkeypatch):
    monkeypatch.setattr(security_scan_inputs, "container_image_digest", lambda c: None)
    monkeypatch.setattr(
        "boxmunge.cve.alerting.send_notification", lambda *a, **k: True,
    )
    return Docker(monkeypatch)


def _scan_returns(monkeypatch, findings):
    monkeypatch.setattr(
        security_scan_core, "scan_image",
        lambda ref, timeout: scan_result(ref, findings),
    )


@pytest.mark.parametrize("failing", ["compose_stop", "caddy_reload"])
def test_failed_quarantine_step_is_retried_until_complete(
    tmp_path, monkeypatch, docker, failing,
):
    """Audit B-03 script A: the step fails once; the next scan completes it."""
    paths = make_box(tmp_path)
    _scan_returns(monkeypatch, [CRIT])
    docker.fail[failing] = 1

    with pytest.raises(RuntimeError, match="quarantine action failed"):
        scan_one_project(paths, "demo", in_grace=False)
    assert q.is_quarantined("demo", paths)
    assert not q.quarantine_action_complete("demo", paths)

    scan_one_project(paths, "demo", in_grace=False)
    assert docker.calls.count("compose_stop") == (2 if failing == "compose_stop" else 1)
    assert q.quarantine_action_complete("demo", paths)


def test_quarantine_is_reasserted_even_when_findings_are_gone(
    tmp_path, monkeypatch, docker,
):
    """An incomplete quarantine converges whatever the new scan finds.

    Only `security resume` lifts a quarantine, so a clean scan must still
    finish stopping the project rather than leave it half-quarantined.
    """
    paths = make_box(tmp_path)
    seed_quarantine(paths, action_complete=False)
    _scan_returns(monkeypatch, [])
    scan_one_project(paths, "demo", in_grace=False)
    assert docker.calls == ["caddy_reload", "compose_stop"]
    assert q.quarantine_action_complete("demo", paths)


def test_quarantine_is_reasserted_when_every_image_fails(
    tmp_path, monkeypatch, docker,
):
    paths = make_box(tmp_path)
    seed_quarantine(paths, action_complete=False)

    def boom(ref, timeout):
        raise ScannerError("db unavailable")

    monkeypatch.setattr(security_scan_core, "scan_image", boom)
    with pytest.raises(RuntimeError, match="All images failed"):
        scan_one_project(paths, "demo", in_grace=False)
    assert docker.calls == ["caddy_reload", "compose_stop"]
    assert q.quarantine_action_complete("demo", paths)


def test_complete_quarantine_is_reasserted_to_undo_drift(tmp_path, monkeypatch, docker):
    """A container someone started behind the maintenance page is stopped."""
    paths = make_box(tmp_path)
    seed_quarantine(paths)
    _scan_returns(monkeypatch, [CRIT])
    scan_one_project(paths, "demo", in_grace=False)
    assert docker.calls == ["caddy_reload", "compose_stop"]


def test_legacy_record_without_flag_counts_as_incomplete(tmp_path):
    paths = make_box(tmp_path)
    seed_quarantine(paths)
    record = q.read_quarantine_state("demo", paths)
    record.pop("action_complete")
    q._write_record("demo", paths, record)
    assert not q.quarantine_action_complete("demo", paths)


def test_audit_only_scan_never_acts(tmp_path, monkeypatch, docker):
    paths = make_box(tmp_path)
    seed_quarantine(paths, action_complete=False)
    _scan_returns(monkeypatch, [CRIT])
    scan_one_project(paths, "demo", audit_only=True)
    assert docker.calls == []


def test_grace_reasserts_existing_quarantine_but_fires_no_new_one(
    tmp_path, monkeypatch, docker,
):
    paths = make_box(tmp_path, projects=("aaa", "bbb"))
    seed_quarantine(paths, "aaa", action_complete=False)
    _scan_returns(monkeypatch, [CRIT])
    scan_one_project(paths, "aaa", in_grace=True)
    scan_one_project(paths, "bbb", in_grace=True)
    assert q.quarantine_action_complete("aaa", paths)
    assert not q.is_quarantined("bbb", paths)

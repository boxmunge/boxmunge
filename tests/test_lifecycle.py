# SPDX-License-Identifier: Apache-2.0
"""Tests for boxmunge.lifecycle (Wave 1 of v0.7.2)."""
from __future__ import annotations

import re
from pathlib import Path

from boxmunge.cve.policy import Disposition, FindingDisposition
from boxmunge.cve.quarantine import write_quarantine_state
from boxmunge.cve.scanner import Finding, Severity
from boxmunge.lifecycle import Block, BlockReason, is_blocked
from boxmunge.pause import write_paused_state
from boxmunge.paths import BoxPaths


def _disposition(
    cve_id: str = "CVE-2026-9999",
    severity: Severity = Severity.CRITICAL,
) -> FindingDisposition:
    finding = Finding(
        cve_id=cve_id,
        severity=severity,
        package="openssl",
        installed_version="1.1.1k",
        fixed_version=None,
        title="critical openssl CVE",
        primary_url=None,
    )
    return FindingDisposition(
        finding=finding,
        base_severity=severity,
        hardening_penalty=0,
        effective_severity=severity,
        disposition=Disposition.QUARANTINE,
        suppression=None,
        explanation="critical CVE",
    )


def _quarantine(
    paths: BoxPaths, project: str, cve_id: str = "CVE-2026-9999",
) -> None:
    """Write a real quarantine state via the production helper."""
    write_quarantine_state(
        project, paths,
        headline=_disposition(cve_id=cve_id),
        image_ref="myimage:latest",
    )


class TestIsBlocked:
    def test_returns_none_when_running(self, paths: BoxPaths) -> None:
        """Fresh paths with neither state file → not blocked."""
        assert is_blocked("myapp", paths) is None

    def test_paused(self, paths: BoxPaths) -> None:
        """Paused project → Block with reason PAUSED."""
        write_paused_state("myapp", paths)
        block = is_blocked("myapp", paths)
        assert isinstance(block, Block)
        assert block.reason is BlockReason.PAUSED
        assert "paused" in block.refuse_message.lower()
        assert "boxmunge resume myapp" in block.refuse_message
        assert "paused" in block.skip_message.lower()
        assert "myapp" in block.skip_message
        # detail dict carries the paused_at timestamp.
        assert "paused_at" in block.detail

    def test_quarantined(self, paths: BoxPaths) -> None:
        """Quarantined project → Block with reason QUARANTINED."""
        _quarantine(paths, "myapp")
        block = is_blocked("myapp", paths)
        assert isinstance(block, Block)
        assert block.reason is BlockReason.QUARANTINED
        assert "quarantine" in block.refuse_message.lower()
        assert "security resume" in block.refuse_message
        assert "CVE-2026-9999" in block.refuse_message
        assert "security resume" in block.skip_message
        assert "myapp" in block.skip_message

    def test_quarantined_takes_precedence(self, paths: BoxPaths) -> None:
        """Both files exist → quarantine wins (more specific security action)."""
        write_paused_state("myapp", paths)
        _quarantine(paths, "myapp")
        block = is_blocked("myapp", paths)
        assert isinstance(block, Block)
        assert block.reason is BlockReason.QUARANTINED

    def test_quarantined_detail_carries_state(self, paths: BoxPaths) -> None:
        """detail dict includes cve_id, severity, image_ref from state file."""
        _quarantine(paths, "myapp")
        block = is_blocked("myapp", paths)
        assert isinstance(block, Block)
        assert block.detail["cve_id"] == "CVE-2026-9999"
        # Severity stored as the enum's `.value` (e.g. "Critical").
        assert block.detail["severity"] == "Critical"
        assert block.detail["image_ref"] == "myimage:latest"


class TestComposeUpCallersUseIsBlocked:
    """Static lint test catching future drift.

    Every site calling compose_up / compose_pull should consult
    is_blocked() (or have a documented exemption). Catches the
    'forgot to check state file' bug that motivated v0.7.0 wave 1.
    """

    def test_compose_up_callers_use_is_blocked(self) -> None:
        src_root = Path(__file__).parent.parent / "src" / "boxmunge"
        callers = []
        for py in src_root.rglob("*.py"):
            text = py.read_text()
            if (
                re.search(r"\bcompose_up\(", text)
                or re.search(r"\bcompose_pull\(", text)
            ):
                callers.append(py)

        # Files that call compose_up/compose_pull directly. They must
        # either call is_blocked() OR be explicitly exempt.
        EXEMPT = {
            # The action itself: stops AND restarts as part of the
            # quarantine/lift flow; gating on is_blocked here would
            # prevent lift_quarantine from ever running.
            "boxmunge/cve/quarantine.py",
            # Wrapper module — defines compose_up/compose_pull.
            "boxmunge/docker.py",
        }

        missing: list[str] = []
        for caller in callers:
            rel = str(caller.relative_to(src_root.parent))
            normalized = rel.replace("src/", "")
            if normalized in EXEMPT:
                continue
            text = caller.read_text()
            if "is_blocked" not in text:
                missing.append(rel)

        assert not missing, (
            "compose_up/compose_pull callers missing is_blocked() "
            f"guard:\n  {chr(10).join(missing)}\n"
            "Add to EXEMPT in this test if intentional."
        )

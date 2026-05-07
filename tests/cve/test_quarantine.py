"""Tests for boxmunge.cve.quarantine — quarantine action module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.cve.policy import (
    Disposition,
    FindingDisposition,
)
from boxmunge.cve.scanner import Finding, Severity
from boxmunge.cve.quarantine import (
    QuarantineError,
    clear_quarantine_state,
    is_quarantined,
    lift_quarantine,
    quarantine_project,
    read_quarantine_state,
    write_quarantine_state,
)
from boxmunge.docker import DockerError
from boxmunge.paths import BoxPaths


# ---------- helpers ----------


def _setup_paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    paths.caddy_sites.mkdir(parents=True, exist_ok=True)
    return paths


def _disposition(
    *,
    cve_id: str = "CVE-2026-1234",
    base: Severity = Severity.CRITICAL,
    effective: Severity = Severity.CRITICAL,
    explanation: str = (
        "Critical, no upstream fix, exceeds balanced threshold — quarantine."
    ),
    penalty: int = 0,
) -> FindingDisposition:
    finding = Finding(
        cve_id=cve_id,
        severity=base,
        package="openssl",
        installed_version="1.1.1k",
        fixed_version=None,
        title="Some critical CVE",
        primary_url=None,
    )
    return FindingDisposition(
        finding=finding,
        base_severity=base,
        hardening_penalty=penalty,
        effective_severity=effective,
        disposition=Disposition.QUARANTINE,
        suppression=None,
        explanation=explanation,
    )


# ---------- state management ----------


class TestStateManagement:
    def test_is_quarantined_false_when_no_state(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        assert is_quarantined("myapp", paths) is False

    def test_is_quarantined_true_after_write(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(),
            image_ref="myapp:1.2.3",
        )
        assert is_quarantined("myapp", paths) is True

    def test_read_quarantine_state_none_when_missing(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        assert read_quarantine_state("myapp", paths) is None

    def test_write_quarantine_state_records_all_fields(
        self, tmp_path: Path,
    ) -> None:
        paths = _setup_paths(tmp_path)
        headline = _disposition(
            cve_id="CVE-2026-1234",
            base=Severity.HIGH,
            effective=Severity.CRITICAL,
            explanation="High elevated to Critical via penalty.",
        )
        write_quarantine_state(
            "myapp", paths,
            headline=headline,
            image_ref="myapp:1.2.3",
        )
        data = json.loads(
            paths.project_quarantine_state("myapp").read_text(),
        )
        assert data["cve_id"] == "CVE-2026-1234"
        assert data["severity"] == "High"
        assert data["effective_severity"] == "Critical"
        assert data["explanation"] == "High elevated to Critical via penalty."
        assert data["image_ref"] == "myapp:1.2.3"
        assert "quarantined_at" in data
        # ISO 8601-ish: contains a 'T' separator and a timezone marker.
        assert "T" in data["quarantined_at"]
        assert any(c in data["quarantined_at"] for c in ("Z", "+", "-"))

    def test_write_quarantine_state_overwrites(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(cve_id="CVE-2026-0001"),
            image_ref="myapp:1.2.3",
        )
        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(cve_id="CVE-2026-9999"),
            image_ref="myapp:1.2.4",
        )
        data = json.loads(
            paths.project_quarantine_state("myapp").read_text(),
        )
        assert data["cve_id"] == "CVE-2026-9999"
        assert data["image_ref"] == "myapp:1.2.4"

    def test_clear_quarantine_state_idempotent(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        # Should not raise.
        clear_quarantine_state("myapp", paths)

    def test_clear_quarantine_state_removes_file(
        self, tmp_path: Path,
    ) -> None:
        paths = _setup_paths(tmp_path)
        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(),
            image_ref="myapp:1.2.3",
        )
        assert is_quarantined("myapp", paths)
        clear_quarantine_state("myapp", paths)
        assert not is_quarantined("myapp", paths)
        assert not paths.project_quarantine_state("myapp").exists()

    def test_read_quarantine_state_returns_dict(
        self, tmp_path: Path,
    ) -> None:
        paths = _setup_paths(tmp_path)
        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(cve_id="CVE-2026-0001"),
            image_ref="myapp:1.2.3",
        )
        data = read_quarantine_state("myapp", paths)
        assert isinstance(data, dict)
        assert data["cve_id"] == "CVE-2026-0001"


# ---------- quarantine_project happy path ----------


class TestQuarantineProjectHappyPath:
    def test_writes_state_caddy_and_stops(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        call_order: list[str] = []

        def _record_state_write(*args, **kwargs):
            # Capture only the quarantine state file write — not the caddy
            # site write — so we can verify ordering relative to the others.
            path = args[0]
            if str(path).endswith(".quarantined.json"):
                call_order.append("state")
            elif "sites" in str(path):
                call_order.append("caddy_site")

        # Patch atomic_write_text in the quarantine module so both writes go
        # through the same observable hook.
        with patch(
            "boxmunge.cve.quarantine.atomic_write_text",
            side_effect=_record_state_write,
        ), patch(
            "boxmunge.cve.quarantine.caddy_reload",
            side_effect=lambda *a, **kw: call_order.append("caddy_reload"),
        ), patch(
            "boxmunge.cve.quarantine.compose_stop",
            side_effect=lambda *a, **kw: call_order.append("compose_stop"),
        ):
            quarantine_project(
                "myapp", paths,
                project_dir=project_dir,
                hosts=["a.example.com"],
                compose_files=["compose.yml"],
                headline=_disposition(),
                image_ref="myapp:1.2.3",
            )

        assert call_order == [
            "state", "caddy_site", "caddy_reload", "compose_stop",
        ]

    def test_caddy_site_is_maintenance_html(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        captured: dict[str, str] = {}

        def _capture(path: Path, content: str, *args, **kwargs) -> None:
            if str(path).endswith(".conf"):
                captured["caddy"] = content
            # State writes still need to happen; do them directly via fileutil.
            elif str(path).endswith(".quarantined.json"):
                path.write_text(content)

        with patch(
            "boxmunge.cve.quarantine.atomic_write_text",
            side_effect=_capture,
        ), patch(
            "boxmunge.cve.quarantine.caddy_reload",
        ), patch(
            "boxmunge.cve.quarantine.compose_stop",
        ):
            quarantine_project(
                "myapp", paths,
                project_dir=project_dir,
                hosts=["a.example.com"],
                compose_files=["compose.yml"],
                headline=_disposition(),
                image_ref="myapp:1.2.3",
            )

        body = captured["caddy"]
        assert "a.example.com" in body
        assert "503" in body
        assert "file_server" in body
        assert "handle" in body

    def test_state_records_headline_correctly(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        with patch(
            "boxmunge.cve.quarantine.caddy_reload",
        ), patch(
            "boxmunge.cve.quarantine.compose_stop",
        ):
            quarantine_project(
                "myapp", paths,
                project_dir=project_dir,
                hosts=["a.example.com"],
                compose_files=["compose.yml"],
                headline=_disposition(
                    cve_id="CVE-2026-1234",
                    base=Severity.CRITICAL,
                    effective=Severity.CRITICAL,
                    explanation="Critical, no upstream fix — quarantine.",
                ),
                image_ref="myapp:1.2.3",
            )

        data = json.loads(
            paths.project_quarantine_state("myapp").read_text(),
        )
        assert data["cve_id"] == "CVE-2026-1234"
        assert data["severity"] == "Critical"
        assert data["effective_severity"] == "Critical"
        assert data["explanation"] == "Critical, no upstream fix — quarantine."
        assert data["image_ref"] == "myapp:1.2.3"


# ---------- quarantine_project failure modes ----------


class TestQuarantineProjectFailures:
    def test_caddy_swap_failure_keeps_state(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        with patch(
            "boxmunge.cve.quarantine.caddy_reload",
            side_effect=DockerError("caddy reload failed"),
        ), patch(
            "boxmunge.cve.quarantine.compose_stop",
        ):
            with pytest.raises(QuarantineError):
                quarantine_project(
                    "myapp", paths,
                    project_dir=project_dir,
                    hosts=["a.example.com"],
                    compose_files=["compose.yml"],
                    headline=_disposition(),
                    image_ref="myapp:1.2.3",
                )

        assert is_quarantined("myapp", paths)

    def test_compose_stop_failure_keeps_state(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        with patch(
            "boxmunge.cve.quarantine.caddy_reload",
        ), patch(
            "boxmunge.cve.quarantine.compose_stop",
            side_effect=DockerError("compose stop failed"),
        ):
            with pytest.raises(QuarantineError):
                quarantine_project(
                    "myapp", paths,
                    project_dir=project_dir,
                    hosts=["a.example.com"],
                    compose_files=["compose.yml"],
                    headline=_disposition(),
                    image_ref="myapp:1.2.3",
                )

        assert is_quarantined("myapp", paths)

    def test_idempotent_when_already_quarantined(
        self, tmp_path: Path,
    ) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        with patch(
            "boxmunge.cve.quarantine.caddy_reload",
        ), patch(
            "boxmunge.cve.quarantine.compose_stop",
        ):
            quarantine_project(
                "myapp", paths,
                project_dir=project_dir,
                hosts=["a.example.com"],
                compose_files=["compose.yml"],
                headline=_disposition(cve_id="CVE-2026-0001"),
                image_ref="myapp:1.2.3",
            )
            # Second call should not raise.
            quarantine_project(
                "myapp", paths,
                project_dir=project_dir,
                hosts=["a.example.com"],
                compose_files=["compose.yml"],
                headline=_disposition(cve_id="CVE-2026-9999"),
                image_ref="myapp:1.2.4",
            )

        data = json.loads(
            paths.project_quarantine_state("myapp").read_text(),
        )
        assert data["cve_id"] == "CVE-2026-9999"
        assert data["image_ref"] == "myapp:1.2.4"


# ---------- lift_quarantine happy path ----------


class TestLiftQuarantineHappyPath:
    def test_restores_caddy_starts_compose_clears_state(
        self, tmp_path: Path,
    ) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        # Pre-quarantine the project.
        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(),
            image_ref="myapp:1.2.3",
        )

        call_order: list[str] = []
        captured: dict[str, str] = {}

        def _record_write(path: Path, content: str, *args, **kwargs) -> None:
            if str(path).endswith(".conf"):
                call_order.append("caddy_site")
                captured["caddy"] = content

        with patch(
            "boxmunge.cve.quarantine.atomic_write_text",
            side_effect=_record_write,
        ), patch(
            "boxmunge.cve.quarantine.caddy_reload",
            side_effect=lambda *a, **kw: call_order.append("caddy_reload"),
        ), patch(
            "boxmunge.cve.quarantine.compose_up",
            side_effect=lambda *a, **kw: call_order.append("compose_up"),
        ):
            lift_quarantine(
                "myapp", paths,
                project_dir=project_dir,
                project_caddy_site_content="NORMAL CADDY CONFIG",
                compose_files=["compose.yml"],
            )

        assert call_order == [
            "caddy_site", "caddy_reload", "compose_up",
        ]
        assert captured["caddy"] == "NORMAL CADDY CONFIG"
        assert not is_quarantined("myapp", paths)

    def test_state_cleared_only_after_compose_up(
        self, tmp_path: Path,
    ) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(),
            image_ref="myapp:1.2.3",
        )

        # Capture state existence at the moment of compose_up.
        state_existed_during_compose: list[bool] = []

        def _check_state(*args, **kwargs) -> None:
            state_existed_during_compose.append(
                paths.project_quarantine_state("myapp").exists(),
            )

        with patch(
            "boxmunge.cve.quarantine.caddy_reload",
        ), patch(
            "boxmunge.cve.quarantine.compose_up",
            side_effect=_check_state,
        ):
            lift_quarantine(
                "myapp", paths,
                project_dir=project_dir,
                project_caddy_site_content="NORMAL",
                compose_files=["compose.yml"],
            )

        assert state_existed_during_compose == [True]
        # And after the call, the state file is gone.
        assert not is_quarantined("myapp", paths)


# ---------- lift_quarantine failure modes ----------


class TestLiftQuarantineFailures:
    def test_compose_up_failure_keeps_state(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(),
            image_ref="myapp:1.2.3",
        )

        with patch(
            "boxmunge.cve.quarantine.caddy_reload",
        ), patch(
            "boxmunge.cve.quarantine.compose_up",
            side_effect=DockerError("compose up failed"),
        ):
            with pytest.raises(QuarantineError):
                lift_quarantine(
                    "myapp", paths,
                    project_dir=project_dir,
                    project_caddy_site_content="NORMAL",
                    compose_files=["compose.yml"],
                )

        assert is_quarantined("myapp", paths)

    def test_idempotent_when_not_quarantined(self, tmp_path: Path) -> None:
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        # Not quarantined → no-op, no error, no subprocess calls.
        with patch(
            "boxmunge.cve.quarantine.caddy_reload",
        ) as mock_reload, patch(
            "boxmunge.cve.quarantine.compose_up",
        ) as mock_up:
            lift_quarantine(
                "myapp", paths,
                project_dir=project_dir,
                project_caddy_site_content="NORMAL",
                compose_files=["compose.yml"],
            )
            mock_reload.assert_not_called()
            mock_up.assert_not_called()


# ---------- structured-extras (audit A-1) ----------


class TestStructuredLogging:
    """Wave 3: cve/quarantine.py info events must carry component=
    'cve-quarantine' and the correct project so `boxmunge log` finds them."""

    def test_quarantine_firing_log_carries_component_and_project(
        self, tmp_path: Path,
    ) -> None:
        import logging as _logging
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)

        records: list = []

        class _ListHandler(_logging.Handler):
            def emit(self, record):  # type: ignore[override]
                records.append(record)

        h = _ListHandler(level=_logging.INFO)
        logger = _logging.getLogger("boxmunge")
        saved_level = logger.level
        logger.setLevel(_logging.INFO)
        logger.addHandler(h)
        try:
            with patch(
                "boxmunge.cve.quarantine.atomic_write_text",
            ), patch(
                "boxmunge.cve.quarantine.caddy_reload",
            ), patch(
                "boxmunge.cve.quarantine.compose_stop",
            ):
                quarantine_project(
                    "myapp", paths,
                    project_dir=project_dir,
                    hosts=["a.example.com"],
                    compose_files=["compose.yml"],
                    headline=_disposition(cve_id="CVE-2026-7777"),
                    image_ref="myapp:1.2.3",
                )
        finally:
            logger.removeHandler(h)
            logger.setLevel(saved_level)

        # Two info records: "firing on..." and "now offline...".
        component_records = [
            r for r in records
            if getattr(r, "component", None) == "cve-quarantine"
        ]
        assert len(component_records) >= 2
        # Every one of those records carries the project name.
        for r in component_records:
            assert getattr(r, "project", None) == "myapp"
        # The "firing" record has cve_id in its detail.
        firing = [
            r for r in component_records
            if "firing on" in r.getMessage()
        ]
        assert len(firing) == 1
        detail = getattr(firing[0], "detail", None)
        assert isinstance(detail, dict)
        assert detail.get("cve_id") == "CVE-2026-7777"
        assert detail.get("image_ref") == "myapp:1.2.3"

    def test_lift_logs_carry_component_and_project(
        self, tmp_path: Path,
    ) -> None:
        import logging as _logging
        paths = _setup_paths(tmp_path)
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)
        write_quarantine_state(
            "myapp", paths,
            headline=_disposition(),
            image_ref="myapp:1.2.3",
        )

        records: list = []

        class _ListHandler(_logging.Handler):
            def emit(self, record):  # type: ignore[override]
                records.append(record)

        h = _ListHandler(level=_logging.INFO)
        logger = _logging.getLogger("boxmunge")
        saved_level = logger.level
        logger.setLevel(_logging.INFO)
        logger.addHandler(h)
        try:
            with patch(
                "boxmunge.cve.quarantine.atomic_write_text",
            ), patch(
                "boxmunge.cve.quarantine.caddy_reload",
            ), patch(
                "boxmunge.cve.quarantine.compose_up",
            ):
                lift_quarantine(
                    "myapp", paths,
                    project_dir=project_dir,
                    project_caddy_site_content="NORMAL",
                    compose_files=["compose.yml"],
                )
        finally:
            logger.removeHandler(h)
            logger.setLevel(saved_level)

        component_records = [
            r for r in records
            if getattr(r, "component", None) == "cve-quarantine"
        ]
        assert component_records, "expected cve-quarantine log records"
        for r in component_records:
            assert getattr(r, "project", None) == "myapp"

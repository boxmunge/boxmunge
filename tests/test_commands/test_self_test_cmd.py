"""Tests for boxmunge self-test command (unit tests, no Docker)."""

import json
from pathlib import Path

import pytest

from boxmunge.commands.self_test_cmd import SelfTestStep, SelfTestReport, _canary_project_path


class TestCanaryProjectPath:
    def test_returns_path_with_canary_name(self) -> None:
        path = _canary_project_path()
        assert path.name == "canary"


class TestSelfTestReport:
    def test_all_passed(self) -> None:
        report = SelfTestReport(steps=[
            SelfTestStep("deploy", True, ""),
            SelfTestStep("backup", True, ""),
        ])
        assert report.success is True
        assert report.exit_code == 0

    def test_any_failure(self) -> None:
        report = SelfTestReport(steps=[
            SelfTestStep("deploy", True, ""),
            SelfTestStep("backup", False, "age key missing"),
        ])
        assert report.success is False
        assert report.exit_code == 1

    def test_report_text(self) -> None:
        report = SelfTestReport(steps=[
            SelfTestStep("deploy", True, ""),
            SelfTestStep("backup", False, "failed"),
        ])
        text = report.format_text()
        assert "PASS" in text
        assert "FAIL" in text
        assert "backup" in text

    def test_report_json(self) -> None:
        report = SelfTestReport(steps=[
            SelfTestStep("deploy", True, "ok"),
        ])
        data = json.loads(report.format_json())
        assert data["success"] is True
        assert data["steps"][0]["name"] == "deploy"
        assert data["steps"][0]["passed"] is True

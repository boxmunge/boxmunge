# SPDX-License-Identifier: Apache-2.0
"""Tests for boxmunge.cve.alerting — formatters, transitions, delivery."""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Any

import pytest

from boxmunge.cve.alerting import (
    Alert,
    detect_transitions,
    emit_scan_alerts,
    format_grace_heads_up_alert,
    format_informational_alert,
    format_quarantine_alert,
    format_still_running_alert,
    format_suppression_expired_alert,
    send_alerts,
)
from boxmunge.cve.policy import (
    Disposition,
    FindingDisposition,
    ProjectDecision,
)
from boxmunge.cve.scanner import Finding, Severity
from boxmunge.cve.suppressions import Suppression
from boxmunge.paths import BoxPaths


# ---------- helpers ----------


def _finding(
    cve_id: str = "CVE-2026-0001",
    severity: Severity = Severity.HIGH,
    fixed_version: str | None = None,
) -> Finding:
    return Finding(
        cve_id=cve_id,
        severity=severity,
        package="openssl",
        installed_version="1.1.1k",
        fixed_version=fixed_version,
        title="Title",
        primary_url=None,
    )


def _disp(
    cve_id: str = "CVE-2026-0001",
    *,
    base: Severity = Severity.HIGH,
    effective: Severity | None = None,
    disposition: Disposition = Disposition.QUARANTINE,
    penalty: int = 0,
) -> FindingDisposition:
    eff = effective if effective is not None else base
    return FindingDisposition(
        finding=_finding(cve_id=cve_id, severity=base),
        base_severity=base,
        hardening_penalty=penalty,
        effective_severity=eff,
        disposition=disposition,
        suppression=None,
        explanation="explained",
    )


def _decision(
    *findings: FindingDisposition,
    project: str = "demo",
    image: str = "myapp:1.0",
    when: datetime | None = None,
) -> ProjectDecision:
    when = when or datetime(2026, 5, 6, tzinfo=timezone.utc)
    quarantine = any(d.disposition == Disposition.QUARANTINE for d in findings)
    at_risk = any(
        d.disposition == Disposition.STILL_RUNNING_AT_RISK for d in findings
    )
    return ProjectDecision(
        project_name=project,
        image_ref=image,
        findings=tuple(findings),
        quarantine_required=quarantine,
        at_risk_running=at_risk,
        scanned_at=when,
    )


def _suppression(
    cve_id: str = "CVE-2026-0001",
    until: date = date(2026, 8, 1),
    added: date = date(2026, 5, 6),
) -> Suppression:
    return Suppression(
        cve_id=cve_id,
        until=until,
        reason="reviewed",
        reviewed_by="ops",
        added=added,
    )


# ---------- formatters ----------


def test_format_quarantine_alert_shape() -> None:
    fd = _disp("CVE-2026-1111", base=Severity.CRITICAL,
               disposition=Disposition.QUARANTINE)
    pd = _decision(fd)
    alert = format_quarantine_alert(pd, fd)
    assert alert.kind == "quarantine"
    assert alert.priority == 1
    assert alert.title == "[boxmunge:demo] QUARANTINED — CVE-2026-1111 (Critical)"
    assert "Project: demo" in alert.body
    assert "CVE-2026-1111 (Critical, no upstream fix)" in alert.body
    assert "Image: myapp:1.0" in alert.body
    assert "Service stopped, maintenance page active." in alert.body
    assert "boxmunge security resume demo" in alert.body


def test_format_still_running_alert_shape() -> None:
    fd = _disp("CVE-2026-2222", base=Severity.HIGH,
               disposition=Disposition.STILL_RUNNING_AT_RISK)
    pd = _decision(fd)
    alert = format_still_running_alert(pd, fd)
    assert alert.kind == "still_running"
    assert alert.priority == 1
    assert alert.title == "[boxmunge:demo] [STILL RUNNING] CVE-2026-2222 (High)"
    assert "QUARANTINE DISABLED BY CONFIG" in alert.body
    assert "dangerously_disable_quarantine" in alert.body
    assert "boxmunge security suppress CVE-2026-2222" in alert.body


def test_format_informational_alert_shape_no_penalty() -> None:
    fd = _disp("CVE-2026-3333", base=Severity.LOW, effective=Severity.LOW,
               disposition=Disposition.INFORMATIONAL, penalty=0)
    pd = _decision(fd)
    alert = format_informational_alert(pd, fd, posture="balanced")
    assert alert.kind == "informational"
    assert alert.priority == 0
    assert alert.title == "[boxmunge:demo] CVE-2026-3333 (Low)"
    assert "Severity: Low" in alert.body
    assert "Below quarantine threshold (balanced posture)" in alert.body
    # No elevation: no arrow
    assert "→" not in alert.body


def test_format_informational_alert_shape_with_penalty() -> None:
    fd = _disp("CVE-2026-3334", base=Severity.LOW, effective=Severity.MEDIUM,
               disposition=Disposition.INFORMATIONAL, penalty=1)
    pd = _decision(fd)
    alert = format_informational_alert(pd, fd, posture="strict")
    assert "Severity: Low → effective Medium via penalty +1" in alert.body
    assert "Below quarantine threshold (strict posture)" in alert.body


def test_format_suppression_expired_alert_shape() -> None:
    sup = _suppression("CVE-2026-7777", until=date(2026, 8, 1),
                       added=date(2026, 5, 1))
    alert = format_suppression_expired_alert("demo", sup)
    assert alert.kind == "suppression_expired"
    assert alert.priority == 1
    assert alert.title == "[boxmunge:demo] Suppression expired — CVE-2026-7777"
    assert "Suppression added: 2026-05-01" in alert.body
    assert "Suppression expired: 2026-08-01" in alert.body
    assert "Quarantine queued for next scan." in alert.body
    assert "boxmunge security suppress CVE-2026-7777 --project demo" in alert.body


# ---------- detect_transitions ----------


def test_first_scan_quarantine_finding_emits_quarantine_alert() -> None:
    fd = _disp(disposition=Disposition.QUARANTINE)
    current = _decision(fd)
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=None, suppressions=(),
    )
    assert len(alerts) == 1
    assert alerts[0].kind == "quarantine"


def test_first_scan_at_risk_finding_emits_still_running_alert() -> None:
    fd = _disp(disposition=Disposition.STILL_RUNNING_AT_RISK)
    current = _decision(fd)
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=None, suppressions=(),
    )
    assert len(alerts) == 1
    assert alerts[0].kind == "still_running"


def test_first_scan_informational_emits_informational_alert() -> None:
    fd = _disp(base=Severity.LOW, effective=Severity.LOW,
               disposition=Disposition.INFORMATIONAL)
    current = _decision(fd)
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=None, suppressions=(),
    )
    assert len(alerts) == 1
    assert alerts[0].kind == "informational"


def test_persisting_quarantine_no_alert() -> None:
    fd = _disp(disposition=Disposition.QUARANTINE)
    prior = _decision(fd, when=datetime(2026, 5, 5, tzinfo=timezone.utc))
    current = _decision(fd, when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(),
    )
    assert alerts == ()


def test_persisting_informational_no_alert() -> None:
    fd = _disp(base=Severity.LOW, effective=Severity.LOW,
               disposition=Disposition.INFORMATIONAL)
    prior = _decision(fd, when=datetime(2026, 5, 5, tzinfo=timezone.utc))
    current = _decision(fd, when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(),
    )
    assert alerts == ()


def test_at_risk_to_quarantine_emits_quarantine_alert() -> None:
    """Operator turned off dangerously_disable_quarantine."""
    prior_fd = _disp(disposition=Disposition.STILL_RUNNING_AT_RISK)
    current_fd = _disp(disposition=Disposition.QUARANTINE)
    prior = _decision(prior_fd, when=datetime(2026, 5, 5, tzinfo=timezone.utc))
    current = _decision(current_fd, when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(),
    )
    assert len(alerts) == 1
    assert alerts[0].kind == "quarantine"


def test_quarantine_to_at_risk_emits_still_running_alert() -> None:
    """Operator enabled dangerously_disable_quarantine."""
    prior_fd = _disp(disposition=Disposition.QUARANTINE)
    current_fd = _disp(disposition=Disposition.STILL_RUNNING_AT_RISK)
    prior = _decision(prior_fd, when=datetime(2026, 5, 5, tzinfo=timezone.utc))
    current = _decision(current_fd, when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(),
    )
    assert len(alerts) == 1
    assert alerts[0].kind == "still_running"


def test_resolved_finding_no_alert() -> None:
    """Finding QUARANTINE in prior, gone in current → 0 alerts (good news)."""
    prior_fd = _disp("CVE-2026-9999", disposition=Disposition.QUARANTINE)
    prior = _decision(prior_fd, when=datetime(2026, 5, 5, tzinfo=timezone.utc))
    current = _decision(when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(),
    )
    assert alerts == ()


def test_new_finding_quarantine_emits_alert() -> None:
    prior_fd = _disp("CVE-2026-0001", disposition=Disposition.QUARANTINE)
    current_old = _disp("CVE-2026-0001", disposition=Disposition.QUARANTINE)
    current_new = _disp("CVE-2026-0002", disposition=Disposition.QUARANTINE)
    prior = _decision(prior_fd, when=datetime(2026, 5, 5, tzinfo=timezone.utc))
    current = _decision(current_old, current_new,
                        when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(),
    )
    assert len(alerts) == 1
    assert alerts[0].kind == "quarantine"
    assert "CVE-2026-0002" in alerts[0].title


def test_suppression_expired_between_scans() -> None:
    sup = _suppression("CVE-2026-5555", until=date(2026, 8, 1),
                       added=date(2026, 5, 1))
    fd = _disp("CVE-2026-OTHER", disposition=Disposition.QUARANTINE)
    prior = _decision(fd, when=datetime(2026, 7, 31, tzinfo=timezone.utc))
    current = _decision(fd, when=datetime(2026, 8, 2, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(sup,),
    )
    expired = [a for a in alerts if a.kind == "suppression_expired"]
    assert len(expired) == 1
    assert "CVE-2026-5555" in expired[0].title


def test_suppression_active_no_alert() -> None:
    sup = _suppression("CVE-2026-5555", until=date(2027, 1, 1),
                       added=date(2026, 5, 1))
    fd = _disp("CVE-2026-OTHER", disposition=Disposition.QUARANTINE)
    prior = _decision(fd, when=datetime(2026, 7, 31, tzinfo=timezone.utc))
    current = _decision(fd, when=datetime(2026, 8, 2, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(sup,),
    )
    expired = [a for a in alerts if a.kind == "suppression_expired"]
    assert expired == []


def test_multiple_alerts_ordering_quarantine_first() -> None:
    """Mix of all categories emits in order: quarantine, still_running,
    suppression_expired, informational."""
    sup = _suppression("CVE-2026-9999", until=date(2026, 8, 1),
                       added=date(2026, 5, 1))
    quarantine_fd = _disp("CVE-2026-AAAA", disposition=Disposition.QUARANTINE)
    at_risk_fd = _disp("CVE-2026-BBBB",
                       disposition=Disposition.STILL_RUNNING_AT_RISK)
    info_fd = _disp("CVE-2026-CCCC", base=Severity.LOW, effective=Severity.LOW,
                    disposition=Disposition.INFORMATIONAL)
    current = _decision(quarantine_fd, at_risk_fd, info_fd,
                        when=datetime(2026, 8, 2, tzinfo=timezone.utc))
    prior = _decision(when=datetime(2026, 7, 31, tzinfo=timezone.utc))
    alerts = detect_transitions(
        project_name="demo", posture="balanced",
        current=current, prior=prior, suppressions=(sup,),
    )
    kinds = [a.kind for a in alerts]
    assert kinds == [
        "quarantine", "still_running", "suppression_expired", "informational",
    ]


# ---------- send_alerts ----------


def _fresh_paths(tmp_path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path)
    paths.config.mkdir(parents=True, exist_ok=True)
    return paths


def _write_config(paths: BoxPaths, *, user_key: str, app_token: str) -> None:
    import yaml
    cfg = {
        "hostname": "host.example.com",
        "admin_email": "a@example.com",
        "pushover": {"user_key": user_key, "app_token": app_token},
    }
    paths.config_file.write_text(yaml.safe_dump(cfg))


def test_send_alerts_no_pushover_config_logs_warning_returns_zero(
    tmp_path, caplog,
) -> None:
    paths = _fresh_paths(tmp_path)
    _write_config(paths, user_key="", app_token="")
    alert = Alert(
        kind="quarantine", title="t", body="b", priority=1,
    )
    caplog.set_level(logging.WARNING, logger="boxmunge")
    sent = send_alerts((alert,), paths)
    assert sent == 0
    assert "alerts skipped, pushover not configured" in caplog.text
    # Wave 3 / audit A-1: warnings carry component='cve-alert' so
    # `boxmunge log --component cve-alert` finds them.
    matching = [
        r for r in caplog.records
        if getattr(r, "component", None) == "cve-alert"
    ]
    assert matching, "expected at least one record with component='cve-alert'"


def test_send_alerts_calls_send_notification_per_alert(
    monkeypatch, tmp_path,
) -> None:
    paths = _fresh_paths(tmp_path)
    _write_config(paths, user_key="u", app_token="a")
    calls: list[tuple[Any, ...]] = []
    def fake_send(user, token, title, message, priority=0):
        calls.append((user, token, title, message, priority))
        return True
    monkeypatch.setattr("boxmunge.cve.alerting.send_notification", fake_send)
    alerts = (
        Alert(kind="quarantine", title="t1", body="b1", priority=1),
        Alert(kind="still_running", title="t2", body="b2", priority=1),
        Alert(kind="informational", title="t3", body="b3", priority=0),
    )
    sent = send_alerts(alerts, paths)
    assert sent == 3
    assert len(calls) == 3
    assert calls[0] == ("u", "a", "t1", "b1", 1)
    assert calls[2] == ("u", "a", "t3", "b3", 0)


def test_send_alerts_continues_on_failure(monkeypatch, tmp_path, caplog) -> None:
    paths = _fresh_paths(tmp_path)
    _write_config(paths, user_key="u", app_token="a")
    seq = iter([True, False, True])
    def fake_send(*args, **kwargs):
        return next(seq)
    monkeypatch.setattr("boxmunge.cve.alerting.send_notification", fake_send)
    alerts = (
        Alert(kind="quarantine", title="t1", body="b1", priority=1),
        Alert(kind="quarantine", title="t2", body="b2", priority=1),
        Alert(kind="quarantine", title="t3", body="b3", priority=1),
    )
    caplog.set_level(logging.WARNING, logger="boxmunge")
    sent = send_alerts(alerts, paths)
    assert sent == 2
    assert "pushover send failed" in caplog.text
    assert "t2" in caplog.text
    # Wave 3 / audit A-1: send-failure warnings carry component='cve-alert'.
    matching = [
        r for r in caplog.records
        if getattr(r, "component", None) == "cve-alert"
        and "pushover send failed" in r.getMessage()
    ]
    assert matching, "expected pushover-send-failed record with cve-alert"


# ---------- emit_scan_alerts ----------


def test_emit_scan_alerts_integration(monkeypatch, tmp_path) -> None:
    paths = _fresh_paths(tmp_path)
    _write_config(paths, user_key="u", app_token="a")
    sent_titles: list[str] = []
    def fake_send(user, token, title, message, priority=0):
        sent_titles.append(title)
        return True
    monkeypatch.setattr("boxmunge.cve.alerting.send_notification", fake_send)

    fd = _disp("CVE-2026-9999", base=Severity.CRITICAL,
               effective=Severity.CRITICAL,
               disposition=Disposition.QUARANTINE)
    current = _decision(fd, when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    sent = emit_scan_alerts(
        project_name="demo", posture="balanced",
        current=current, prior=None, suppressions=(),
        paths=paths,
    )
    assert sent == 1
    assert any("CVE-2026-9999" in t for t in sent_titles)


# ---------- grace heads-up ----------


def test_format_grace_heads_up_alert_lists_quarantine_projects() -> None:
    fd = _disp(
        "CVE-2026-5678", base=Severity.CRITICAL,
        disposition=Disposition.QUARANTINE,
    )
    decision = _decision(fd, project="auth-svc", image="auth:1.0")
    alert = format_grace_heads_up_alert(
        expires_at=datetime(2026, 5, 7, 12, tzinfo=timezone.utc),
        decisions_by_project={"auth-svc": decision},
        posture_by_project={"auth-svc": "balanced"},
        dangerously_by_project={"auth-svc": False},
    )
    assert alert.kind == "grace_heads_up"
    assert "Would quarantine after grace ends" in alert.body
    assert "auth-svc" in alert.body
    assert "CVE-2026-5678" in alert.body
    assert "posture: balanced" in alert.body


def test_format_grace_heads_up_alert_lists_at_risk_running_projects() -> None:
    fd = _disp(
        "CVE-2026-9999", base=Severity.CRITICAL,
        disposition=Disposition.STILL_RUNNING_AT_RISK,
    )
    decision = _decision(fd, project="weather-app", image="weather:1.0")
    alert = format_grace_heads_up_alert(
        expires_at=datetime(2026, 5, 7, 12, tzinfo=timezone.utc),
        decisions_by_project={"weather-app": decision},
        posture_by_project={"weather-app": "balanced"},
        dangerously_by_project={"weather-app": True},
    )
    assert "At-risk-running" in alert.body
    assert "weather-app" in alert.body
    assert "CVE-2026-9999" in alert.body


def test_format_grace_heads_up_alert_omits_empty_sections() -> None:
    """When no project would quarantine, no quarantine bullet list shown."""
    info = _disp(
        "CVE-2026-1234", base=Severity.LOW, effective=Severity.LOW,
        disposition=Disposition.INFORMATIONAL,
    )
    decision = _decision(info, project="clean-svc", image="clean:1.0")
    alert = format_grace_heads_up_alert(
        expires_at=datetime(2026, 5, 7, 12, tzinfo=timezone.utc),
        decisions_by_project={"clean-svc": decision},
        posture_by_project={"clean-svc": "balanced"},
        dangerously_by_project={"clean-svc": False},
    )
    body = alert.body
    # The section heading-with-bullet form only shows up when there are
    # rows. Heading prose for empty sections is acceptable; no bullets.
    assert "No projects would be quarantined" in body
    # No bullet for clean-svc under quarantine list.
    quarantine_section_lines = [
        line for line in body.splitlines()
        if line.strip().startswith("- clean-svc")
    ]
    assert quarantine_section_lines == []


def test_format_grace_heads_up_alert_includes_expires_time() -> None:
    fd = _disp(
        "CVE-2026-5678", base=Severity.CRITICAL,
        disposition=Disposition.QUARANTINE,
    )
    decision = _decision(fd, project="auth-svc", image="auth:1.0")
    expires = datetime(2026, 5, 7, 12, 30, tzinfo=timezone.utc)
    alert = format_grace_heads_up_alert(
        expires_at=expires,
        decisions_by_project={"auth-svc": decision},
        posture_by_project={"auth-svc": "balanced"},
        dangerously_by_project={"auth-svc": False},
    )
    assert "2026-05-07 12:30" in alert.body
    assert "Enforcement begins" in alert.body


# Audit F-7: at-risk-running cross-references `dangerously_by_project`.


def test_grace_heads_up_at_risk_section_omitted_when_all_dangerously_false() -> None:
    """All projects have dangerously_by_project=False → no At-risk section."""
    fd = _disp(
        "CVE-2026-1111", base=Severity.CRITICAL,
        disposition=Disposition.QUARANTINE,
    )
    decision = _decision(fd, project="auth-svc", image="auth:1.0")
    alert = format_grace_heads_up_alert(
        expires_at=datetime(2026, 5, 7, 12, tzinfo=timezone.utc),
        decisions_by_project={"auth-svc": decision},
        posture_by_project={"auth-svc": "balanced"},
        dangerously_by_project={"auth-svc": False},
    )
    assert "At-risk-running" not in alert.body


def test_grace_heads_up_at_risk_omitted_when_no_quarantine_findings() -> None:
    """dangerously_by_project says foo is set, but foo has zero
    quarantine-disposition findings → not listed at-risk."""
    info = _disp(
        "CVE-2026-2222", base=Severity.LOW, effective=Severity.LOW,
        disposition=Disposition.INFORMATIONAL,
    )
    decision = _decision(info, project="foo", image="foo:1.0")
    alert = format_grace_heads_up_alert(
        expires_at=datetime(2026, 5, 7, 12, tzinfo=timezone.utc),
        decisions_by_project={"foo": decision},
        posture_by_project={"foo": "balanced"},
        dangerously_by_project={"foo": True},
    )
    # The flag is set but the project doesn't have any
    # would-quarantine (STILL_RUNNING_AT_RISK) findings, so foo must
    # NOT appear under the at-risk section.
    assert "At-risk-running" not in alert.body
    bullet_lines = [
        line for line in alert.body.splitlines()
        if line.strip().startswith("- foo")
    ]
    assert bullet_lines == []


def test_grace_heads_up_at_risk_section_sorted_deterministically() -> None:
    """Multiple at-risk projects appear sorted by name."""
    fd_a = _disp(
        "CVE-2026-AAAA", base=Severity.CRITICAL,
        disposition=Disposition.STILL_RUNNING_AT_RISK,
    )
    fd_b = _disp(
        "CVE-2026-BBBB", base=Severity.CRITICAL,
        disposition=Disposition.STILL_RUNNING_AT_RISK,
    )
    fd_c = _disp(
        "CVE-2026-CCCC", base=Severity.CRITICAL,
        disposition=Disposition.STILL_RUNNING_AT_RISK,
    )
    alert = format_grace_heads_up_alert(
        expires_at=datetime(2026, 5, 7, 12, tzinfo=timezone.utc),
        decisions_by_project={
            "zzz": _decision(fd_a, project="zzz", image="z:1"),
            "aaa": _decision(fd_b, project="aaa", image="a:1"),
            "mmm": _decision(fd_c, project="mmm", image="m:1"),
        },
        posture_by_project={
            "zzz": "balanced", "aaa": "balanced", "mmm": "balanced",
        },
        dangerously_by_project={"zzz": True, "aaa": True, "mmm": True},
    )
    body = alert.body
    aaa_idx = body.find("- aaa")
    mmm_idx = body.find("- mmm")
    zzz_idx = body.find("- zzz")
    assert 0 <= aaa_idx < mmm_idx < zzz_idx, (
        "at-risk-running entries must appear sorted by project name"
    )


def test_format_grace_heads_up_alert_priority_high() -> None:
    fd = _disp(
        "CVE-2026-5678", base=Severity.CRITICAL,
        disposition=Disposition.QUARANTINE,
    )
    decision = _decision(fd, project="auth-svc", image="auth:1.0")
    alert = format_grace_heads_up_alert(
        expires_at=datetime(2026, 5, 7, 12, tzinfo=timezone.utc),
        decisions_by_project={"auth-svc": decision},
        posture_by_project={"auth-svc": "balanced"},
        dangerously_by_project={"auth-svc": False},
    )
    assert alert.priority == 1


# ---------- decisions_from_scan_state (round-trip) ----------


def test_decisions_from_scan_state_round_trips(tmp_path) -> None:
    """Ensure prior-state deserialisation reconstructs disposition + scanned_at
    well enough for transition detection."""
    from boxmunge.cve.scan_state import (
        decisions_from_scan_state,
        read_scan_state,
        write_scan_state,
    )
    fd = _disp("CVE-2026-9999", base=Severity.CRITICAL,
               effective=Severity.CRITICAL,
               disposition=Disposition.QUARANTINE)
    decision = _decision(fd, when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    state_path = tmp_path / "demo.json"
    write_scan_state(state_path, decisions=(decision,),
                     scanned_at=decision.scanned_at)
    raw = read_scan_state(state_path)
    assert raw is not None
    rebuilt = decisions_from_scan_state(raw, project_name="demo")
    assert len(rebuilt) == 1
    rd = rebuilt[0]
    assert rd.image_ref == "myapp:1.0"
    assert rd.scanned_at == decision.scanned_at
    assert len(rd.findings) == 1
    assert rd.findings[0].finding.cve_id == "CVE-2026-9999"
    assert rd.findings[0].disposition == Disposition.QUARANTINE
    assert rd.quarantine_required is True


def test_scan_state_round_trips_attack_vector(tmp_path) -> None:
    """v0.7.1: Finding.attack_vector survives the JSON round-trip."""
    from boxmunge.cve.scan_state import (
        decisions_from_scan_state,
        read_scan_state,
        write_scan_state,
    )
    from boxmunge.cve.scanner import AttackVector, Finding

    finding = Finding(
        cve_id="CVE-2026-7777",
        severity=Severity.HIGH,
        package="libfoo",
        installed_version="1.0",
        fixed_version=None,
        title="t",
        primary_url=None,
        attack_vector=AttackVector.LOCAL,
    )
    fd = FindingDisposition(
        finding=finding,
        base_severity=Severity.HIGH,
        hardening_penalty=0,
        effective_severity=Severity.HIGH,
        disposition=Disposition.INFORMATIONAL,
        suppression=None,
        explanation="AV:L gated to informational.",
    )
    decision = _decision(fd, when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    state_path = tmp_path / "demo.json"
    write_scan_state(state_path, decisions=(decision,),
                     scanned_at=decision.scanned_at)
    raw = read_scan_state(state_path)
    assert raw is not None
    # On-disk shape: attack_vector serialized as the enum value.
    assert raw["decisions"][0]["findings"][0]["attack_vector"] == "Local"
    rebuilt = decisions_from_scan_state(raw, project_name="demo")
    assert rebuilt[0].findings[0].finding.attack_vector is AttackVector.LOCAL


def test_scan_state_legacy_without_attack_vector_field(tmp_path) -> None:
    """Backward-compat: scan_state files written by v0.7.0 lack the
    attack_vector field. Deserialiser must default to None and not raise."""
    import json as _json
    from boxmunge.cve.scan_state import (
        decisions_from_scan_state,
        read_scan_state,
    )

    legacy = {
        "scanned_at": "2026-05-06T12:00:00+00:00",
        "decisions": [{
            "image_ref": "myapp:1.0",
            "findings": [{
                "cve_id": "CVE-2026-9999",
                "base_severity": "Critical",
                "effective_severity": "Critical",
                "hardening_penalty": 0,
                "disposition": "quarantine",
                "explanation": "Critical, exceeds threshold.",
                "fix_available": False,
                "fixed_version": None,
                "package": "openssl",
                "primary_url": None,
                "title": "t",
                "installed_version": "1",
                # NOTE: no attack_vector key
            }],
        }],
    }
    state_path = tmp_path / "legacy.json"
    state_path.write_text(_json.dumps(legacy))
    raw = read_scan_state(state_path)
    assert raw is not None
    rebuilt = decisions_from_scan_state(raw, project_name="demo")
    # Defaulted to None — no exception raised.
    assert rebuilt[0].findings[0].finding.attack_vector is None


def test_scan_state_round_trips_attack_vector_none(tmp_path) -> None:
    """A finding scanned without a CVSS block (attack_vector=None) round-trips
    cleanly — explicit None on serialisation, None on deserialisation."""
    from boxmunge.cve.scan_state import (
        decisions_from_scan_state,
        read_scan_state,
        write_scan_state,
    )
    from boxmunge.cve.scanner import Finding

    finding = Finding(
        cve_id="CVE-2026-8888",
        severity=Severity.MEDIUM,
        package="x",
        installed_version="1",
        fixed_version=None,
        title="t",
        primary_url=None,
        attack_vector=None,
    )
    fd = FindingDisposition(
        finding=finding,
        base_severity=Severity.MEDIUM,
        hardening_penalty=0,
        effective_severity=Severity.MEDIUM,
        disposition=Disposition.INFORMATIONAL,
        suppression=None,
        explanation="x",
    )
    decision = _decision(fd, when=datetime(2026, 5, 6, tzinfo=timezone.utc))
    state_path = tmp_path / "demo.json"
    write_scan_state(state_path, decisions=(decision,),
                     scanned_at=decision.scanned_at)
    raw = read_scan_state(state_path)
    assert raw is not None
    assert raw["decisions"][0]["findings"][0]["attack_vector"] is None
    rebuilt = decisions_from_scan_state(raw, project_name="demo")
    assert rebuilt[0].findings[0].finding.attack_vector is None

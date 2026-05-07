"""Tests for the `boxmunge security <project>` introspection command."""
import io
import json
from contextlib import redirect_stdout

import pytest
import yaml

from boxmunge.commands.security_cmd import cmd_security


@pytest.fixture
def project_with_default(tmp_path, monkeypatch):
    from boxmunge.paths import BoxPaths
    paths = BoxPaths(root=tmp_path)
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    paths.state.mkdir(parents=True, exist_ok=True)
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    # Register the project so the fleet path knows about it.
    (paths.state / "projects.txt").write_text("demo\n")
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    return paths


def test_security_default_lists_full_payload(project_with_default) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo"])
    out = buf.getvalue()
    assert "demo" in out
    assert "schema_version: 2" in out
    assert "service: web" in out
    assert "no-new-privileges:true" in out
    assert "pids_limit" in out and "512" in out
    assert "NET_ADMIN" in out


def test_security_json_returns_structured_data(project_with_default) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo", "--json"])
    payload = json.loads(buf.getvalue())
    assert payload["project"] == "demo"
    assert payload["project_profile"] == "default"
    assert "web" in payload["services"]
    web = payload["services"]["web"]
    assert web["pids_limit"] == 512
    assert "NET_ADMIN" in web["cap_drop"]
    assert payload["off_services"] == []


def test_security_json_flag_first(project_with_default) -> None:
    """Audit H-3b: ``--json`` must be detected even when it precedes the project."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["--json", "demo"])
    payload = json.loads(buf.getvalue())
    assert payload["project"] == "demo"


def _make_paths(tmp_path):
    from boxmunge.paths import BoxPaths
    paths = BoxPaths(root=tmp_path)
    paths.projects.mkdir(parents=True, exist_ok=True)
    paths.state.mkdir(parents=True, exist_ok=True)
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    return paths


def test_security_text_missing_schema_version_fails_loud(monkeypatch, tmp_path, capsys) -> None:
    """Audit I-2c: a manifest missing schema_version must NOT silently default
    to 1 — operators get a clear error on stderr and exit 1."""
    paths = _make_paths(tmp_path)
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    (paths.state / "projects.txt").write_text("demo\n")
    manifest = {
        # schema_version intentionally omitted
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    # Bypass load_manifest's own schema validation so we can exercise the
    # security_cmd fail-loud path directly with a hand-edited manifest.
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd.load_manifest",
        lambda path: manifest,
    )

    with pytest.raises(SystemExit) as exc:
        cmd_security(["demo"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "schema_version" in captured.err
    assert "ERROR" in captured.err


def test_security_json_missing_schema_version_fails_loud(monkeypatch, tmp_path, capsys) -> None:
    """Same fail-loud guarantee for the --json code path."""
    paths = _make_paths(tmp_path)
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    (paths.state / "projects.txt").write_text("demo\n")
    manifest = {
        # schema_version intentionally omitted
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd.load_manifest",
        lambda path: manifest,
    )

    with pytest.raises(SystemExit) as exc:
        cmd_security(["demo", "--json"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "schema_version" in captured.err
    assert "ERROR" in captured.err


def test_security_json_off_services(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    (paths.state / "projects.txt").write_text("demo\n")
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "security": {"profile": "off", "reason": "deliberate"},
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)

    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo", "--json"])
    payload = json.loads(buf.getvalue())
    assert payload["project_profile"] == "off"
    assert payload["off_services"] == [{"service": "web", "reason": "deliberate"}]
    assert payload["services"]["web"] == {}


def test_security_unknown_flag_exits_2(capsys) -> None:
    """Audit H-N1: cmd_security rejects unknown flags."""
    with pytest.raises(SystemExit) as exc:
        cmd_security(["demo", "--not-a-flag"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert "--not-a-flag" in err


# ---------- fleet summary ----------


def test_fleet_summary_no_projects_text(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    (paths.state / "projects.txt").write_text("")
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security([])
    assert "No projects registered." in buf.getvalue()


def test_fleet_summary_no_projects_json(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    (paths.state / "projects.txt").write_text("")
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["--json"])
    payload = json.loads(buf.getvalue())
    assert payload["projects_count"] == 0
    assert payload["quarantined"] == []
    assert payload["last_fleet_scan"] is None


def test_fleet_summary_single_project(project_with_default) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security([])
    out = buf.getvalue()
    assert "Projects: 1" in out
    assert "balanced: 1" in out
    assert "Quarantined: 0" in out


def test_fleet_summary_json_aggregates(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    for name, posture in [("alpha", "strict"), ("beta", "balanced"), ("gamma", "balanced")]:
        proj = paths.projects / name
        proj.mkdir(parents=True)
        manifest = {
            "schema_version": 2,
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "source": "bundle",
            "project": name,
            "hosts": [f"{name}.example.com"],
            "security": {"posture": posture},
            "services": {
                "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
            },
        }
        (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    (paths.state / "projects.txt").write_text("alpha\nbeta\ngamma\n")
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["--json"])
    payload = json.loads(buf.getvalue())
    assert payload["projects_count"] == 3
    assert payload["posture_distribution"]["strict"] == 1
    assert payload["posture_distribution"]["balanced"] == 2


def test_fleet_summary_quarantined_listed(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {"web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"}},
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    (paths.state / "projects.txt").write_text("demo\n")
    qfile = paths.project_quarantine_state("demo")
    qfile.parent.mkdir(parents=True, exist_ok=True)
    qfile.write_text(json.dumps({
        "quarantined_at": "2026-05-06T03:14:25+00:00",
        "cve_id": "CVE-2026-5678",
        "severity": "Critical",
        "effective_severity": "Critical",
        "explanation": "no upstream fix",
        "image_ref": "myapp@sha256:abc",
    }))
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["--json"])
    payload = json.loads(buf.getvalue())
    assert len(payload["quarantined"]) == 1
    assert payload["quarantined"][0]["project"] == "demo"
    assert payload["quarantined"][0]["cve_id"] == "CVE-2026-5678"


# ---------- per-project view extensions ----------


def test_per_project_no_scan_yet_text(project_with_default) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo"])
    out = buf.getvalue()
    assert "CVE state:" in out
    assert "posture:" in out and "balanced" in out
    assert "No CVE scans have run yet" in out


def test_per_project_no_scan_yet_json(project_with_default) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo", "--json"])
    payload = json.loads(buf.getvalue())
    assert "cve" in payload
    assert payload["cve"]["last_scan"] is None
    assert payload["cve"]["findings"] == []
    assert payload["cve"]["status"] == "NORMAL"


def test_per_project_with_scan_state(project_with_default) -> None:
    """When a scan state file is present, findings are rendered."""
    paths = project_with_default
    state_path = paths.project_scan_state("demo")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({
        "scanned_at": "2026-05-06T03:00:00+00:00",
        "decisions": [{
            "image_ref": "myapp@sha256:abc",
            "findings": [{
                "cve_id": "CVE-2026-1111",
                "base_severity": "High",
                "effective_severity": "High",
                "hardening_penalty": 0,
                "disposition": "informational",
                "explanation": "below threshold",
                "fix_available": False,
                "fixed_version": None,
                "package": "openssl",
                "primary_url": None,
            }],
        }],
    }))
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo"])
    out = buf.getvalue()
    assert "Findings (1)" in out
    assert "CVE-2026-1111" in out
    assert "INFORMATIONAL" in out


def test_per_project_quarantined_view(project_with_default) -> None:
    paths = project_with_default
    qfile = paths.project_quarantine_state("demo")
    qfile.parent.mkdir(parents=True, exist_ok=True)
    qfile.write_text(json.dumps({
        "quarantined_at": "2026-05-06T03:14:25+00:00",
        "cve_id": "CVE-2026-5678",
        "severity": "Critical",
        "effective_severity": "Critical",
        "explanation": "no upstream fix",
        "image_ref": "myapp@sha256:abc",
    }))
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo", "--json"])
    payload = json.loads(buf.getvalue())
    assert payload["cve"]["status"] == "QUARANTINED"
    assert payload["cve"]["quarantine"]["cve_id"] == "CVE-2026-5678"


def test_per_project_active_suppression_listed(project_with_default) -> None:
    paths = project_with_default
    sup_path = paths.project_dir("demo") / "security" / "suppressions.yml"
    sup_path.parent.mkdir(parents=True, exist_ok=True)
    sup_path.write_text(
        "suppressions:\n"
        "  - cve: CVE-2026-1234\n"
        "    until: '2099-01-01'\n"
        "    reason: Endpoint not exposed\n"
        "    reviewed_by: jon\n"
        "    added: '2026-05-06'\n"
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["demo", "--json"])
    payload = json.loads(buf.getvalue())
    assert len(payload["cve"]["active_suppressions"]) == 1
    assert payload["cve"]["active_suppressions"][0]["cve_id"] == "CVE-2026-1234"


# ---------- subcommand routing ----------


def test_subcommand_scan_routes_to_scan_handler(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    called = {}
    def fake(args, p):
        called["scan"] = args
        return 0
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd.cmd_security_scan", fake,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_security(["scan", "demo"])
    assert exc.value.code == 0
    assert called["scan"] == ["demo"]


def test_subcommand_suppress_routes_to_handler(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    called = {}
    def fake(args, p):
        called["suppress"] = args
        return 0
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd.cmd_security_suppress", fake,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_security(["suppress", "CVE-2026-1234", "--project", "demo"])
    assert exc.value.code == 0
    assert called["suppress"][0] == "CVE-2026-1234"


def test_subcommand_unsuppress_routes_to_handler(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    called = {}
    def fake(args, p):
        called["unsup"] = args
        return 0
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd.cmd_security_unsuppress", fake,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_security(["unsuppress", "CVE-2026-1234", "--project", "demo"])
    assert exc.value.code == 0
    assert called["unsup"][0] == "CVE-2026-1234"


def test_subcommand_resume_routes_to_handler(monkeypatch, tmp_path) -> None:
    paths = _make_paths(tmp_path)
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    called = {}
    def fake(args, p):
        called["resume"] = args
        return 0
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd.cmd_security_resume", fake,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_security(["resume", "demo"])
    assert exc.value.code == 0
    assert called["resume"] == ["demo"]


# ---------- suppress validation ----------


def _suppress_paths(tmp_path):
    paths = _make_paths(tmp_path)
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    (paths.state / "projects.txt").write_text("demo\n")
    return paths


def test_suppress_missing_required_flags_exits_2(tmp_path, capsys) -> None:
    from boxmunge.commands.security_suppress import cmd_security_suppress
    paths = _suppress_paths(tmp_path)
    rc = cmd_security_suppress(["CVE-2026-1234"], paths)
    assert rc == 2
    err = capsys.readouterr().err
    assert "missing required flag" in err


def test_suppress_past_date_rejected(tmp_path, capsys) -> None:
    from boxmunge.commands.security_suppress import cmd_security_suppress
    paths = _suppress_paths(tmp_path)
    rc = cmd_security_suppress(
        ["CVE-2026-1234", "--project", "demo",
         "--until", "1999-01-01", "--reason", "x"],
        paths,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "future date" in err


def test_suppress_invalid_date_rejected(tmp_path, capsys) -> None:
    from boxmunge.commands.security_suppress import cmd_security_suppress
    paths = _suppress_paths(tmp_path)
    rc = cmd_security_suppress(
        ["CVE-2026-1234", "--project", "demo",
         "--until", "not-a-date", "--reason", "x"],
        paths,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "YYYY-MM-DD" in err


def test_suppress_unregistered_project_rejected(tmp_path, capsys) -> None:
    from boxmunge.commands.security_suppress import cmd_security_suppress
    paths = _make_paths(tmp_path)
    (paths.state / "projects.txt").write_text("")
    rc = cmd_security_suppress(
        ["CVE-2026-1234", "--project", "nope",
         "--until", "2099-01-01", "--reason", "x"],
        paths,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "not registered" in err


def test_suppress_writes_file(monkeypatch, tmp_path, capsys) -> None:
    from boxmunge.commands.security_suppress import cmd_security_suppress
    monkeypatch.setenv("USER", "jon")
    paths = _suppress_paths(tmp_path)
    rc = cmd_security_suppress(
        ["CVE-2026-1234", "--project", "demo",
         "--until", "2099-01-01", "--reason", "Endpoint not exposed"],
        paths,
    )
    out = capsys.readouterr().out
    assert rc == 0
    sup_file = paths.project_dir("demo") / "security" / "suppressions.yml"
    assert sup_file.exists()
    text = sup_file.read_text()
    assert "CVE-2026-1234" in text
    assert "jon" in text
    assert "Suppression added" in out


# ---------- unsuppress ----------


def test_unsuppress_missing_project_flag_exits_2(tmp_path, capsys) -> None:
    from boxmunge.commands.security_suppress import cmd_security_unsuppress
    paths = _suppress_paths(tmp_path)
    rc = cmd_security_unsuppress(["CVE-2026-1234"], paths)
    assert rc == 2
    err = capsys.readouterr().err
    assert "--project" in err


def test_unsuppress_no_existing_entry_exits_1(tmp_path, capsys) -> None:
    from boxmunge.commands.security_suppress import cmd_security_unsuppress
    paths = _suppress_paths(tmp_path)
    rc = cmd_security_unsuppress(
        ["CVE-2026-1234", "--project", "demo"], paths,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "ERROR" in err


def test_unsuppress_removes_entry(monkeypatch, tmp_path, capsys) -> None:
    from boxmunge.commands.security_suppress import (
        cmd_security_suppress, cmd_security_unsuppress,
    )
    monkeypatch.setenv("USER", "jon")
    paths = _suppress_paths(tmp_path)
    rc1 = cmd_security_suppress(
        ["CVE-2026-1234", "--project", "demo",
         "--until", "2099-01-01", "--reason", "x"],
        paths,
    )
    capsys.readouterr()  # discard
    assert rc1 == 0
    rc2 = cmd_security_unsuppress(
        ["CVE-2026-1234", "--project", "demo"], paths,
    )
    assert rc2 == 0
    out = capsys.readouterr().out
    assert "removed" in out
    sup_file = paths.project_dir("demo") / "security" / "suppressions.yml"
    assert "CVE-2026-1234" not in sup_file.read_text()


# ---------- Wave 3: suppress/unsuppress audit trail (D-1 + D-2) ----------


def _capture_log_records():
    """Attach a capturing handler to the boxmunge logger.

    Returns (records, detacher). The boxmunge logger sets propagate=False
    once initialised, so caplog cannot see records reliably across tests.
    """
    import logging as _logging
    records: list = []

    class _ListHandler(_logging.Handler):
        def emit(self, record):  # type: ignore[override]
            records.append(record)

    h = _ListHandler(level=_logging.DEBUG)
    logger = _logging.getLogger("boxmunge")
    saved_level = logger.level
    logger.setLevel(_logging.DEBUG)
    logger.addHandler(h)

    def detach():
        logger.removeHandler(h)
        logger.setLevel(saved_level)
    return records, detach


def test_suppress_emits_log_operation(monkeypatch, tmp_path, capsys) -> None:
    """Audit D-1: every successful suppress emits a structured log_operation
    on component='cve-suppress' with the project name and CVE detail."""
    from boxmunge.commands.security_suppress import cmd_security_suppress
    monkeypatch.setenv("USER", "jon")
    paths = _suppress_paths(tmp_path)
    paths.logs.mkdir(parents=True, exist_ok=True)
    records, detach = _capture_log_records()
    try:
        rc = cmd_security_suppress(
            ["CVE-2026-1234", "--project", "demo",
             "--until", "2099-01-01", "--reason", "Endpoint not exposed"],
            paths,
        )
    finally:
        detach()
    capsys.readouterr()
    assert rc == 0
    matching = [
        r for r in records
        if getattr(r, "component", None) == "cve-suppress"
    ]
    assert len(matching) == 1
    rec = matching[0]
    assert getattr(rec, "project", None) == "demo"
    detail = getattr(rec, "detail", None)
    assert isinstance(detail, dict)
    assert detail["cve_id"] == "CVE-2026-1234"
    assert detail["until"] == "2099-01-01"
    assert detail["reason"] == "Endpoint not exposed"
    assert detail["reviewed_by"] == "jon"
    assert detail["previously_suppressed"] is False


def test_unsuppress_emits_log_operation(monkeypatch, tmp_path, capsys) -> None:
    """Audit D-1: unsuppress emits a structured log_operation."""
    from boxmunge.commands.security_suppress import (
        cmd_security_suppress, cmd_security_unsuppress,
    )
    monkeypatch.setenv("USER", "jon")
    paths = _suppress_paths(tmp_path)
    paths.logs.mkdir(parents=True, exist_ok=True)
    rc1 = cmd_security_suppress(
        ["CVE-2026-1234", "--project", "demo",
         "--until", "2099-01-01", "--reason", "x"],
        paths,
    )
    capsys.readouterr()
    assert rc1 == 0

    records, detach = _capture_log_records()
    try:
        rc2 = cmd_security_unsuppress(
            ["CVE-2026-1234", "--project", "demo"], paths,
        )
    finally:
        detach()
    capsys.readouterr()
    assert rc2 == 0
    matching = [
        r for r in records
        if getattr(r, "component", None) == "cve-suppress"
        and "removed" in r.getMessage().lower()
    ]
    assert len(matching) == 1
    rec = matching[0]
    assert getattr(rec, "project", None) == "demo"
    detail = getattr(rec, "detail", None)
    assert isinstance(detail, dict)
    assert detail["cve_id"] == "CVE-2026-1234"
    assert "previous_until" in detail
    assert "previous_added" in detail


def test_resuppress_within_window_flags_silent_extension(
    monkeypatch, tmp_path, capsys,
) -> None:
    """Audit D-2: unsuppress + suppress within 7 days warns AND records
    previously_suppressed=true in the audit log detail."""
    from boxmunge.commands.security_suppress import (
        cmd_security_suppress, cmd_security_unsuppress,
    )
    monkeypatch.setenv("USER", "jon")
    paths = _suppress_paths(tmp_path)
    paths.logs.mkdir(parents=True, exist_ok=True)
    # Initial suppress.
    rc = cmd_security_suppress(
        ["CVE-2026-1234", "--project", "demo",
         "--until", "2099-01-01", "--reason", "first"],
        paths,
    )
    capsys.readouterr()
    assert rc == 0
    # Unsuppress.
    rc = cmd_security_unsuppress(
        ["CVE-2026-1234", "--project", "demo"], paths,
    )
    capsys.readouterr()
    assert rc == 0

    # Re-suppress immediately. Should succeed but emit a warning to
    # stderr AND log previously_suppressed=true.
    records, detach = _capture_log_records()
    try:
        rc = cmd_security_suppress(
            ["CVE-2026-1234", "--project", "demo",
             "--until", "2099-12-31", "--reason", "second"],
            paths,
        )
    finally:
        detach()
    captured = capsys.readouterr()
    assert rc == 0
    # Stderr NOTE.
    assert "NOTE" in captured.err
    assert "unsuppressed" in captured.err
    assert "re-suppressed" in captured.err
    # Audit log detail flags the silent extension.
    op_records = [
        r for r in records
        if getattr(r, "component", None) == "cve-suppress"
        and "added" in r.getMessage().lower()
    ]
    assert len(op_records) == 1
    detail = getattr(op_records[0], "detail", None)
    assert isinstance(detail, dict)
    assert detail["previously_suppressed"] is True
    assert "previous_until" in detail
    assert "previous_added" in detail
    assert "removed_at" in detail


def test_resuppress_after_window_treated_as_fresh(
    monkeypatch, tmp_path, capsys,
) -> None:
    """Audit D-2: re-suppress beyond the 7-day window is treated as a fresh
    decision — no NOTE, previously_suppressed=false."""
    from boxmunge.commands.security_suppress import (
        cmd_security_suppress, cmd_security_unsuppress,
    )
    from boxmunge.cve.suppressions import history_path_for
    monkeypatch.setenv("USER", "jon")
    paths = _suppress_paths(tmp_path)
    paths.logs.mkdir(parents=True, exist_ok=True)
    rc = cmd_security_suppress(
        ["CVE-2026-1234", "--project", "demo",
         "--until", "2099-01-01", "--reason", "first"],
        paths,
    )
    capsys.readouterr()
    assert rc == 0
    rc = cmd_security_unsuppress(
        ["CVE-2026-1234", "--project", "demo"], paths,
    )
    capsys.readouterr()
    assert rc == 0

    # Backdate the recorded removal so the window has expired (8+ days ago).
    sup_path = paths.project_dir("demo") / "security" / "suppressions.yml"
    history = history_path_for(sup_path)
    text = history.read_text()
    # Replace today's removed_at with a date a year ago.
    import re as _re
    text = _re.sub(
        r"removed_at: '?\d{4}-\d{2}-\d{2}'?",
        "removed_at: '2024-01-01'",
        text,
    )
    history.write_text(text)

    records, detach = _capture_log_records()
    try:
        rc = cmd_security_suppress(
            ["CVE-2026-1234", "--project", "demo",
             "--until", "2099-12-31", "--reason", "second"],
            paths,
        )
    finally:
        detach()
    captured = capsys.readouterr()
    assert rc == 0
    # No silent-extension NOTE.
    assert "NOTE" not in captured.err
    op_records = [
        r for r in records
        if getattr(r, "component", None) == "cve-suppress"
        and "added" in r.getMessage().lower()
    ]
    assert len(op_records) == 1
    detail = getattr(op_records[0], "detail", None)
    assert isinstance(detail, dict)
    assert detail["previously_suppressed"] is False


def test_suppress_validation_failure_emits_log_error(
    monkeypatch, tmp_path, capsys,
) -> None:
    """Audit D-1: validation failures emit log_error on cve-suppress so
    the trail still surfaces what the operator tried to do."""
    from boxmunge.commands.security_suppress import cmd_security_suppress
    monkeypatch.setenv("USER", "jon")
    paths = _suppress_paths(tmp_path)
    paths.logs.mkdir(parents=True, exist_ok=True)
    records, detach = _capture_log_records()
    try:
        rc = cmd_security_suppress(
            ["CVE-2026-1234", "--project", "demo",
             "--until", "1999-01-01", "--reason", "x"],
            paths,
        )
    finally:
        detach()
    capsys.readouterr()
    assert rc == 1
    err_records = [
        r for r in records
        if getattr(r, "component", None) == "cve-suppress"
        and r.levelname == "ERROR"
    ]
    assert err_records, "expected an ERROR-level cve-suppress log record"


# ---------- scan ----------


def _scan_paths(tmp_path, *, in_grace: bool = False):
    """Build a paths fixture with a single 'demo' project ready to scan.

    By default tests run with the migration grace already expired (so the
    long-standing quarantine/alert behaviour matches the pre-grace tests).
    Pass ``in_grace=True`` to write an active grace marker for the
    grace-specific tests.
    """
    paths = _make_paths(tmp_path)
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh", "image": "myapp:1.0"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    (proj / "compose.yml").write_text(yaml.safe_dump({
        "services": {
            "web": {
                "image": "myapp:1.0",
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
            },
        },
    }))
    (paths.state / "projects.txt").write_text("demo\n")
    _seed_grace(paths, in_grace=in_grace)
    return paths


def _seed_grace(paths, *, in_grace: bool, heads_up_sent: bool = False) -> None:
    """Pre-create a grace marker. ``in_grace=False`` writes an already-expired
    marker so tests exercise the normal enforcement path."""
    from datetime import datetime, timedelta, timezone
    paths.state.mkdir(parents=True, exist_ok=True)
    if in_grace:
        installed = datetime.now(timezone.utc)
        expires = installed + timedelta(hours=24)
    else:
        installed = datetime(2025, 1, 1, tzinfo=timezone.utc)
        expires = datetime(2025, 1, 2, tzinfo=timezone.utc)
    paths.cve_grace_state.write_text(json.dumps({
        "installed_at": installed.isoformat(),
        "expires_at": expires.isoformat(),
        "heads_up_sent": heads_up_sent,
    }))


def test_scan_no_projects_registered(monkeypatch, tmp_path, capsys) -> None:
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _make_paths(tmp_path)
    (paths.state / "projects.txt").write_text("")
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    rc = cmd_security_scan([], paths)
    out = capsys.readouterr().out
    assert rc == 0
    assert "No projects registered." in out


def test_scan_trivy_not_installed_exits_1(monkeypatch, tmp_path, capsys) -> None:
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.cve.scanner import TrivyNotInstalledError
    paths = _scan_paths(tmp_path)
    def boom():
        raise TrivyNotInstalledError("trivy not found on PATH. Install: <url>")
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", boom,
    )
    rc = cmd_security_scan([], paths)
    err = capsys.readouterr().err
    assert rc == 1
    assert "trivy" in err.lower()


def test_scan_clean_image_persists_state(monkeypatch, tmp_path, capsys) -> None:
    """Mock scan_image to return a clean ScanResult; verify state file written."""
    from datetime import datetime, timezone
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.cve.scanner import ScanResult
    paths = _scan_paths(tmp_path)
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.container_image_digest",
        lambda c: None,
    )
    sr = ScanResult(
        image_ref="myapp:1.0",
        findings=(),
        scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
        db_version="2026-05-06",
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.scan_image", lambda r, **kw: sr,
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    state = paths.project_scan_state("demo")
    assert state.exists()
    payload = json.loads(state.read_text())
    assert payload["decisions"][0]["findings"] == []


def test_scan_quarantine_finding_triggers_quarantine_action(
    monkeypatch, tmp_path,
) -> None:
    """A QUARANTINE-disposition finding should call quarantine_project."""
    from datetime import datetime, timezone
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.cve.scanner import Finding, ScanResult, Severity
    paths = _scan_paths(tmp_path)
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.container_image_digest",
        lambda c: None,
    )
    finding = Finding(
        cve_id="CVE-2026-9999",
        severity=Severity.CRITICAL,
        package="openssl",
        installed_version="1.1.1",
        fixed_version=None,
        title="bad",
        primary_url=None,
    )
    sr = ScanResult(
        image_ref="myapp:1.0",
        findings=(finding,),
        scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
        db_version="2026-05-06",
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.scan_image", lambda r, **kw: sr,
    )
    called = {}
    def fake_quarantine(*args, **kwargs):
        called["q"] = (args, kwargs)
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        fake_quarantine,
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    assert "q" in called


def test_scan_per_project_budget_skips_remaining_images(
    monkeypatch, tmp_path, capsys,
) -> None:
    """When the first image's scan exhausts the per-project budget, the
    remaining images for that project must be skipped (not invoke
    scan_image) and a warning must be logged.

    Sized fake-clock: each scan_image call advances time.monotonic by an
    amount large enough to exhaust the 600s budget on the first call.
    """
    import yaml
    from datetime import datetime, timezone
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.cve.scanner import ScanResult

    paths = _scan_paths(tmp_path)
    # Reshape demo's manifest + compose to declare 3 images. _identify_images
    # falls back to compose-declared images when no container is running.
    proj_dir = paths.projects / "demo"
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
            "sidecar": {"port": 4000, "routes": [], "smoke": "x.sh"},
            "worker": {"port": 5000, "routes": [], "smoke": "x.sh"},
        },
    }
    (proj_dir / "manifest.yml").write_text(yaml.safe_dump(manifest))
    (proj_dir / "compose.yml").write_text(yaml.safe_dump({
        "services": {
            "web": {"image": "web:1.0", "read_only": True,
                    "security_opt": ["no-new-privileges:true"]},
            "sidecar": {"image": "sidecar:1.0", "read_only": True,
                        "security_opt": ["no-new-privileges:true"]},
            "worker": {"image": "worker:1.0", "read_only": True,
                       "security_opt": ["no-new-privileges:true"]},
        },
    }))

    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.container_image_digest",
        lambda c: None,
    )

    # Scripted monotonic clock — patching security_scan_core.time.monotonic
    # affects time.monotonic for the whole test (the import binding is shared).
    # Sequence covers ALL time.monotonic() calls during the scan, in order:
    #   1. cmd_security_scan: start = time.monotonic()                       -> 0
    #   2. _scan_one_project_locked: project_start = time.monotonic()        -> 0
    #   3. loop iter 0: elapsed = monotonic() - project_start                -> 100   (remaining=500, scan runs)
    #   4. loop iter 1: elapsed = monotonic() - project_start                -> 700   (remaining=-100, break)
    #   5. cmd_security_scan: elapsed = monotonic() - start                  -> 800
    # Subsequent calls (defensive) keep returning the last value.
    fake_times = iter([0.0, 0.0, 100.0, 700.0, 800.0])
    last_t = [800.0]
    def fake_monotonic() -> float:
        try:
            v = next(fake_times)
        except StopIteration:
            return last_t[0]
        last_t[0] = v
        return v
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.time.monotonic", fake_monotonic,
    )

    scan_calls: list[str] = []
    def fake_scan(image_ref, *, timeout: int = 300) -> ScanResult:
        scan_calls.append(image_ref)
        return ScanResult(
            image_ref=image_ref,
            findings=(),
            scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
            db_version="2026-05-06",
        )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.scan_image", fake_scan,
    )

    rc = cmd_security_scan([], paths)
    out = capsys.readouterr().out

    # Exactly one image was scanned before the budget kicked in.
    assert len(scan_calls) == 1, (
        f"expected exactly 1 scan_image call before budget exhaustion, "
        f"got {len(scan_calls)}: {scan_calls}"
    )
    # The user-visible warning surfaced through the per-project warnings list.
    assert "budget exceeded" in out.lower()
    # rc=0 because no failures, no quarantine — just a partial scan.
    assert rc == 0


# ---------- resume ----------


def test_resume_not_quarantined_exits_1(tmp_path, capsys) -> None:
    from boxmunge.commands.security_actions import cmd_security_resume
    paths = _suppress_paths(tmp_path)
    rc = cmd_security_resume(["demo"], paths)
    err = capsys.readouterr().err
    assert rc == 1
    assert "not quarantined" in err


def test_resume_blocked_when_finding_still_quarantines(
    monkeypatch, tmp_path, capsys,
) -> None:
    from datetime import datetime, timezone
    from boxmunge.commands.security_actions import cmd_security_resume
    from boxmunge.cve.scanner import Finding, ScanResult, Severity
    paths = _scan_paths(tmp_path)
    qfile = paths.project_quarantine_state("demo")
    qfile.parent.mkdir(parents=True, exist_ok=True)
    qfile.write_text(json.dumps({
        "quarantined_at": "2026-05-06T03:14:25+00:00",
        "cve_id": "CVE-2026-9999",
        "severity": "Critical",
        "effective_severity": "Critical",
        "explanation": "no upstream fix",
        "image_ref": "myapp:1.0",
    }))
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.container_image_digest",
        lambda c: None,
    )
    finding = Finding(
        cve_id="CVE-2026-9999",
        severity=Severity.CRITICAL,
        package="openssl",
        installed_version="1.1.1",
        fixed_version=None,
        title="bad",
        primary_url=None,
    )
    sr = ScanResult(
        image_ref="myapp:1.0",
        findings=(finding,),
        scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
        db_version="2026-05-06",
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.scan_image", lambda r, **kw: sr,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: None,
    )
    rc = cmd_security_resume(["demo"], paths)
    err = capsys.readouterr().err
    assert rc == 1
    assert "Cannot resume" in err
    assert "CVE-2026-9999" in err


# ---------- alerting integration ----------


def test_scan_invokes_emit_scan_alerts_after_persist(
    monkeypatch, tmp_path,
) -> None:
    """Verify the scan handler hands the prior + current decisions to
    emit_scan_alerts after persisting the new scan_state."""
    from datetime import datetime, timezone
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.cve.scanner import Finding, ScanResult, Severity
    paths = _scan_paths(tmp_path)
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.container_image_digest",
        lambda c: None,
    )
    finding = Finding(
        cve_id="CVE-2026-9999",
        severity=Severity.CRITICAL,
        package="openssl",
        installed_version="1.1.1",
        fixed_version=None,
        title="bad",
        primary_url=None,
    )
    sr = ScanResult(
        image_ref="myapp:1.0",
        findings=(finding,),
        scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
        db_version="2026-05-06",
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.scan_image", lambda r, **kw: sr,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: None,
    )
    captured: dict = {}
    def fake_emit(**kwargs):
        captured.update(kwargs)
        return 0
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.emit_scan_alerts", fake_emit,
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    # The state file was written.
    assert paths.project_scan_state("demo").exists()
    # emit_scan_alerts received this scan's current decision and no prior.
    assert captured.get("project_name") == "demo"
    assert captured.get("posture") == "balanced"
    assert captured.get("prior") is None
    current = captured.get("current")
    assert current is not None
    assert current.image_ref == "myapp:1.0"
    assert any(
        d.finding.cve_id == "CVE-2026-9999" for d in current.findings
    )


def test_scan_passes_prior_decision_on_second_scan(monkeypatch, tmp_path) -> None:
    """When a scan_state file already exists, the second scan should hand its
    deserialised decisions to emit_scan_alerts as `prior`."""
    from datetime import datetime, timezone
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.cve.scanner import Finding, ScanResult, Severity
    paths = _scan_paths(tmp_path)
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.container_image_digest",
        lambda c: None,
    )
    finding = Finding(
        cve_id="CVE-2026-9999",
        severity=Severity.CRITICAL,
        package="openssl",
        installed_version="1.1.1",
        fixed_version=None,
        title="bad",
        primary_url=None,
    )
    sr = ScanResult(
        image_ref="myapp:1.0",
        findings=(finding,),
        scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
        db_version="2026-05-06",
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.scan_image", lambda r, **kw: sr,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: None,
    )

    captured_runs: list[dict] = []
    def fake_emit(**kwargs):
        captured_runs.append(kwargs)
        return 0
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.emit_scan_alerts", fake_emit,
    )
    # First scan — establishes state.
    rc = cmd_security_scan([], paths)
    assert rc == 0
    # Second scan — must see the first scan's decisions as prior.
    rc = cmd_security_scan([], paths)
    assert rc == 0
    assert len(captured_runs) == 2
    assert captured_runs[0]["prior"] is None
    second_prior = captured_runs[1]["prior"]
    assert second_prior is not None
    assert second_prior.image_ref == "myapp:1.0"
    assert any(
        d.finding.cve_id == "CVE-2026-9999" for d in second_prior.findings
    )


# ---------- migration grace ----------


def _grace_quarantine_scan(monkeypatch, paths) -> None:
    """Wire up scan-related stubs for grace tests: returns a Critical finding
    that would normally trigger quarantine."""
    from datetime import datetime, timezone
    from boxmunge.cve.scanner import Finding, ScanResult, Severity
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.container_image_digest",
        lambda c: None,
    )
    finding = Finding(
        cve_id="CVE-2026-9999",
        severity=Severity.CRITICAL,
        package="openssl",
        installed_version="1.1.1",
        fixed_version=None,
        title="bad",
        primary_url=None,
    )
    sr = ScanResult(
        image_ref="myapp:1.0",
        findings=(finding,),
        scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
        db_version="2026-05-06",
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.scan_image", lambda r, **kw: sr,
    )


def test_scan_all_initializes_grace_on_first_run(monkeypatch, tmp_path) -> None:
    """Fresh paths, no grace file → grace file created post-scan."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _make_paths(tmp_path)
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    manifest = {
        "schema_version": 2,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle",
        "project": "demo",
        "hosts": ["demo.example.com"],
        "services": {
            "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
        },
    }
    (proj / "manifest.yml").write_text(yaml.safe_dump(manifest))
    (proj / "compose.yml").write_text(yaml.safe_dump({
        "services": {"web": {"image": "myapp:1.0"}},
    }))
    (paths.state / "projects.txt").write_text("demo\n")
    # No grace file exists.
    assert not paths.cve_grace_state.exists()
    _grace_quarantine_scan(monkeypatch, paths)
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: None,
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    assert paths.cve_grace_state.exists()
    payload = json.loads(paths.cve_grace_state.read_text())
    assert "installed_at" in payload
    assert "expires_at" in payload


def test_scan_all_during_grace_does_not_quarantine(
    monkeypatch, tmp_path,
) -> None:
    """A would-quarantine finding inside the grace window must NOT call
    quarantine_project."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path, in_grace=True)
    _grace_quarantine_scan(monkeypatch, paths)
    called = {}
    def fake_quarantine(*a, **k):
        called["q"] = True
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        fake_quarantine,
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    assert "q" not in called


def test_scan_all_during_grace_fires_heads_up_once(
    monkeypatch, tmp_path,
) -> None:
    """Heads-up alert fires exactly once when grace is active and unsent."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path, in_grace=True)
    _grace_quarantine_scan(monkeypatch, paths)
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: None,
    )
    sends: list = []
    def fake_send(alerts, p):
        sends.append(alerts)
        return len(alerts)
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.send_alerts", fake_send,
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    assert len(sends) == 1
    assert sends[0][0].kind == "grace_heads_up"
    # Marker now has heads_up_sent: True.
    payload = json.loads(paths.cve_grace_state.read_text())
    assert payload["heads_up_sent"] is True


def test_scan_all_during_grace_does_not_fire_heads_up_again(
    monkeypatch, tmp_path,
) -> None:
    """If grace.heads_up_sent is already True, no heads-up call."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path, in_grace=True)
    # Re-seed with heads_up_sent=True.
    _seed_grace(paths, in_grace=True, heads_up_sent=True)
    _grace_quarantine_scan(monkeypatch, paths)
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: None,
    )
    sends: list = []
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.send_alerts",
        lambda alerts, p: sends.append(alerts) or len(alerts),
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    assert sends == []


def test_scan_all_during_grace_skips_normal_transition_alerts(
    monkeypatch, tmp_path,
) -> None:
    """emit_scan_alerts is NOT called inside the grace window."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path, in_grace=True)
    _grace_quarantine_scan(monkeypatch, paths)
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: None,
    )
    captured: list = []
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.emit_scan_alerts",
        lambda **kw: captured.append(kw) or 0,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.send_alerts",
        lambda alerts, p: 0,
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    assert captured == []


def test_scan_all_after_grace_quarantines_normally(
    monkeypatch, tmp_path,
) -> None:
    """When grace has expired, full enforcement and per-project alerts fire."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path, in_grace=False)
    _grace_quarantine_scan(monkeypatch, paths)
    quarantine_called: list = []
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: quarantine_called.append((a, k)),
    )
    emit_called: list = []
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.emit_scan_alerts",
        lambda **kw: emit_called.append(kw) or 0,
    )
    rc = cmd_security_scan([], paths)
    assert rc == 0
    assert len(quarantine_called) == 1
    assert len(emit_called) == 1


def test_scan_per_project_during_grace_does_not_quarantine(
    monkeypatch, tmp_path,
) -> None:
    """Per-project scan during grace skips quarantine AND skips heads-up."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path, in_grace=True)
    _grace_quarantine_scan(monkeypatch, paths)
    quarantine_called: list = []
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        lambda *a, **k: quarantine_called.append(True),
    )
    sends: list = []
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.send_alerts",
        lambda alerts, p: sends.append(alerts) or len(alerts),
    )
    rc = cmd_security_scan(["demo"], paths)
    assert rc == 0
    assert quarantine_called == []
    # Per-project flow doesn't fire heads-up.
    assert sends == []


def test_scan_corrupt_grace_aborts(monkeypatch, tmp_path, capsys) -> None:
    """Corrupt grace state aborts the scan loud rather than proceeding."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path, in_grace=False)
    paths.cve_grace_state.write_text("garbage {")
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    rc = cmd_security_scan([], paths)
    err = capsys.readouterr().err
    assert rc == 1
    assert "grace state is corrupt" in err


def test_security_summary_shows_grace_active_when_in_window(
    monkeypatch, tmp_path,
) -> None:
    """Fleet text summary surfaces ACTIVE grace and heads_up_sent flag."""
    paths = _make_paths(tmp_path)
    (paths.state / "projects.txt").write_text("")
    _seed_grace(paths, in_grace=True, heads_up_sent=True)
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd._paths", lambda: paths,
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["--json"])
    payload = json.loads(buf.getvalue())
    assert payload["grace"] is not None
    assert payload["grace"]["active"] is True
    assert payload["grace"]["heads_up_sent"] is True


def test_security_summary_omits_grace_when_no_file(
    monkeypatch, tmp_path,
) -> None:
    """No grace file → grace key is null in JSON, line absent in text."""
    paths = _make_paths(tmp_path)
    (paths.state / "projects.txt").write_text("")
    monkeypatch.setattr(
        "boxmunge.commands.security_cmd._paths", lambda: paths,
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(["--json"])
    payload = json.loads(buf.getvalue())
    assert payload["grace"] is None


# ---------- Wave 2: A-2 lock skip / E-1 heads-up flock / E-2 ordering / F-8 exit code ----------


def _wire_clean_scan(monkeypatch, paths) -> None:
    """Stub the scan path with a clean ScanResult (no findings)."""
    from datetime import datetime, timezone
    from boxmunge.cve.scanner import ScanResult
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.container_image_digest",
        lambda c: None,
    )
    sr = ScanResult(
        image_ref="myapp:1.0",
        findings=(),
        scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
        db_version="2026-05-06",
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.scan_image", lambda r, **kw: sr,
    )


def test_scan_skips_locked_project_and_logs(monkeypatch, tmp_path, capsys) -> None:
    """Audit A-2: when another op holds the project lock, scan skips
    that project and logs the skip; rc still reflects success across
    other projects."""
    import fcntl
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.fileutil import open_shared_lockfile
    paths = _scan_paths(tmp_path)
    _wire_clean_scan(monkeypatch, paths)
    # Hold the lock externally, simulating a concurrent op.
    lock_path = paths.project_lock_file("demo")
    fd = open_shared_lockfile(lock_path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rc = cmd_security_scan([], paths)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        import os as _os
        _os.close(fd)
    out = capsys.readouterr().out
    # rc 0 because no failures (skipped is not a failure) and no quarantine.
    assert rc == 0
    assert "SKIPPED" in out
    assert "Skipped (locked): demo" in out


def test_resume_returns_lock_error_when_held(monkeypatch, tmp_path, capsys) -> None:
    """Audit A-2: cmd_security_resume must surface LockError as a clear
    'try again' message rather than racing the holder."""
    import fcntl
    import json as _json
    from boxmunge.commands.security_actions import cmd_security_resume
    from boxmunge.fileutil import open_shared_lockfile
    paths = _scan_paths(tmp_path)
    # Mark the project as quarantined first so the resume gets past the
    # is_quarantined guard.
    qfile = paths.project_quarantine_state("demo")
    qfile.parent.mkdir(parents=True, exist_ok=True)
    qfile.write_text(_json.dumps({
        "quarantined_at": "2026-05-06T03:14:25+00:00",
        "cve_id": "CVE-2026-1",
        "severity": "Critical",
        "effective_severity": "Critical",
        "explanation": "test",
        "image_ref": "myapp:1.0",
    }))
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_db", lambda: None,
    )
    lock_path = paths.project_lock_file("demo")
    fd = open_shared_lockfile(lock_path)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rc = cmd_security_resume(["demo"], paths)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        import os as _os
        _os.close(fd)
    err = capsys.readouterr().err
    assert rc == 1
    assert "Another operation is in progress" in err


def test_resume_lift_section_holds_project_lock(monkeypatch, tmp_path) -> None:
    """Audit A-2: lift section must hold the project_lock when running.

    Patches lift_quarantine to assert the lock is exclusively held by us
    (i.e. another process attempting LOCK_NB would fail).
    """
    import fcntl as _fcntl
    import json as _json
    import os as _os
    from boxmunge.commands.security_actions import cmd_security_resume
    from boxmunge.fileutil import open_shared_lockfile
    paths = _scan_paths(tmp_path)
    qfile = paths.project_quarantine_state("demo")
    qfile.parent.mkdir(parents=True, exist_ok=True)
    qfile.write_text(_json.dumps({
        "quarantined_at": "2026-05-06T03:14:25+00:00",
        "cve_id": "CVE-2026-1",
        "severity": "Critical",
        "effective_severity": "Critical",
        "explanation": "test",
        "image_ref": "myapp:1.0",
    }))
    _wire_clean_scan(monkeypatch, paths)
    # Pre-render the caddy site to avoid prepare_caddy_config errors.
    paths.project_caddy_site("demo").parent.mkdir(parents=True, exist_ok=True)
    paths.project_caddy_site("demo").write_text("dummy")
    monkeypatch.setattr(
        "boxmunge.commands.deploy.prepare_caddy_config",
        lambda p, m: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.deploy.prepare_compose_override",
        lambda p, m, component=None: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.resume_cmd.run_smoke",
        lambda p, paths_: (True, "ok"),
    )
    lock_holds: list = []
    def assert_lock_held(*args, **kwargs):
        # Try to grab the lock non-blocking — should fail because the
        # caller (cmd_security_resume) is supposed to be holding it.
        fd = open_shared_lockfile(paths.project_lock_file("demo"))
        try:
            _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            lock_holds.append("acquired")  # bug if we get here
            _fcntl.flock(fd, _fcntl.LOCK_UN)
        except OSError:
            lock_holds.append("blocked")
        finally:
            _os.close(fd)
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.lift_quarantine",
        assert_lock_held,
    )
    rc = cmd_security_resume(["demo"], paths)
    assert rc == 0
    assert lock_holds == ["blocked"], (
        f"lift_quarantine ran without project_lock held; got {lock_holds}"
    )


def test_grace_heads_up_only_fires_once_under_concurrent_callers(
    monkeypatch, tmp_path,
) -> None:
    """Audit E-1: the grace heads-up alert must not double-fire when two
    fleet scans race. Direct test of the helper's flock + re-read semantics."""
    from boxmunge.commands.security_actions import _maybe_fire_grace_heads_up
    paths = _scan_paths(tmp_path, in_grace=True)
    sends: list = []
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.send_alerts",
        lambda alerts, p: sends.append(alerts) or len(alerts),
    )
    # Make formatting cheap and deterministic.
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.format_grace_heads_up_alert",
        lambda **kw: "ALERT",
    )
    # Provide a non-empty decisions_by_project so the outer guard would
    # have fired the heads-up.
    from datetime import datetime, timezone
    from boxmunge.cve.policy import ProjectDecision
    decisions = {"demo": ProjectDecision(
        project_name="demo",
        image_ref="myapp:1.0",
        scanned_at=datetime(2026, 5, 6, tzinfo=timezone.utc),
        findings=(),
        quarantine_required=False,
        at_risk_running=False,
    )}
    posture = {"demo": "balanced"}
    dangerously = {"demo": False}
    # First call should fire and persist heads_up_sent=True.
    _maybe_fire_grace_heads_up(
        paths,
        decisions_by_project=decisions,
        posture_by_project=posture,
        dangerously_by_project=dangerously,
    )
    # Second call simulates a concurrent fleet scan that passed its outer
    # check before the first call persisted. Inside the lock it must
    # re-read and bail.
    _maybe_fire_grace_heads_up(
        paths,
        decisions_by_project=decisions,
        posture_by_project=posture,
        dangerously_by_project=dangerously,
    )
    assert len(sends) == 1, (
        f"heads-up fired {len(sends)} times (expected 1)"
    )


def test_scan_state_not_written_when_quarantine_raises(
    monkeypatch, tmp_path, capsys,
) -> None:
    """Audit E-2: if quarantine_project raises, scan_state must NOT be
    written — next scan re-evaluates and re-fires."""
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.cve.quarantine import QuarantineError
    paths = _scan_paths(tmp_path)
    _grace_quarantine_scan(monkeypatch, paths)
    def boom(*args, **kwargs):
        raise QuarantineError("compose_stop failed")
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project", boom,
    )
    rc = cmd_security_scan([], paths)
    err_out = capsys.readouterr()
    # Failure surfaces in the per-project loop as ERROR — exit code 1.
    assert rc == 1
    # Critical: scan_state was NOT written, so a re-run will retry.
    assert not paths.project_scan_state("demo").exists()


def test_scan_exit_code_2_when_project_quarantined(
    monkeypatch, tmp_path, capsys,
) -> None:
    """Audit F-8: scan returns exit code 2 when ≥1 project is quarantined."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path)
    _grace_quarantine_scan(monkeypatch, paths)
    # Stub quarantine_project to write the state file (mimics the real action).
    def fake_quarantine(project_name, paths_, **kwargs):
        qf = paths_.project_quarantine_state(project_name)
        qf.parent.mkdir(parents=True, exist_ok=True)
        qf.write_text("{}")
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.quarantine_project",
        fake_quarantine,
    )
    rc = cmd_security_scan([], paths)
    out = capsys.readouterr().out
    assert rc == 2
    assert "Attention required" in out
    assert "1 quarantined" in out


def test_scan_exit_code_0_when_all_clean(monkeypatch, tmp_path, capsys) -> None:
    """Audit F-8: scan returns exit code 0 when no project is at-risk."""
    from boxmunge.commands.security_actions import cmd_security_scan
    paths = _scan_paths(tmp_path)
    _wire_clean_scan(monkeypatch, paths)
    rc = cmd_security_scan([], paths)
    assert rc == 0

# SPDX-License-Identifier: Apache-2.0
"""A suppression never hides a KEV-listed CVE (audit B-07)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import yaml

from boxmunge.commands import security_scan_core
from tests.test_commands.cve_helpers import scan_and_send
from boxmunge.commands.security_suppress import cmd_security_suppress
from boxmunge.commands.security_suppress_targets import utc_today
from boxmunge.cve import kev as kev_module
from boxmunge.cve.exploited import ExploitedSource
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import Disposition
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state
from tests.test_commands.cve_helpers import CRIT, Docker, Pushover, make_box, scan_result

_CVE = CRIT.cve_id


def _kev(*ids: str) -> KevCatalog:
    return KevCatalog(frozenset(ids), datetime.now(timezone.utc), datetime.now(timezone.utc), 'test')


def _suppress(paths, cve: str = _CVE) -> None:
    until = (utc_today() + timedelta(days=30)).isoformat()
    path = paths.project_dir("demo") / "security" / "suppressions.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"suppressions": [{
        "cve": cve, "until": until, "reason": "reviewed: endpoint not exposed",
        "reviewed_by": "ops", "added": utc_today().isoformat(),
    }]}))


@pytest.fixture
def box(tmp_path, monkeypatch):
    paths = make_box(tmp_path)
    monkeypatch.setattr(
        security_scan_core, "scan_image", lambda ref, timeout: scan_result(ref, [CRIT]),
    )
    return paths


def test_kev_listing_after_suppression_reactivates_with_priority_1_alert(
    box, monkeypatch,
):
    docker = Docker(monkeypatch)
    pushover = Pushover(monkeypatch, box)
    _suppress(box)

    scan = scan_and_send(box, "demo", kev=_kev())
    assert scan.decisions[0].findings[0].disposition is Disposition.SUPPRESSED
    assert not is_quarantined("demo", box)
    assert pushover.sent == []

    # CISA lists the CVE after the operator reviewed it.
    scan = scan_and_send(box, "demo", kev=_kev(_CVE))
    fd = scan.decisions[0].findings[0]
    assert fd.disposition is Disposition.QUARANTINE
    assert fd.full_kev is True
    assert "does not apply" in fd.explanation
    assert is_quarantined("demo", box)
    assert docker.calls == ["caddy_reload", "compose_stop"]
    assert [p for _, _, p in pushover.sent] == [1]
    title, body, _ = pushover.sent[0]
    assert _CVE in title and "does not apply" in body


def test_kev_listed_flag_round_trips_through_scan_state(box, monkeypatch):
    Docker(monkeypatch)
    scan_and_send(box, "demo", kev=_kev(_CVE))
    state = read_scan_state(box.project_scan_state("demo"))
    prior = decisions_from_scan_state(state, project_name="demo")
    assert prior[0].findings[0].full_kev


def _seed_kev_cache(paths, *ids: str, age_days: int = 0) -> None:
    when = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(kev_module.json.dumps({
        "fetched_at": when, "source": "test", "released_at": when, "cve_ids": list(ids),
    }))


def _suppress_args(*extra: str) -> list[str]:
    until = (utc_today() + timedelta(days=30)).isoformat()
    return [*extra, "--project", "demo", "--until", until, "--reason", "reviewed"]


def test_suppress_refuses_a_kev_listed_cve(box, capsys):
    _seed_kev_cache(box, _CVE)
    rc = cmd_security_suppress(_suppress_args(_CVE), box)
    assert rc == 1
    assert "Suppressions do not apply to KEV-listed CVEs" in capsys.readouterr().err
    assert not (box.project_dir("demo") / "security" / "suppressions.yml").exists()


def test_suppress_refuses_a_cve_on_a_stale_cached_catalog(box, capsys):
    """CVE-04: staleness turns the KEV gate off for new quarantines, but the
    cached IDs still say the CVE is listed; once the catalog is fresh the
    suppression would not apply, so it is refused now."""
    _seed_kev_cache(box, _CVE, age_days=30)
    assert cmd_security_suppress(_suppress_args(_CVE), box) == 1
    err = capsys.readouterr().err
    assert "Suppressions do not apply to KEV-listed CVEs" in err
    assert "the cached catalog is stale" in err
    assert not (box.project_dir("demo") / "security" / "suppressions.yml").exists()


def test_suppress_current_skips_kev_listed_and_suppresses_the_rest(
    box, monkeypatch, capsys,
):
    from boxmunge.cve.scan_state import write_scan_state
    from boxmunge.cve.policy import evaluate_project
    from boxmunge.cve.hardening import HardeningProfile
    from boxmunge.cve.policy import Posture
    from tests.test_commands.cve_helpers import finding

    other = finding("CVE-2026-0002")
    decision = evaluate_project(
        "demo", scan_result("demo-web:1", [CRIT, other]),
        posture=Posture.PARANOID,
        hardening_profile=HardeningProfile(True, True, False, False),
        dangerously_disable_quarantine=False, suppressions=(),
        today=utc_today(), exploited_lookup=lambda c: frozenset({ExploitedSource.CISA}) if c == _CVE else frozenset(),
    )
    write_scan_state(box.project_scan_state("demo"), decisions=(decision,))
    _seed_kev_cache(box, _CVE)
    rc = cmd_security_suppress(_suppress_args("--current"), box)
    assert rc == 0
    assert f"NOTE: {_CVE} is on the CISA Known" in capsys.readouterr().err
    text = (box.project_dir("demo") / "security" / "suppressions.yml").read_text()
    assert "CVE-2026-0002" in text and _CVE not in text


# ---------- B-09: the opt-out is honoured for KEV, loudly ----------


@pytest.mark.parametrize("fix", [None, "5.6.1-2"])
def test_kev_on_opted_out_project_keeps_running_and_alerts_every_scan(
    tmp_path, monkeypatch, fix,
):
    from boxmunge.commands import security_scan_core as core
    from tests.test_commands.cve_helpers import finding

    paths = make_box(tmp_path, security={"dangerously_disable_quarantine": True})
    monkeypatch.setattr(core, "scan_image",
                        lambda ref, timeout: scan_result(ref, [finding(_CVE, fix=fix)]))
    docker = Docker(monkeypatch)
    pushover = Pushover(monkeypatch, paths)
    for _ in range(2):
        pushover.clear()
        scan = scan_and_send(paths, "demo", kev=_kev(_CVE))
        fd = scan.decisions[0].findings[0]
        assert fd.disposition is Disposition.STILL_RUNNING_AT_RISK and fd.full_kev
        assert not is_quarantined("demo", paths) and docker.calls == []
        [(title, body, priority)] = pushover.sent
        assert priority == 1
        assert "STILL RUNNING" in title and "ACTIVELY EXPLOITED" in title and _CVE in title
        assert "dangerously_disable_quarantine" in body
        assert ("fix is available (5.6.1-2)" in body) is (fix is not None)


def test_fleet_view_lists_at_risk_only_with_findings(tmp_path, monkeypatch, capsys):
    """CVE_POLICY ledger #37: at_risk_running means opted out AND exposed."""
    import json

    from boxmunge.commands import security_actions
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.commands.security_cmd import cmd_security
    from tests.test_commands.cve_helpers import write_project

    # Paranoid: a non-KEV finding quarantines there, so opting out leaves it at risk.
    opted_out = {"posture": "paranoid", "dangerously_disable_quarantine": True}
    paths = make_box(tmp_path, projects=("exposed",), security=opted_out)
    write_project(paths, "quiet", security=opted_out)
    (paths.state / "projects.txt").write_text("exposed\nquiet\n")
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(
        security_scan_core, "scan_image",
        lambda ref, timeout: scan_result(ref, [CRIT] if ref.startswith("exposed") else []),
    )
    Pushover(monkeypatch, paths)
    assert cmd_security_scan([], paths) == 2
    capsys.readouterr()
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    cmd_security(["--json"])
    assert json.loads(capsys.readouterr().out)["at_risk_running"] == ["exposed"]



# ---------- 0.12: every list a suppression would not apply to ----------


def _seed_enisa(paths, **entries) -> None:
    paths.kev_enisa.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_enisa.write_text(kev_module.json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(), "etag": None,
        "last_modified": None, "entries": entries}))


def _seed_vulncheck(paths, *ids: str) -> None:
    paths.kev_vulncheck.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_vulncheck.write_text(kev_module.json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(), "entries": list(ids)}))


def _host_args(cve: str) -> list[str]:
    until = (utc_today() + timedelta(days=30)).isoformat()
    return [cve, "--host", "--until", until, "--reason", "reviewed"]


@pytest.mark.parametrize("scope", ["project", "host"])
def test_suppress_refuses_an_eu_only_kev_cve(box, capsys, scope):
    box.logs.mkdir(parents=True, exist_ok=True)
    _seed_kev_cache(box)
    _seed_enisa(box, **{_CVE: ["eukev_kev"]})
    args = _suppress_args(_CVE) if scope == "project" else _host_args(_CVE)
    assert cmd_security_suppress(args, box) == 1
    err = capsys.readouterr().err
    assert f"ERROR: {_CVE} is on the EU's known-exploited list" in err
    assert "Suppressions do not apply to KEV-listed CVEs" in err
    assert not (box.project_dir("demo") / "security" / "suppressions.yml").exists()
    assert not box.host_suppressions.exists()
    assert "eu_kev" in box.log_file.read_text()


def test_a_cisa_refusal_names_the_eu_listing_too(box, capsys):
    _seed_kev_cache(box, _CVE)
    _seed_enisa(box, **{_CVE: ["cisa_kev", "eukev_kev"]})
    assert cmd_security_suppress(_suppress_args(_CVE), box) == 1
    assert "(also listed by EU KEV)" in capsys.readouterr().err


def test_suppress_refuses_a_vulncheck_only_cve_on_a_paranoid_project(box, capsys):
    """make_box's project is paranoid."""
    _seed_kev_cache(box)
    _seed_vulncheck(box, _CVE)
    assert cmd_security_suppress(_suppress_args(_CVE), box) == 1
    err = capsys.readouterr().err
    assert f"{_CVE} is listed as actively exploited by VulnCheck KEV, and demo is paranoid" in err
    assert not (box.project_dir("demo") / "security" / "suppressions.yml").exists()


def test_a_vulncheck_only_cve_is_suppressed_below_paranoid(tmp_path, capsys):
    paths = make_box(tmp_path, security={"posture": "balanced"})
    _seed_kev_cache(paths)
    _seed_vulncheck(paths, _CVE)
    assert cmd_security_suppress(_suppress_args(_CVE), paths) == 0
    assert _CVE in (paths.project_dir("demo") / "security" / "suppressions.yml").read_text()


def test_a_host_suppression_of_a_vulncheck_only_cve_says_paranoid_ignores_it(box, capsys):
    _seed_kev_cache(box)
    _seed_vulncheck(box, _CVE)
    assert cmd_security_suppress(_host_args(_CVE), box) == 0
    assert "will not apply to a paranoid project" in capsys.readouterr().err
    assert _CVE in box.host_suppressions.read_text()

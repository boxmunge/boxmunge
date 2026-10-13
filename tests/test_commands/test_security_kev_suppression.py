# SPDX-License-Identifier: Apache-2.0
"""A suppression never hides a KEV-listed CVE (audit B-07)."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
import yaml

from boxmunge.commands import security_scan_core, security_scan_inputs
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.commands.security_suppress import cmd_security_suppress
from boxmunge.cve import kev as kev_module
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import Disposition
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state
from tests.test_commands.cve_helpers import CRIT, Docker, Pushover, make_box, scan_result

_CVE = CRIT.cve_id


def _kev(*ids: str) -> KevCatalog:
    return KevCatalog(frozenset(ids), datetime.now(timezone.utc))


def _suppress(paths, cve: str = _CVE) -> None:
    until = (date.today() + timedelta(days=30)).isoformat()
    path = paths.project_dir("demo") / "security" / "suppressions.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"suppressions": [{
        "cve": cve, "until": until, "reason": "reviewed: endpoint not exposed",
        "reviewed_by": "ops", "added": date.today().isoformat(),
    }]}))


@pytest.fixture
def box(tmp_path, monkeypatch):
    paths = make_box(tmp_path)
    monkeypatch.setattr(security_scan_inputs, "container_image_digest", lambda c: None)
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

    scan = scan_one_project(box, "demo", in_grace=False, kev=_kev())
    assert scan.decisions[0].findings[0].disposition is Disposition.SUPPRESSED
    assert not is_quarantined("demo", box)
    assert pushover.sent == []

    # CISA lists the CVE after the operator reviewed it.
    scan = scan_one_project(box, "demo", in_grace=False, kev=_kev(_CVE))
    fd = scan.decisions[0].findings[0]
    assert fd.disposition is Disposition.QUARANTINE
    assert fd.kev_listed is True
    assert "does not apply" in fd.explanation
    assert is_quarantined("demo", box)
    assert docker.calls == ["caddy_reload", "compose_stop"]
    assert [p for _, _, p in pushover.sent] == [1]
    title, body, _ = pushover.sent[0]
    assert _CVE in title and "does not apply" in body


def test_kev_listed_flag_round_trips_through_scan_state(box, monkeypatch):
    Docker(monkeypatch)
    scan_one_project(box, "demo", in_grace=False, kev=_kev(_CVE))
    state = read_scan_state(box.project_scan_state("demo"))
    prior = decisions_from_scan_state(state, project_name="demo")
    assert prior[0].findings[0].kev_listed is True


def _seed_kev_cache(paths, *ids: str) -> None:
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(kev_module.json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(), "cve_ids": list(ids),
    }))


def _suppress_args(*extra: str) -> list[str]:
    until = (date.today() + timedelta(days=30)).isoformat()
    return [*extra, "--project", "demo", "--until", until, "--reason", "reviewed"]


def test_suppress_refuses_a_kev_listed_cve(box, capsys):
    _seed_kev_cache(box, _CVE)
    rc = cmd_security_suppress(_suppress_args(_CVE), box)
    assert rc == 1
    assert "Suppressions do not apply to KEV-listed CVEs" in capsys.readouterr().err
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
        posture=Posture.BALANCED,
        hardening_profile=HardeningProfile(True, True, False, False),
        dangerously_disable_quarantine=False, suppressions=(),
        today=date.today(), kev_lookup=lambda c: c == _CVE,
    )
    write_scan_state(box.project_scan_state("demo"), decisions=(decision,))
    _seed_kev_cache(box, _CVE)
    rc = cmd_security_suppress(_suppress_args("--current"), box)
    assert rc == 0
    assert f"NOTE: {_CVE} is on the CISA Known" in capsys.readouterr().err
    text = (box.project_dir("demo") / "security" / "suppressions.yml").read_text()
    assert "CVE-2026-0002" in text and _CVE not in text

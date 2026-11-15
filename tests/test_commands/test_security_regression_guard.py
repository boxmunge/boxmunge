# SPDX-License-Identifier: Apache-2.0
"""The deploy guard (commands/security_regression_guard): a release whose
images carry a known-exploited CVE is refused on every route that someone
working on the project takes, quarantined or not, unless the operator
overrides it with a reason. The real scan, policy, KEV and cache code run;
Docker and Trivy are stubbed as in the quarantine gate's tests."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from boxmunge.commands import quarantine_gate as gate
from boxmunge.commands import security_regression_guard as guard
from boxmunge.commands.release_config import decide_release_users
from boxmunge.cve.scanner import Severity
from boxmunge.release_target import production_target
from boxmunge.staging_bringup import _decide_users
from tests.test_commands.cve_helpers import Pushover, finding
from tests.test_commands.test_quarantine_gate import KEV_CVE, MANIFEST, Box

pytestmark = pytest.mark.deploy_guard

CACHE_IMAGE = "sha256:" + "c" * 64
CLOSING = ('Fix it in the repo: bump the base image, or upgrade the package in the '
           'Dockerfile, then deploy again. To deploy anyway: --allow-security-regression '
           '--reason "<why>"')


@pytest.fixture
def box(tmp_path, monkeypatch) -> Box:
    """A project that is not quarantined, on a fresh KEV catalog listing KEV_CVE."""
    b = Box(tmp_path, monkeypatch)
    b.paths.project_quarantine_state("demo").unlink()
    b.kev(KEV_CVE)
    b.db = "2:db-1"
    monkeypatch.setattr(gate, "trivy_db_version", lambda: b.db)
    return b


def _guard(box, manifest=MANIFEST) -> None:
    guard.guard_release(box.paths, production_target(box.paths, "demo"), manifest)


def _carry_kev(box) -> None:
    box.findings[CACHE_IMAGE] = (finding(KEV_CVE, fix="7.0.9", pkg="libc"),)


def test_guard_runs_when_not_quarantined(box) -> None:
    _carry_kev(box)
    with pytest.raises(guard.SecurityRegressionRefused):
        _guard(box)


def test_a_clean_release_passes(box, capsys) -> None:
    box.findings[CACHE_IMAGE] = (finding("CVE-2026-1234"),)  # not exploited
    _guard(box)
    assert "no known-exploited CVE" in capsys.readouterr().out


def test_refusal_text_names_cve_package_and_fix(box) -> None:
    _carry_kev(box)
    with pytest.raises(guard.SecurityRegressionRefused) as e:
        _guard(box)
    problems = e.value.problems
    assert problems[0] == ("This release carries a known-exploited CVE; nothing was started "
                           "in production:")
    assert (f"{KEV_CVE} in libc 1 (fixed in 7.0.9), service cache ({CACHE_IMAGE}): listed "
            f"as actively exploited by CISA KEV") in problems[1]
    assert problems[-1] == CLOSING


def test_a_kev_finding_without_a_fix_says_so(box) -> None:
    box.findings[CACHE_IMAGE] = (finding(KEV_CVE, sev=Severity.LOW),)
    with pytest.raises(guard.SecurityRegressionRefused) as e:
        _guard(box, {**MANIFEST, "security": {"posture": "relaxed"}})
    assert "(no fixed version published yet)" in str(e.value)


def _vulncheck(box, *cves) -> None:
    box.paths.kev_vulncheck.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(), "entries": list(cves)}))


def test_a_vulncheck_only_listing_refuses_only_under_paranoid(box) -> None:
    box.findings[CACHE_IMAGE] = (finding("CVE-2026-4242", fix="2"),)
    _vulncheck(box, "CVE-2026-4242")
    _guard(box)  # balanced: never refused for a VulnCheck-only listing
    with pytest.raises(guard.SecurityRegressionRefused) as e:
        _guard(box, {**MANIFEST, "security": {"posture": "paranoid"}})
    assert "VulnCheck KEV (paranoid refuses it)" in str(e.value)


def test_a_failed_scan_refuses_with_the_override_offered(box) -> None:
    box.failing.add(CACHE_IMAGE)
    with pytest.raises(guard.SecurityRegressionRefused) as e:
        _guard(box)
    text = str(e.value)
    assert "could not clear this release" in text and "scan failed" in text
    assert e.value.problems[-1] == 'To deploy anyway: --allow-security-regression --reason "<why>"'


def test_with_no_usable_kev_catalog_it_refuses_with_fresh_data_advice(box) -> None:
    box.paths.kev_catalog.unlink()
    with pytest.raises(guard.SecurityRegressionRefused) as e:
        _guard(box)
    assert "no usable CISA KEV catalog" in str(e.value)
    assert "boxmunge security scan" in str(e.value)


def test_prod_deploys_accept_stale_kev_accepts_no_usable_catalog(box, capsys) -> None:
    from boxmunge.commands.kev_acceptance import prod_deploy_acceptance
    box.paths.kev_catalog.unlink()
    with prod_deploy_acceptance(box.paths, "demo", True):
        _guard(box)
    assert "--accept-stale-kev: deploying although" in capsys.readouterr().out


def test_a_stale_catalog_refuses_a_cve_its_cached_copy_lists(box) -> None:
    from tests.test_commands.test_stale_kev_lift import _write_kev
    _write_kev(box.paths, KEV_CVE, age_days=20)
    _carry_kev(box)
    with pytest.raises(guard.SecurityRegressionRefused) as e:
        _guard(box)
    assert "cached CISA KEV catalog, which is stale" in str(e.value)


def test_unchanged_images_hit_the_cache(box) -> None:
    _guard(box)
    first = list(box.scanned)
    box.scanned.clear()
    _guard(box)
    assert first and box.scanned == []


def test_cache_invalid_after_trivy_db_update(box) -> None:
    _guard(box)
    box.scanned.clear()
    box.db = "2:db-2"
    _carry_kev(box)
    with pytest.raises(guard.SecurityRegressionRefused):
        _guard(box)
    assert CACHE_IMAGE in box.scanned


def test_the_quarantine_gate_reads_the_guards_scan_from_the_cache(box) -> None:
    from tests.test_commands.cve_helpers import seed_quarantine
    _guard(box)
    box.scanned.clear()
    seed_quarantine(box.paths)
    box.clear()
    assert box.scanned == []


def _decide_production(box, component: str, carry_record: bool = False) -> None:
    decide_release_users("demo", box.paths, MANIFEST, component, pull=False,
                         carry_record=carry_record)


def _decide_staging(box) -> None:
    _decide_users(box.paths, "demo", MANIFEST, pull=False)


@pytest.mark.parametrize("route", [
    pytest.param(lambda b: _decide_staging(b), id="stage"),
    pytest.param(lambda b: _decide_production(b, "deploy"), id="prod-deploy"),
    pytest.param(lambda b: _decide_production(b, "promote"), id="promote"),
    pytest.param(lambda b: _decide_production(b, "rollback", True), id="rollback"),
])
def test_release_with_kev_refused_on_every_route(box, route) -> None:
    _carry_kev(box)
    with pytest.raises(guard.SecurityRegressionRefused) as e:
        route(box)
    assert KEV_CVE in str(e.value) and str(e.value).endswith(CLOSING)


@pytest.mark.parametrize("module,command,runner,extra", [
    ("boxmunge.commands.stage_cmd", "cmd_stage", "run_stage", []),
    ("boxmunge.commands.promote_cmd", "cmd_promote", "run_promote", []),
    ("boxmunge.commands.deploy", "cmd_deploy", "run_deploy", []),
    ("boxmunge.commands.rollback", "cmd_rollback", "run_rollback", ["--yes"]),
])
def test_every_cli_route_carries_the_override(monkeypatch, module, command, runner,
                                              extra) -> None:
    import importlib
    mod = importlib.import_module(module)
    seen = []
    monkeypatch.setattr(mod, runner, lambda *a, **k: seen.append(guard._CURRENT.get()) or 0)
    with pytest.raises(SystemExit) as e:
        getattr(mod, command)(["demo", *extra, "--allow-security-regression",
                               "--reason", "hotfix, CVE not reachable"])
    assert e.value.code == 0
    assert seen[0].project == "demo" and seen[0].reason == "hotfix, CVE not reachable"


@pytest.mark.parametrize("args", [["--allow-security-regression"],
                                  ["--allow-security-regression", "--reason", "  "],
                                  ["--reason", "why"]])
def test_override_without_reason_rejected(monkeypatch, args) -> None:
    from boxmunge.commands import stage_cmd
    monkeypatch.setattr(stage_cmd, "run_stage", lambda *a, **k: pytest.fail("ran"))
    with pytest.raises(SystemExit) as e:
        stage_cmd.cmd_stage(["demo", *args])
    assert e.value.code == 2


def test_override_with_reason_proceeds_and_is_audited(box, monkeypatch, capsys) -> None:
    pushover = Pushover(monkeypatch, box.paths)
    box.paths.logs.mkdir(parents=True, exist_ok=True)
    _carry_kev(box)
    with guard.regression_override(box.paths, "demo", "not reachable: libc unused"):
        _guard(box)
        _guard(box)  # a rollback decides its release twice: recorded once
    out = capsys.readouterr().out
    assert "--allow-security-regression: deploying to production although" in out
    assert "nothing to override" not in out
    entries = [json.loads(line) for line in box.paths.log_file.read_text().splitlines()]
    logged = [e for e in entries if "past the deploy guard" in e["msg"]]
    assert len(logged) == 1 and logged[0]["level"] == "warn"
    assert logged[0]["detail"]["reason"] == "not reachable: libc unused"
    assert any(KEV_CVE in p for p in logged[0]["detail"]["problems"])
    (title, body, priority), = pushover.sent
    assert "deployed past the deploy guard" in title and priority == 0
    assert "not reachable: libc unused" in body and KEV_CVE in body


def test_an_override_nothing_needed_says_so(box, capsys) -> None:
    with guard.regression_override(box.paths, "demo", "just in case"):
        _guard(box)
    assert ("--allow-security-regression: nothing to override: the deploy guard found no "
            "known-exploited CVE") in capsys.readouterr().out
    with guard.regression_override(box.paths, "demo", "just in case"):
        pass
    assert "the deploy stopped before the deploy guard ran" in capsys.readouterr().out


def test_a_scan_that_cannot_be_kept_still_stands(box, monkeypatch, capsys) -> None:
    from boxmunge.cve.scan_cache import ScanCache

    def full(*a):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(ScanCache, "put", full)
    _guard(box)
    assert "WARNING: keeping the scan of" in capsys.readouterr().out

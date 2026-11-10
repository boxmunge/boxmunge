# SPDX-License-Identifier: Apache-2.0
"""`prod-deploy <project> --accept-stale-kev` carries the audited acceptance
through a deploy to its quarantine gate (commands/kev_acceptance), as
`security resume --accept-stale-kev` does for a lift: only with no usable
KEV catalog, logged before anything starts, alerted with the lift."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands import deploy as deploy_cmd
from boxmunge.commands import quarantine_gate as gate
from boxmunge.commands.deploy import cmd_deploy, run_deploy
from boxmunge.commands.kev_acceptance import (
    accept_at_gate, gate_exits, prod_deploy_acceptance,
)
from boxmunge.cve.lift_rule import KevLiftCheck
from boxmunge.cve.quarantine import clear_quarantine_state
from boxmunge.project_registry import add_project
from boxmunge.release_target import production_target
from tests.test_commands.cve_helpers import BALANCED, finding, make_clearance, seed_quarantine
from tests.test_commands.test_deploy import _place_deploy_bundle
from tests.test_commands.test_stale_kev_lift import (
    KEV_CVE, OTHER_CVE, _manifest, _write_kev, make_gate_box,
)


@pytest.fixture
def gate_box(tmp_path, monkeypatch):
    return make_gate_box(tmp_path, monkeypatch)


def _clear(paths, accepted: bool):
    with prod_deploy_acceptance(paths, "demo", accepted):
        return gate.clear_release(paths, production_target(paths, "demo"), _manifest())


def test_with_no_catalog_the_release_clears_logged_before_the_start(gate_box, capsys) -> None:
    seed_quarantine(gate_box, cve_id=OTHER_CVE)
    gate_box.logs.mkdir(parents=True, exist_ok=True)
    clearance = _clear(gate_box, True)
    assert clearance.kev_accepted is not None
    assert "no usable CISA KEV catalog" in clearance.kev_accepted
    out = capsys.readouterr().out
    assert "--accept-stale-kev: deploying although" in out and "may go live" in out
    assert "--accept-stale-kev: release cleared" in gate_box.log_file.read_text()
    message, detail = gate._lift_report(clearance, "v2")
    assert "Lifted with --accept-stale-kev, although" in message
    assert detail["kev_accepted"] == clearance.kev_accepted


def test_it_never_overrides_a_stale_catalog_listing_a_cve_in_the_images(gate_box) -> None:
    gate_box.scan_findings = [finding(KEV_CVE)]
    _write_kev(gate_box, KEV_CVE, age_days=20)
    with pytest.raises(gate.QuarantineRefused) as e:
        _clear(gate_box, True)
    assert "--accept-stale-kev does not apply" in str(e.value)


@pytest.mark.parametrize("age,needle", [(0, "the KEV catalog is fresh"),
                                        (20, "stale but lists no CVE in the images")])
def test_with_nothing_to_accept_it_says_why(gate_box, capsys, age, needle) -> None:
    seed_quarantine(gate_box, cve_id=OTHER_CVE)
    _write_kev(gate_box, KEV_CVE, age_days=age)
    assert _clear(gate_box, True).kev_accepted is None
    out = capsys.readouterr().out
    assert "--accept-stale-kev: nothing to accept" in out and needle in out


def test_a_prod_deploy_without_it_is_offered_the_flag(gate_box) -> None:
    seed_quarantine(gate_box, cve_id=OTHER_CVE)
    with pytest.raises(gate.QuarantineRefused) as e:
        _clear(gate_box, False)
    text = str(e.value)
    assert "`prod-deploy demo --redeploy --accept-stale-kev`" in text
    assert "security resume" not in text


def test_the_lift_alerts_at_priority_one(gate_box, monkeypatch, capsys) -> None:
    clearance = make_clearance("demo", before=BALANCED)
    clearance = gate.Clearance(**{**clearance.__dict__, "kev_accepted": "no usable catalog"})
    sent = []
    monkeypatch.setattr(gate, "_verify_running", lambda *a, **k: {})
    monkeypatch.setattr(gate, "_release_policies", lambda *a: {})
    monkeypatch.setattr(gate, "lift_quarantine", lambda *a, **k: None)
    monkeypatch.setattr(gate, "notify", lambda p, title, body, **kw: sent.append(
        (title, kw["priority"])))
    site = gate_box.project_caddy_site("demo")
    site.parent.mkdir(parents=True, exist_ok=True)
    site.write_text("site")
    assert gate.lift_after_deploy(gate_box, "demo", "v2", clearance, txn=None,
                                  component="deploy") == 0
    assert sent == [("demo: quarantine lifted by deploying v2 with --accept-stale-kev", 1)]


def test_the_flag_unused_says_it_did_nothing(gate_box, capsys) -> None:
    with prod_deploy_acceptance(gate_box, "demo", True):
        pass
    assert "nothing to accept: the deploy stopped before" in capsys.readouterr().out


def test_abandon_takes_no_accept_flag(capsys) -> None:
    with pytest.raises(SystemExit):
        cmd_deploy(["demo", "--abandon", "--accept-stale-kev"])
    assert "--abandon takes no other options" in capsys.readouterr().err


# ---- end to end: the refusal names a command that gets the release through ----

NO_CATALOG = KevLiftCheck("no KEV catalog has been fetched yet", acceptable=True,
                          refusal="there is no usable CISA KEV catalog")


@patch("boxmunge.compose_guard.compose_up")
@patch("boxmunge.commands.deploy.caddy_reload")
def test_the_offered_command_deploys_the_refused_release(mock_reload, mock_up, paths,
                                                         monkeypatch, capsys) -> None:
    add_project("testapp", paths)
    _place_deploy_bundle(paths)
    seed_quarantine(paths, "testapp")
    cleared = make_clearance("testapp", {"web": ("nginx", "sha256:x")}, before=BALANCED)

    def clear(paths_, target, manifest, previous):
        """The gate's KEV step on a box with no catalog, scan stubbed clear."""
        accepted = accept_at_gate("testapp", NO_CATALOG, paths_)
        if accepted is None:
            raise gate.QuarantineRefused(gate_exits("testapp", NO_CATALOG, paths_))
        return gate.Clearance(**{**cleared.__dict__, "kev_accepted": accepted})
    monkeypatch.setattr("boxmunge.commands.release_config.clear_release", clear)
    monkeypatch.setattr("boxmunge.commands.release_config.remove_candidates", lambda p: None)
    monkeypatch.setattr("boxmunge.commands.deploy_tree.require_unchanged", lambda *a: None)
    monkeypatch.setattr(gate, "_verify_running", lambda *a, **k: {})
    monkeypatch.setattr(gate, "_release_policies", lambda *a: {})
    monkeypatch.setattr(gate, "lift_quarantine",
                        lambda project, paths_, **kw: clear_quarantine_state(project, paths_))

    with prod_deploy_acceptance(paths, "testapp", False):
        assert run_deploy("testapp", paths) == 1
    err = capsys.readouterr().err
    offered = err.split("deploy it anyway: `")[1].split("`")[0]
    assert offered.startswith("prod-deploy testapp ") and offered.endswith(" --accept-stale-kev")

    monkeypatch.setattr(deploy_cmd, "BoxPaths", lambda: paths)
    with pytest.raises(SystemExit) as e:
        cmd_deploy(offered.split()[1:])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert "Lifted with --accept-stale-kev" in out
    assert not paths.project_quarantine_state("testapp").exists()

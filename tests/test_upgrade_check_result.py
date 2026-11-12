# SPDX-License-Identifier: Apache-2.0
"""The upgrade shim's check verdict (K3), read and shown on the deploy side
(boxmunge.upgrade_check_result)."""
from __future__ import annotations

import json
from typing import Any

import pytest

from boxmunge.upgrade_check_result import check_to_json, parse_check, render_check

TARGET, INSTALLED = "0.12.0", "0.11.8"
PREREQS = [{"script": "bootstrap/upgrade-floor.sh", "ok": True, "message": ""},
           {"script": "bootstrap/python-floor.sh", "ok": True, "message": ""}]


def finding(fid: str, severity: str = "todo", message: str = "msg", remedy: str = "fix it",
            when: str = "before") -> dict[str, str]:
    return {"id": fid, "severity": severity, "when": when, "message": message,
            "remedy": remedy}


def readiness(projects: list[tuple[str, list[dict]]] | None = None, box: list[dict] = (),
              release: str = TARGET, **extra: Any) -> dict[str, Any]:
    projects = [("app", []), ("web", [])] if projects is None else projects
    rows = [{"name": name, "findings": fs,
             "result": "blocked" if any(f["severity"] == "block" for f in fs) else "pass"}
            for name, fs in projects]
    blocked = any(f["severity"] == "block" for f in box) or any(
        r["result"] == "blocked" for r in rows)
    return {"contract": 1, "release": release, "installed": INSTALLED,
            "result": "blocked" if blocked else "pass", "box": list(box), "projects": rows,
            **extra}


def k3(result: str = "pass", stage: str = "complete", **fields: Any) -> dict[str, Any]:
    doc = {"check": 1, "target": TARGET, "installed": INSTALLED, "result": result,
           "stage": stage, "reasons": [], "prerequisites": PREREQS,
           "readiness": readiness(), "dry_run": {"ok": True, "output": "dry run ok\n"}}
    return {**doc, **fields}


def parse(doc: Any, rc: int | None = None, stderr: str = "", target: str = TARGET):
    stdout = doc if isinstance(doc, str) else json.dumps(doc) + "\n"
    if rc is None:
        rc = 0 if isinstance(doc, dict) and doc.get("result") == "pass" else 1
    return parse_check(stdout, stderr, rc, target=target, installed=INSTALLED)


def test_parse_pass_blocked_cantverify() -> None:
    assert parse(k3()).result == "pass"
    blocked = parse(k3("blocked", readiness=readiness(
        [("app", [finding("project.image_missing", "block")])]),
        reasons=["the readiness check found what blocks the upgrade"]))
    assert blocked.result == "blocked" and blocked.readiness is not None
    cant = parse(k3("cant_verify", "fetch", reasons=["download failed"], prerequisites=[],
                    readiness=None, dry_run=None))
    assert (cant.result, cant.stage, cant.reasons) == ("cant_verify", "fetch",
                                                       ("download failed",))


@pytest.mark.parametrize("stdout", ["", "Usage: boxmunge-upgrade check <version>\n",
                                    "[1, 2]", '{"no": "check key"}', "{" * 50_000])
def test_non_json_stdout_is_cant_verify_with_stderr_tail(stdout: str) -> None:
    stderr = "y" * 1000 + " FATAL: No installed version recorded\x1b[0m"
    r = parse(stdout, rc=1, stderr=stderr)
    assert r.result == "cant_verify" and r.stage == "shim"
    (reason,) = r.reasons
    assert reason.startswith("the upgrade shim gave no verdict: ")
    assert reason.endswith("FATAL: No installed version recorded[0m")
    assert len(reason) <= len("the upgrade shim gave no verdict: ") + 400
    assert r.readiness is None and r.dry_run_ok is None


def test_a_sudo_refusal_names_install_sudoers() -> None:
    r = parse("", rc=1, stderr="sudo: a password is required\n")
    assert any("boxmunge-upgrade install-sudoers" in reason for reason in r.reasons)


@pytest.mark.parametrize("change", [
    {"check": 2}, {"check": True}, {"result": "maybe"}, {"stage": "later"},
    {"reasons": "one"}, {"reasons": [1]}, {"prerequisites": [{"script": "x", "ok": "yes",
                                                               "message": ""}]},
    {"dry_run": {"ok": 1, "output": ""}}, {"dry_run": "ok"}, {"installed": "eleven"},
    {"target": None},
])
def test_a_verdict_outside_k3_is_cant_verify_naming_it(change: dict) -> None:
    r = parse(k3(**change), rc=0)
    assert r.result == "cant_verify" and r.stage == "shim"
    assert r.reasons[0].startswith("the upgrade shim's verdict is not one this release reads")


def test_embedded_readiness_contract_2_is_cant_verify() -> None:
    r = parse(k3(readiness={**readiness(), "contract": 2}))
    assert r.result == "cant_verify"
    assert "contract 2" in " ".join(r.reasons)


def test_a_verdict_for_another_release_is_refused() -> None:
    r = parse(k3(target="0.11.9"))
    assert r.result == "cant_verify" and "0.11.9" in r.reasons[0] and TARGET in r.reasons[0]


def test_a_readiness_answer_from_another_release_is_refused() -> None:
    """A signed older release's bundle replayed under the target's name runs
    that release's readiness command."""
    r = parse(k3(readiness=readiness(release="0.11.9")))
    assert r.result == "cant_verify"
    assert "0.11.9" in r.reasons[0] and TARGET in r.reasons[0]


@pytest.mark.parametrize("change", [
    {"readiness": None},
    {"readiness": readiness([("app", [finding("project.compose", "block")])])},
    {"dry_run": {"ok": False, "output": "refused"}}, {"dry_run": None},
    {"prerequisites": [{"script": "bootstrap/python-floor.sh", "ok": False, "message": "old"}]},
])
def test_a_pass_its_own_parts_contradict_is_cant_verify(change: dict) -> None:
    r = parse(k3(**change), rc=0)
    assert r.result == "cant_verify" and "pass" in r.reasons[0]


@pytest.mark.parametrize("result,rc", [("pass", 1), ("blocked", 0)])
def test_an_exit_code_that_contradicts_the_verdict_is_cant_verify(result: str, rc: int) -> None:
    r = parse(k3(result), rc=rc)
    assert r.result == "cant_verify" and "exit" in r.reasons[0]


def test_unknown_keys_are_ignored() -> None:
    assert parse(k3(later={"x": 1}, readiness=readiness(later=True))).result == "pass"


def test_render_lists_every_project_even_when_passing() -> None:
    text = render_check(parse(k3()))
    assert text.startswith("Result: PASS (complete)")
    projects = text[text.index("Projects:"):]
    assert "app: pass, nothing to do" in projects and "web: pass, nothing to do" in projects
    assert "upgrade --target 0.12.0" in text
    assert "do not upgrade" not in text


def test_render_blocked_per_project_with_fixes() -> None:
    r = parse(k3("blocked", reasons=["the readiness check found what blocks the upgrade"],
                 readiness=readiness(
                     [("app", [finding("project.image_missing", "block", "image gone",
                                       "prod-deploy app --redeploy")]),
                      ("web", [finding("project.validate", message="bad key",
                                       remedy="fix manifest.yml")])],
                     box=[finding("box.compose_version", "block", "compose too old",
                                  "upgrade compose")])))
    text = render_check(r)
    assert text.startswith("Result: BLOCKED (complete)")
    lines = text.splitlines()
    assert "the readiness check found what blocks the upgrade" in text
    box = text[text.index("Box:"):text.index("Projects:")]
    assert "bootstrap/python-floor.sh: met" in box
    assert "[block, before] box.compose_version: compose too old" in box
    app = lines.index("  app: blocked")
    assert lines[app + 1].strip() == "[block, before] project.image_missing: image gone"
    assert lines[app + 2].strip() == "Fix: prod-deploy app --redeploy"
    assert "  web: pass" in lines
    assert text.rstrip().endswith(
        "Result is not PASS: do not upgrade. Report this to the person, per project.")


def test_render_shows_the_dry_run_tail_only_when_it_failed() -> None:
    passing = render_check(parse(k3()))
    assert "dry run ok" not in passing
    failed = render_check(parse(k3("blocked", "dry_run", reasons=["pre-flight refused"],
                                   dry_run={"ok": False, "output": "REFUSED: app: bad\n"})))
    assert "REFUSED: app: bad" in failed


def test_prerequisite_failure_says_projects_not_checked() -> None:
    r = parse(k3("blocked", "prerequisites", reasons=["this box does not meet what 0.12.0 "
                                                      "needs"],
                 prerequisites=[{"script": "bootstrap/python-floor.sh", "ok": False,
                                 "message": "Python 3.11 is older than 3.13"}],
                 readiness=None, dry_run=None))
    assert r.result == "blocked"
    text = render_check(r)
    assert "bootstrap/python-floor.sh: NOT MET: Python 3.11 is older than 3.13" in text
    projects = text[text.index("Projects:"):]
    assert "not checked" in projects and "prerequisite" in projects


def test_render_strips_nonprintable() -> None:
    r = parse(k3("blocked", reasons=["re\x1b[2Json"], readiness=readiness(
        [("app", [finding("project.compose", "block", "bad\x07 line‮", "fi\rx")])])))
    text = render_check(r)
    assert all(c == "\n" or c.isprintable() for c in text)
    assert "bad line" in text and "Fix: fix" in text


def test_exit_code_0_only_on_pass() -> None:
    from boxmunge.upgrade_check_result import exit_code
    assert exit_code(parse(k3())) == 0
    assert exit_code(parse(k3("blocked", readiness=readiness(
        [("a", [finding("project.compose", "block")])])))) == 1
    assert exit_code(parse("", rc=0)) == 1


def test_check_to_json_is_k3_again() -> None:
    doc = k3(later="dropped")
    again = check_to_json(parse(doc))
    assert again["check"] == 1 and again["result"] == "pass"
    assert again["readiness"]["projects"][0]["name"] == "app"
    assert again["dry_run"] == {"ok": True, "output": "dry run ok\n"}
    assert "later" not in again
    no_verdict = check_to_json(parse("", rc=1, stderr="boom"))
    assert no_verdict["stage"] == "shim" and no_verdict["readiness"] is None
    assert no_verdict["dry_run"] is None and no_verdict["target"] == TARGET

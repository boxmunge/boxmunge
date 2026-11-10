# SPDX-License-Identifier: Apache-2.0
"""scripts/lock-freshness.py: a release pull request fails while a runtime
lock (the pyproject extras Dependabot never regenerates) has fallen behind
its pins' same-major releases."""
from __future__ import annotations

import datetime as dt
import importlib.util
import io
import urllib.error
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
RUNTIME_LOCKS = ["requirements.txt", "requirements-tui.txt", "requirements-mcp.txt",
                 "cli/requirements.txt"]

_spec = importlib.util.spec_from_file_location("lock_freshness", REPO / "scripts" / "lock-freshness.py")
lf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lf)

NOW = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)


def _release(days_ago: int, yanked: bool = False) -> list[dict]:
    when = (NOW - dt.timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return [{"upload_time_iso_8601": when, "yanked": yanked}]


def test_pins_reads_names_and_versions_with_extras() -> None:
    text = "pyjwt[crypto]==2.15.1 \\\n    --hash=sha256:aa\n    # via mcp\nmcp==1.30.0 \\\n"
    assert lf.pins(text) == {"pyjwt": "2.15.1", "mcp": "1.30.0"}


def test_a_same_major_release_older_than_the_limit_is_overdue() -> None:
    releases = {"1.2.0": _release(100), "1.3.0": _release(20), "1.4.0": _release(3)}
    assert lf.overdue("1.2.0", releases, NOW, max_age_days=14) == "1.3.0"


def test_a_release_still_inside_the_limit_is_not_overdue() -> None:
    releases = {"1.2.0": _release(100), "1.3.0": _release(10)}
    assert lf.overdue("1.2.0", releases, NOW, max_age_days=14) is None


def test_majors_prereleases_and_yanked_releases_are_never_overdue() -> None:
    releases = {"1.2.0": _release(100), "2.0.0": _release(90), "1.3.0rc1": _release(90),
                "1.3.0": _release(90, yanked=True), "1.4.0": []}
    assert lf.overdue("1.2.0", releases, NOW, max_age_days=14) is None


def test_main_names_each_overdue_pin_and_the_fix(capsys) -> None:
    lock = REPO / "requirements-mcp.txt"
    current = lf.pins(lock.read_text())

    def fetch(name: str) -> dict:
        out = {current[name]: _release(100)}
        if name == "starlette":  # a minor of the pinned major, out for 30 days
            out[f"{current[name].split('.')[0]}.9999.0"] = _release(30)
        return out

    assert lf.main([str(lock)], fetch=fetch, now=NOW) == 1
    err = capsys.readouterr().err
    assert "starlette" in err and "make relock" in err


def test_main_passes_when_every_pin_is_current() -> None:
    lock = REPO / "requirements-mcp.txt"
    current = lf.pins(lock.read_text())
    assert lf.main([str(lock)], fetch=lambda n: {current[n]: _release(100)}, now=NOW) == 0


def test_release_pull_requests_check_every_runtime_lock() -> None:
    """The release pull request (a release/* branch) is where the locks must
    be fresh; the runtime locks are the ones `make relock` writes."""
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    steps = [s for s in ci["jobs"]["unit"]["steps"] if "lock-freshness.py" in s.get("run", "")]
    assert len(steps) == 1, "the unit job runs scripts/lock-freshness.py once"
    assert steps[0]["if"] == "startsWith(github.head_ref, 'release/')"
    assert steps[0]["run"].split()[2:] == RUNTIME_LOCKS
    makefile = (REPO / "Makefile").read_text()
    runtime = makefile.split("\nlock-runtime:\n")[1].split("\n\n")[0]
    assert sorted(runtime.count(f"-o {lock} ") for lock in RUNTIME_LOCKS) == [1] * 4


def test_a_calendar_versioned_package_is_overdue_across_a_new_year() -> None:
    """certifi ships CA removals as its next year's release: a year is not a major."""
    releases = {"2026.10.23": _release(100), "2027.1.15": _release(30)}
    assert lf.overdue("2026.10.23", releases, NOW, max_age_days=14) == "2027.1.15"


def test_a_calendar_versioned_release_inside_the_limit_is_not_overdue() -> None:
    releases = {"2026.10.23": _release(100), "2027.1.15": _release(10)}
    assert lf.overdue("2026.10.23", releases, NOW, max_age_days=14) is None


def test_an_oversized_pypi_answer_is_refused_naming_the_package(monkeypatch) -> None:
    monkeypatch.setattr(lf, "MAX_RESPONSE_BYTES", 16)
    with pytest.raises(lf.FetchError, match=r"^certifi: .*refusing to read it"):
        lf.read_releases(io.BytesIO(b'{"releases": {"1.0": []}}'), "certifi")


def test_a_pypi_answer_within_the_limit_is_read() -> None:
    assert lf.read_releases(io.BytesIO(b'{"releases": {"1.0": []}}'), "x") == {"1.0": []}


def test_a_network_error_names_the_package_and_exits_without_a_traceback(
        monkeypatch, tmp_path, capsys) -> None:
    def refuse(url, timeout):
        raise urllib.error.URLError("Name or service not known")

    monkeypatch.setattr(lf.urllib.request, "urlopen", refuse)
    lock = tmp_path / "requirements.txt"
    lock.write_text("pyyaml==6.0.3 \\\n    --hash=sha256:aa\n")
    assert lf.main([str(lock)], now=NOW) == 2
    err = capsys.readouterr().err
    assert "pyyaml: could not fetch https://pypi.org/pypi/pyyaml/json" in err
    assert "Traceback" not in err

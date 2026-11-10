# SPDX-License-Identifier: Apache-2.0
"""`boxmunge security` shows which KEV source answered and whether the
catalog is fresh (issue #121)."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

from boxmunge.commands.security_cmd import cmd_security
from tests.test_commands.cve_helpers import make_box

MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"


def _run(monkeypatch, paths, *args: str) -> str:
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_security(list(args))
    return buf.getvalue()


def _seed(paths, released: datetime) -> None:
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": MIRROR, "released_at": released.isoformat(),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cve_ids": ["CVE-2026-1", "CVE-2026-2"]}))


def test_text_view_names_the_source_and_release(monkeypatch, tmp_path) -> None:
    paths = make_box(tmp_path)
    _seed(paths, datetime.now(timezone.utc) - timedelta(days=1))
    out = _run(monkeypatch, paths)
    assert "CISA KEV catalog: fresh" in out
    assert f"source:   {MIRROR}" in out
    assert "entries:  2" in out


def test_text_view_says_why_a_lagging_catalog_is_stale(monkeypatch, tmp_path) -> None:
    paths = make_box(tmp_path)
    _seed(paths, datetime.now(timezone.utc) - timedelta(days=40))
    out = _run(monkeypatch, paths)
    assert "CISA KEV catalog: STALE" in out
    assert "why:      the catalog is lagging" in out


def test_json_view_carries_the_kev_block(monkeypatch, tmp_path) -> None:
    paths = make_box(tmp_path)
    _seed(paths, datetime.now(timezone.utc))
    kev = json.loads(_run(monkeypatch, paths, "--json"))["kev"]
    assert kev["source"] == MIRROR and kev["entries"] == 2 and kev["stale_reason"] is None


def test_json_view_on_an_empty_box_carries_the_kev_block(monkeypatch, tmp_path) -> None:
    paths = make_box(tmp_path, projects=())
    kev = json.loads(_run(monkeypatch, paths, "--json"))["kev"]
    assert kev["source"] is None and kev["stale_reason"] == "no KEV catalog has been fetched yet"

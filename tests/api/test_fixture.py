# SPDX-License-Identifier: Apache-2.0
"""The dev fixture box: written in the platform's own formats, never a real box."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from boxmunge.api.dev.fixture import (
    FIXTURE_MARKER, FixtureError, make_fixture, require_fixture,
)
from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.jobs import JobStore
from boxmunge.backup import snapshot_kind
from boxmunge.commands.backup_cmd import list_snapshots
from boxmunge.commands.inbox_cmd import collect_inbox
from boxmunge.commands.log_cmd import parse_log_file
from boxmunge.commands.security_cmd import load_project_security
from boxmunge.commands.status import collect_status
from boxmunge.config import load_config
from boxmunge.project_registry import load_registered_projects
from tests.api.fakes import registry_results

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)


def test_fixture_reads_back_through_the_platform_readers(tmp_path) -> None:
    paths = make_fixture(tmp_path / "box", now=NOW)
    require_fixture(paths.root)
    assert load_config(paths)["hostname"] == "box.example.test"
    assert sorted(load_registered_projects(paths)) == [
        "billing", "blog", "newapp", "shop", "wiki"]
    snapshot = collect_status(paths)
    assert snapshot.failures == []
    assert {row["project"]: row["state"] for row in snapshot.rows} == {
        "shop": "ok", "blog": "paused", "billing": "quarantined",
        "wiki": "failing", "newapp": "pre_registered",
    }
    assert [snapshot_kind(p, "shop").value for p in list_snapshots(paths, "shop")] == [
        "predeploy", "nightly", "manual"]
    assert load_project_security("billing", paths).quarantined is True
    assert [b["project"] for b in collect_inbox(paths, None)] == ["shop", "wiki"]
    assert {e["level"] for e in parse_log_file(paths.log_file).entries} == {"info", "warn", "error"}
    jobs = JobStore(paths, result_schemas=registry_results).recent().jobs
    assert [(j["action"], j["state"]) for j in jobs] == [
        ("project.deploy", "succeeded"), ("project.backup", "failed")]
    assert len(JobStore(paths, result_schemas=registry_results).events(jobs[0]["id"])) == 7


def test_fixture_host_serves_the_canned_answers(tmp_path) -> None:
    paths = make_fixture(tmp_path / "box", now=NOW)
    host = FixtureHost(paths)
    assert host.health_report()["exit_code"] == 1
    assert host.project_check("wiki")["status"] == "warning"
    web = host.container_logs("shop", "web", 5).splitlines()
    assert len(web) == 5 and all(line.startswith("shop-web-1  | ") for line in web)
    both = host.container_logs("shop", None, 100).splitlines()
    assert len(both) == 60


def test_fixture_refuses_a_directory_with_content(tmp_path) -> None:
    (tmp_path / "box").mkdir()
    (tmp_path / "box" / "keep.txt").write_text("mine")
    with pytest.raises(FixtureError, match="not an empty directory"):
        make_fixture(tmp_path / "box")
    assert (tmp_path / "box" / "keep.txt").read_text() == "mine"


def test_a_real_box_layout_is_not_a_fixture(paths) -> None:
    paths.config_file.write_text("hostname: real.example.test\nadmin_email: a@b.test\n")
    with pytest.raises(FixtureError, match=f"no {FIXTURE_MARKER} file"):
        require_fixture(paths.root)

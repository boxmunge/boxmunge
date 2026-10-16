"""Reruns resume; a different deploy fixes forward; the bundle may be gone."""
from __future__ import annotations

from boxmunge.commands.deploy import run_deploy
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn
from tests.bundle_helpers import manifest_text, place_bundle
from tests.txn_helpers import (
    crash_at, docker_off, fake_backups, flaky_hook, hook_manifest, hook_runs,
)

V1, V2, V3 = ("2026-10-16T090000000000", "2026-10-16T100000000000",
              "2026-10-16T110000000000")


def _prod_v1(paths):
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0


def test_rerun_after_a_failed_hook_reruns_it_and_reuses_the_snapshot(paths, tmp_path) -> None:
    _prod_v1(paths)
    place_bundle(paths, timestamp=V2, files={
        "manifest.yml": hook_manifest(flaky_hook(tmp_path), backup="postgres")})
    taken: list[dict] = []
    with docker_off(), fake_backups(taken):
        assert run_deploy("myapp", paths, ref=V2) == 1
        kept = (paths.project_releases("myapp") / "previous.json").read_text()
        assert run_deploy("myapp", paths) == 0   # the bundle was consumed at `installed`
    assert hook_runs(tmp_path) == 2 and len(taken) == 1
    assert (paths.project_releases("myapp") / "previous.json").read_text() == kept
    assert load_txn(paths, "myapp") is None


def test_resume_at_switching_skips_hook_and_snapshot(paths, tmp_path) -> None:
    _prod_v1(paths)
    place_bundle(paths, timestamp=V2, files={
        "manifest.yml": hook_manifest(flaky_hook(tmp_path, failures=0), backup="postgres")})
    taken: list[dict] = []
    with docker_off(), fake_backups(taken):
        assert crash_at("txn.switching", lambda: run_deploy("myapp", paths, ref=V2)) == 137
        assert load_txn(paths, "myapp").phase == "switching"
        assert run_deploy("myapp", paths) == 0
    # The snapshot was taken in the crashed child; the rerun takes none.
    assert hook_runs(tmp_path) == 1 and taken == []


def test_resume_without_the_bundle_before_installed_names_abandon(paths, capsys) -> None:
    """Review Focus 1."""
    _prod_v1(paths)
    bundle = place_bundle(paths, timestamp=V2)
    with docker_off():
        assert crash_at("txn.previous_kept", lambda: run_deploy("myapp", paths, ref=V2)) == 137
        bundle.unlink()
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "prod-deploy myapp --abandon" in err and f"myapp-{V2}" in err
    assert load_txn(paths, "myapp").phase == "previous_kept"


def test_fix_forward_inherits_the_rollback_pairing(paths) -> None:
    _prod_v1(paths)
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest("false", "postgres")})
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    taken: list[dict] = []
    with docker_off(), fake_backups(taken):
        assert run_deploy("myapp", paths, ref=V2) == 1
        assert run_deploy("myapp", paths, ref=V3) == 0
    assert len(taken) == 1   # no snapshot of data the failed hook may have changed
    meta = (paths.project_releases("myapp") / "previous.json").read_text()
    assert f'"ref": "myapp-{V1}"' in meta and "myapp-p1.tar.gz.age" in meta


def test_fix_forward_resolves_an_always_failing_first_deploy(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"manifest.yml": hook_manifest("false")})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 1
        assert run_deploy("myapp", paths, ref=V2) == 0
    assert (paths.project_dir("myapp") / "VERSION").read_text() == "v2\n"
    assert not (paths.project_releases("myapp") / "previous").exists()


def test_fix_forward_at_committed_starts_over(paths) -> None:
    _prod_v1(paths)
    place_bundle(paths, timestamp=V2)
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with docker_off():
        assert crash_at("txn.committed", lambda: run_deploy("myapp", paths, ref=V2)) == 137
        assert run_deploy("myapp", paths, ref=V3) == 0
    assert '"ref": "myapp-' + V1 in (paths.project_releases("myapp") / "previous.json").read_text()


def test_dry_run_never_resumes_an_open_install(paths, capsys) -> None:
    _prod_v1(paths)
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest("false")})
    with docker_off() as up:
        assert run_deploy("myapp", paths, ref=V2) == 1
        up.reset_mock()
        assert run_deploy("myapp", paths, dry_run=True) == 0
        up.assert_not_called()
    assert load_txn(paths, "myapp").phase == "hook_started"
    assert "[DRY RUN] Would resume" in capsys.readouterr().out

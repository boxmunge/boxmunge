"""unstage takes staging down and drops the slot; production is not touched."""
from __future__ import annotations

from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.docker_run import DockerError
from boxmunge.release_txn import open_txn
from boxmunge.staged_release import load_slot, slot_dir, update_meta
from tests.bundle_helpers import tree_snapshot
from tests.stage_helpers import V1, prod_and_stage, staging_docker_off


def _production(paths) -> dict:
    return {k: v for k, v in tree_snapshot(paths.project_dir("myapp")).items()
            if not k.startswith(".releases/staged")}


def test_unstage_drops_the_slot(paths) -> None:
    prod_and_stage(paths)
    before = _production(paths)
    with staging_docker_off() as docker:
        assert run_unstage("myapp", paths) == 0
    assert docker["down"].call_args.kwargs["project_directory"] == slot_dir(paths, "myapp") / "release"
    assert load_slot(paths, "myapp") is None and _production(paths) == before
    assert not paths.project_bind_record("myapp", staging=True).exists()


def test_failed_down_records_cleanup_incomplete_and_keeps_the_slot(paths) -> None:
    prod_and_stage(paths)
    with staging_docker_off() as docker:
        docker["down"].side_effect = DockerError("daemon gone")
        assert run_unstage("myapp", paths) == 1
    assert load_slot(paths, "myapp").cleanup_incomplete == "daemon gone"


def test_unstage_with_unreadable_meta_still_tears_down(paths) -> None:
    """Review Focus 2."""
    prod_and_stage(paths)
    (slot_dir(paths, "myapp") / "meta.json").write_text("{broken")
    with staging_docker_off() as docker:
        assert run_unstage("myapp", paths) == 0
    docker["down"].assert_called_once()
    assert not slot_dir(paths, "myapp").exists()


def test_unstage_refused_while_promoting_this_slot(paths, capsys) -> None:
    prod_and_stage(paths)
    meta = load_slot(paths, "myapp")
    open_txn(paths, "myapp", source="staged", ref=meta.ref, replaced_ref=f"myapp-{V1}",
             staged_id=meta.id, snapshot="")
    with staging_docker_off():
        assert run_unstage("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "promote myapp" in err and "--abandon" in err


def test_unstage_restarts_production_first_if_a_copy_stopped_it(paths, fake_containers) -> None:
    from unittest.mock import patch
    prod_and_stage(paths)
    fake_containers.run("myapp", "web", "sha256:1", running=False)
    update_meta(paths, "myapp", load_slot(paths, "myapp"),
                production_stopped={"at": "t", "containers": ["myapp-web-1"]})
    with staging_docker_off(), \
            patch("boxmunge.production_stopped.start_containers_checked") as start, \
            patch("boxmunge.production_stopped.notify"):
        assert run_unstage("myapp", paths) == 0
    start.assert_called_once()


def test_unstage_refused_while_a_staged_install_is_open_and_meta_is_unreadable(
        paths, capsys) -> None:
    """The open promote's slot cannot be told apart from this one: never
    drop a slot an open staged install may need."""
    prod_and_stage(paths)
    meta = load_slot(paths, "myapp")
    open_txn(paths, "myapp", source="staged", ref=meta.ref, replaced_ref=f"myapp-{V1}",
             staged_id=meta.id, snapshot="")
    (slot_dir(paths, "myapp") / "meta.json").write_text("{broken")
    with staging_docker_off() as docker:
        assert run_unstage("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "promote myapp" in err and "--abandon" in err
    docker["down"].assert_not_called()
    assert slot_dir(paths, "myapp").is_dir()


def test_unstage_goes_ahead_beside_a_bundle_install(paths) -> None:
    prod_and_stage(paths)
    open_txn(paths, "myapp", source="bundle", ref="myapp-x", replaced_ref=f"myapp-{V1}",
             staged_id=None, snapshot="")
    with staging_docker_off():
        assert run_unstage("myapp", paths) == 0
    assert load_slot(paths, "myapp") is None


def test_unstage_removes_a_leftover_site_without_a_slot(paths) -> None:
    prod_and_stage(paths)
    with staging_docker_off():
        assert run_unstage("myapp", paths) == 0
    site = paths.project_staging_caddy_site("myapp")
    site.write_text("staging.myapp.example.com {}\n")
    with staging_docker_off() as docker:
        assert run_unstage("myapp", paths) == 0
        docker["down"].assert_not_called()
        assert run_unstage("myapp", paths) == 1
    assert not site.exists()


def test_unstage_dry_run_changes_nothing(paths, capsys) -> None:
    prod_and_stage(paths)
    before = tree_snapshot(paths.project_dir("myapp"))
    with staging_docker_off() as docker:
        assert run_unstage("myapp", paths, dry_run=True) == 0
    docker["down"].assert_not_called()
    assert tree_snapshot(paths.project_dir("myapp")) == before


def test_unstage_removes_copies_only_the_staged_release_used(paths) -> None:
    """The staged release's own data dirs are never recorded in production's
    tree; their -staging copies are still staging's, and go with it."""
    from tests.bundle_helpers import SAFE_COMPOSE
    pdir = prod_and_stage(
        paths, prod_files={"compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"},
        staged_files={"compose.yml": SAFE_COMPOSE + "    volumes: ['./media:/m', './uploads:/u']\n"})
    assert (pdir / "media-staging").is_dir() and (pdir / "uploads-staging").is_dir()
    (pdir / "uploads-staging" / "kept").write_text("staging's own")
    with staging_docker_off():
        assert run_unstage("myapp", paths) == 0
    assert not (pdir / "media-staging").exists()
    assert (pdir / "uploads-staging" / "kept").exists()  # production mounts ./uploads
    assert not (pdir / "media").exists()


def test_unstage_with_unreadable_meta_logs_and_pages(paths) -> None:
    """The record holds the only trace of a copy that stopped production."""
    from unittest.mock import patch
    prod_and_stage(paths)
    (slot_dir(paths, "myapp") / "meta.json").write_text("{broken")
    sent: list[tuple] = []
    with staging_docker_off(), patch("boxmunge.production_stopped.notify",
                                     lambda *a, **k: sent.append((a[2], k["priority"]))):
        assert run_unstage("myapp", paths) == 0
    assert [p for _, p in sent] == [1]
    assert "boxmunge recover myapp" in sent[0][0]
    import json
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    assert any(e["level"] == "warn" and "boxmunge recover myapp" in e["msg"]
               for e in entries)


def _left(paths) -> list[str]:
    return sorted(p.name for p in paths.project_releases("myapp").iterdir()
                  if p.name.startswith("staged"))


def test_an_unstage_killed_dropping_the_slot_finishes_on_rerun(paths, capsys) -> None:
    from tests.txn_helpers import crash_at
    prod_and_stage(paths)
    with staging_docker_off():
        assert crash_at("slot.discarding", lambda: run_unstage("myapp", paths)) == 137
        assert _left(paths) == ["staged.discarded"]
        capsys.readouterr()
        assert run_unstage("myapp", paths, dry_run=True) == 0
        assert _left(paths) == ["staged.discarded"]   # a dry run changes nothing
        assert run_unstage("myapp", paths) == 0
    assert "staging torn down" in capsys.readouterr().out
    assert _left(paths) == []
    assert paths.log_file.read_text().count("Unstaged") == 1


def test_unstage_after_a_promote_killed_dropping_the_slot(paths, capsys) -> None:
    """The removal was the promotion's: unstage finishes it as that."""
    from boxmunge.commands.promote_cmd import run_promote
    from tests.txn_helpers import crash_at
    prod_and_stage(paths)
    with staging_docker_off():
        assert crash_at("slot.discarding", lambda: run_promote("myapp", paths)) == 137
        assert _left(paths) == ["staged.promoted.discarded"]
        capsys.readouterr()
        assert run_unstage("myapp", paths) == 0
    assert "interrupted promote" in capsys.readouterr().out
    assert _left(paths) == []
    assert "Unstaged" not in paths.log_file.read_text()

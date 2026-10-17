"""stage puts the staged release in the slot and never writes production's tree."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.docker_run import DockerError
from boxmunge.project_registry import add_project
from boxmunge.release_txn import open_txn
from boxmunge.staged_release import load_slot, release_dir, slot_dir
from tests.bundle_helpers import place_bundle, tree_snapshot
from tests.stage_helpers import V1, V2, V3, prod_and_stage, staging_docker_off


def _production(paths) -> dict:
    snap = tree_snapshot(paths.project_dir("myapp"))
    return {k: v for k, v in snap.items() if not k.startswith(".releases/staged")}


def test_stage_fills_the_slot_and_leaves_production_alone(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with staging_docker_off() as docker:
        assert run_deploy("myapp", paths, ref=V1) == 0
        before = _production(paths)
        assert run_stage("myapp", paths, ref=V2) == 0
    assert _production(paths) == before
    slot = slot_dir(paths, "myapp")
    assert (release_dir(slot) / "VERSION").read_text() == "v2\n"
    meta = load_slot(paths, "myapp")
    assert meta.state == "ready" and meta.ref == f"myapp-{V2}" and meta.kind == "bundle"
    up = docker["up"].call_args
    assert up.args[0] == release_dir(slot) and up.kwargs["project_name"] == "myapp-staging"


def test_restage_replaces_the_slot_after_taking_staging_down(paths) -> None:
    prod_and_stage(paths)
    first = load_slot(paths, "myapp")
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with staging_docker_off() as docker:
        assert run_stage("myapp", paths, ref=V3) == 0
    assert docker["down_retire"].call_args.kwargs["project_name"] == "myapp-staging"
    new = load_slot(paths, "myapp")
    assert new.id != first.id and new.ref == f"myapp-{V3}"


def test_failed_bring_up_tears_the_slot_down(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    place_bundle(paths, timestamp=V2)
    with staging_docker_off() as docker:
        assert run_deploy("myapp", paths, ref=V1) == 0
        before = _production(paths)
        docker["up"].side_effect = DockerError("up failed")
        assert run_stage("myapp", paths, ref=V2) == 1
    assert load_slot(paths, "myapp") is None and _production(paths) == before


def test_failed_retire_keeps_the_old_slot_starting(paths) -> None:
    prod_and_stage(paths)
    place_bundle(paths, timestamp=V3)
    with staging_docker_off() as docker:
        docker["down_retire"].side_effect = DockerError("down failed")
        assert run_stage("myapp", paths, ref=V3) == 1
    meta = load_slot(paths, "myapp")
    assert meta.ref == f"myapp-{V2}" and meta.state == "starting"
    assert not (paths.project_releases("myapp") / "staged.building").exists()


def test_first_stage_of_a_new_project_creates_only_the_slot(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with staging_docker_off():
        assert run_stage("myapp", paths, ref=V1) == 0
    pdir = paths.project_dir("myapp")
    assert sorted(p.name for p in pdir.iterdir()) == [".releases"]
    assert sorted(p.name for p in (pdir / ".releases").iterdir()) == ["staged"]  # incoming/ is removed


def test_stage_refused_while_an_install_is_open(paths, capsys) -> None:
    prod_and_stage(paths)
    open_txn(paths, "myapp", source="bundle", ref="myapp-x", replaced_ref=f"myapp-{V1}",
             staged_id=None, snapshot="")
    place_bundle(paths, timestamp=V3)
    with staging_docker_off():
        assert run_stage("myapp", paths, ref=V3) == 1
    assert "myapp-x" in capsys.readouterr().err


def test_git_projects_refused_until_rebuilt(paths, capsys) -> None:
    prod_and_stage(paths)
    (paths.project_dir("myapp") / "repo").mkdir()
    with staging_docker_off():
        assert run_stage("myapp", paths) == 1
    assert "git" in capsys.readouterr().err


def test_debris_is_swept(paths) -> None:
    prod_and_stage(paths)
    (paths.project_releases("myapp") / "staged.building" / "release").mkdir(parents=True)
    place_bundle(paths, timestamp=V3)
    with staging_docker_off():
        assert run_stage("myapp", paths, ref=V3) == 0
    assert not (paths.project_releases("myapp") / "staged.building").exists()


def test_dry_run_builds_no_slot(paths, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    place_bundle(paths, timestamp=V2)
    with staging_docker_off() as docker:
        assert run_deploy("myapp", paths, ref=V1) == 0
        before = tree_snapshot(paths.project_dir("myapp"))
        assert run_stage("myapp", paths, ref=V2, dry_run=True) == 0
    assert "[DRY RUN] Would stage 'myapp'" in capsys.readouterr().out
    assert tree_snapshot(paths.project_dir("myapp")) == before
    assert docker["up"].call_count == 1  # production's deploy only


def test_first_stage_with_copy_data_says_there_is_nothing_to_copy(paths, capsys) -> None:
    from tests.bundle_helpers import manifest_text
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={
        "manifest.yml": manifest_text() + "staging:\n  copy_data: true\n"})
    with staging_docker_off():
        assert run_stage("myapp", paths, ref=V1) == 0
    assert ("production was never deployed, so there is no data to copy"
            in capsys.readouterr().out)


def test_failed_slot_build_changes_nothing(paths, capsys) -> None:
    prod_and_stage(paths)
    before = tree_snapshot(paths.project_dir("myapp"))
    place_bundle(paths, timestamp=V3)
    with staging_docker_off() as docker, \
            patch("boxmunge.stage_slot.write_staging_files", side_effect=OSError("disk full")):
        assert run_stage("myapp", paths, ref=V3) == 1
    assert "Nothing was changed" in capsys.readouterr().err
    docker["down_retire"].assert_not_called()
    assert tree_snapshot(paths.project_dir("myapp")) == before


def test_restage_starts_production_first_if_a_copy_stopped_it(paths, fake_containers) -> None:
    from boxmunge.staged_release import update_meta
    prod_and_stage(paths)
    fake_containers.run("myapp", "web", "sha256:1", running=False)
    update_meta(paths, "myapp", load_slot(paths, "myapp"),
                production_stopped={"at": "t", "containers": ["myapp-web-1"]})
    place_bundle(paths, timestamp=V3)
    with staging_docker_off(), \
            patch("boxmunge.production_stopped.start_containers_checked") as start, \
            patch("boxmunge.production_stopped.notify"):
        assert run_stage("myapp", paths, ref=V3) == 0
    start.assert_called_once()
    assert load_slot(paths, "myapp").production_stopped is None


def test_restage_over_an_unreadable_record_takes_the_old_staging_down(paths, capsys) -> None:
    prod_and_stage(paths)
    (slot_dir(paths, "myapp") / "meta.json").write_text("{broken")
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with staging_docker_off() as docker:
        assert run_stage("myapp", paths, ref=V3) == 0
    assert "record is unreadable" in capsys.readouterr().out
    docker["down_retire"].assert_called_once()
    assert load_slot(paths, "myapp").ref == f"myapp-{V3}"
    assert (release_dir(slot_dir(paths, "myapp")) / "VERSION").read_text() == "v3\n"


def test_staging_record_hashes_the_slot(paths) -> None:
    """A production deploy during the stage leaves staging's record valid."""
    import json
    prod_and_stage(paths)
    record = json.loads(paths.project_bind_record("myapp", staging=True).read_text())
    assert ".releases/staged/release/manifest.yml" in record["control"]
    assert "manifest.yml" not in record["control"]


def test_copy_plan_knows_the_staged_releases_own_data_dirs(paths) -> None:
    """A data dir only the staged release mounts is a store of staging's:
    its box state comes from the slot's release, not from production's."""
    from tests.bundle_helpers import SAFE_COMPOSE, manifest_text
    staged_manifest = (manifest_text() + "staging:\n  copy_data:\n"
                       "    sources: {./media: ./uploads}\n")
    prod_and_stage(paths, prod_files={
        "compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"})
    place_bundle(paths, timestamp=V3, files={
        "manifest.yml": staged_manifest,
        "compose.yml": SAFE_COMPOSE + "    volumes: ['./media:/u']\n"})
    with staging_docker_off(), \
            patch("boxmunge.staging_bringup.prepare_destinations"), \
            patch("boxmunge.staging_bringup.copy_production_data") as copy:
        assert run_stage("myapp", paths, ref=V3) == 0
    plan = copy.call_args.args[2]
    assert [(s.key, d.key) for s, d in plan.pairs] == [("./uploads", "./media")]
    assert plan.pairs[0][1].ref == str(paths.project_dir("myapp") / "media-staging")


def test_restage_over_a_slot_whose_switch_failed(paths) -> None:
    """Retiring an old slot back to `starting` drops its switch_rc: a slot
    left `starting` with one would be refused by load_slot (Task 20 review)."""
    from boxmunge.staged_release import update_meta
    prod_and_stage(paths)
    update_meta(paths, "myapp", load_slot(paths, "myapp"), state="retired", switch_rc=1)
    place_bundle(paths, timestamp=V3)
    with staging_docker_off() as docker:
        docker["down_retire"].side_effect = DockerError("down failed")
        assert run_stage("myapp", paths, ref=V3) == 1
    meta = load_slot(paths, "myapp")
    assert meta.state == "starting" and meta.switch_rc is None


# -- final review fixes ------------------------------------------------------

def test_restage_over_an_unreadable_record_logs_and_pages(paths) -> None:
    """The record holds the only trace of a copy that stopped production."""
    prod_and_stage(paths)
    (slot_dir(paths, "myapp") / "meta.json").write_text("{broken")
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    sent: list[tuple] = []
    with staging_docker_off(), patch("boxmunge.production_stopped.notify",
                                     lambda *a, **k: sent.append((a[2], k["priority"]))):
        assert run_stage("myapp", paths, ref=V3) == 0
    assert [p for _, p in sent] == [1]
    assert "boxmunge recover myapp" in sent[0][0]
    import json
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    assert any(e["level"] == "warn" and "boxmunge recover myapp" in e["msg"]
               for e in entries)


def test_dry_run_leaves_leftovers_and_production_alone(paths, capsys) -> None:
    """A dry run changes nothing: no sweep, no start of production."""
    prod_and_stage(paths)
    releases = paths.project_releases("myapp")
    (releases / ".isolation-killed").mkdir()
    (releases / "staged.building").mkdir()
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with staging_docker_off(), \
            patch("boxmunge.commands.stage_cmd.start_again") as start:
        assert run_stage("myapp", paths, ref=V3, dry_run=True) == 0
    start.assert_not_called()
    assert (releases / ".isolation-killed").is_dir() and (releases / "staged.building").is_dir()
    assert "[DRY RUN] Would stage 'myapp'" in capsys.readouterr().out


def test_the_announcement_does_not_read_the_slot_again(paths, capsys) -> None:
    """A stage that recorded itself ready is announced from what it wrote."""
    from boxmunge.staged_release import SlotError

    def load(paths_, project):
        meta = load_slot(paths_, project)
        if meta is not None and meta.state == "ready":
            raise SlotError("unreadable after ready")
        return meta
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with staging_docker_off(), patch("boxmunge.commands.stage_cmd.load_slot", load):
        assert run_stage("myapp", paths, ref=V2) == 0
    assert "Run 'promote myapp' to go live" in capsys.readouterr().out


def test_a_failed_build_whose_cleanup_fails_reports_both(paths, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with staging_docker_off(), \
            patch("boxmunge.commands.stage_cmd.build_slot", side_effect=OSError("build boom")), \
            patch("boxmunge.commands.stage_cmd.discard_dir", side_effect=OSError("rm boom")):
        assert run_stage("myapp", paths, ref=V2) == 1
    err = capsys.readouterr().err
    assert "Building the staged release failed: build boom" in err
    assert "failed too: rm boom" in err and "Nothing was changed" not in err

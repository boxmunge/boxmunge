"""A copy only the staged release mounts is box state while it is staged."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.compose_guard import compose_up_checked
from boxmunge.data_dirs import classify
from boxmunge.release import project_data_dirs
from boxmunge.staging_cleanup import retired_staging_copies
from tests.bundle_helpers import SAFE_COMPOSE, place_bundle
from tests.stage_helpers import V3, prod_and_stage, staging_docker_off

UPLOADS = SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"


def test_staged_mount_makes_its_copy_box_state(paths) -> None:
    pdir = prod_and_stage(paths, staged_files={"compose.yml": UPLOADS})
    (pdir / "uploads-staging").mkdir(exist_ok=True)  # stage made its placeholder
    (pdir / "uploads-staging" / "f").write_text("staging data")
    assert "uploads-staging" in project_data_dirs(pdir).box_state()
    place_bundle(paths, timestamp=V3)
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 0
    assert (pdir / "uploads-staging" / "f").read_text() == "staging data"


def test_classify_reads_the_staged_compose_only_when_given(tmp_path) -> None:
    pdir = tmp_path / "myapp"
    pdir.mkdir()
    (pdir / "compose.yml").write_text(SAFE_COMPOSE)
    staged = tmp_path / "staged-compose.yml"
    staged.write_text(SAFE_COMPOSE + "    volumes: ['./uploads:/u', './conf:/c:ro']\n")
    assert classify(pdir, None, []).staged == frozenset()
    dirs = classify(pdir, None, [], staged)
    assert dirs.staged == {"uploads", "conf"}
    assert {"uploads-staging", "conf-staging"} <= dirs.box_state()
    # Staged mounts are staging's: production records nothing for them.
    assert "uploads" not in dirs.recorded and "uploads" not in dirs.box_state()


def test_unstage_retires_the_copy_only_the_staged_release_mounted(paths) -> None:
    pdir = prod_and_stage(paths, staged_files={"compose.yml": UPLOADS})
    (pdir / "uploads-staging").mkdir(exist_ok=True)  # stage made its placeholder
    assert retired_staging_copies(pdir) == [pdir / "uploads-staging"]


def test_live_scripts_from_0_10_1_are_swept_after_a_production_up(paths) -> None:
    pdir = prod_and_stage(paths)
    live = pdir / ".releases" / "live-scripts"
    live.mkdir()
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, "myapp", component="upgrade",
                           compose_files=["compose.yml", "compose.boxmunge.yml"])
    assert not live.exists()


def test_live_scripts_kept_while_a_container_mounts_them(paths, monkeypatch) -> None:
    pdir = prod_and_stage(paths)
    live = pdir / ".releases" / "live-scripts"
    live.mkdir()
    monkeypatch.setattr("boxmunge.docker_containers.container_bind_sources",
                        lambda project_name: [(str(live), False)])
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, "myapp", component="upgrade",
                           compose_files=["compose.yml", "compose.boxmunge.yml"])
    assert live.exists()


def test_live_scripts_kept_while_the_overlay_names_them(paths) -> None:
    pdir = prod_and_stage(paths)
    live = pdir / ".releases" / "live-scripts"
    live.mkdir()
    overlay = paths.project_compose_override("myapp")
    overlay.write_text(overlay.read_text() + "# ./.releases/live-scripts\n")
    with patch("boxmunge.compose_guard.compose_up"), \
            patch("boxmunge.compose_guard.check_start"):
        compose_up_checked(paths, "myapp", component="upgrade",
                           compose_files=["compose.yml", "compose.boxmunge.yml"])
    assert live.exists()


def test_live_scripts_kept_after_a_partial_or_staging_up(paths) -> None:
    pdir = prod_and_stage(paths)
    live = pdir / ".releases" / "live-scripts"
    live.mkdir()
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, "myapp", component="restore", services=["web"],
                           compose_files=["compose.yml", "compose.boxmunge.yml"])
        compose_up_checked(paths, "myapp", component="stage", staging=True)
    assert live.exists()


def test_a_read_only_staged_mount_leaves_its_old_copy_reported_only(paths) -> None:
    """In the slot layout staging reads ./conf from the staged release; a
    conf-staging in the project dir is 0.10.1's code copy or the
    operator's, which unstage reports and never removes."""
    from boxmunge.staged_release import release_dir, slot_dir
    from boxmunge.staging_cleanup import old_layout_copies
    pdir = prod_and_stage(paths)
    # Written into the slot directly: the unit tier's literal `compose
    # config` leaves ./conf relative, which the stage's isolation proof
    # would resolve against the project dir (real Compose makes it absolute).
    (release_dir(slot_dir(paths, "myapp")) / "compose.yml").write_text(
        SAFE_COMPOSE + "    volumes: ['./conf:/c:ro']\n")
    (pdir / "conf-staging").mkdir()
    (pdir / "conf-staging" / "x").write_text("operator's\n")
    assert project_data_dirs(pdir).staged == {"conf"}
    assert project_data_dirs(pdir).staged_rw == frozenset()
    assert retired_staging_copies(pdir) == []
    assert pdir / "conf-staging" in old_layout_copies(pdir)


def test_the_staged_view_does_not_read_the_current_slot(paths, tmp_path) -> None:
    """A re-stage classifies the incoming release; an old slot whose
    compose.yml cannot be read must not fail it."""
    from boxmunge.release import staged_box_state
    from boxmunge.staged_release import release_dir, slot_dir
    pdir = prod_and_stage(paths)
    (release_dir(slot_dir(paths, "myapp")) / "compose.yml").write_text("services: [\n")
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    (incoming / "compose.yml").write_text(UPLOADS)
    assert "uploads-staging" in staged_box_state(pdir, incoming)


def test_a_linked_live_scripts_is_warned_about_and_left(paths, tmp_path, capsys) -> None:
    pdir = prod_and_stage(paths)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep").write_text("not boxmunge's\n")
    live = pdir / ".releases" / "live-scripts"
    live.symlink_to(target)
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, "myapp", component="upgrade",
                           compose_files=["compose.yml", "compose.boxmunge.yml"])
    assert live.is_symlink() and (target / "keep").read_text() == "not boxmunge's\n"
    assert "was not removed" in capsys.readouterr().err


def test_live_scripts_swept_when_the_overlay_only_mentions_the_word(paths) -> None:
    pdir = prod_and_stage(paths)
    live = pdir / ".releases" / "live-scripts"
    live.mkdir()
    overlay = paths.project_compose_override("myapp")
    overlay.write_text(overlay.read_text() + "# no live-scripts here any more\n")
    with patch("boxmunge.compose_guard.compose_up"), \
            patch("boxmunge.compose_guard.check_start"):
        compose_up_checked(paths, "myapp", component="upgrade",
                           compose_files=["compose.yml", "compose.boxmunge.yml"])
    assert not live.exists()

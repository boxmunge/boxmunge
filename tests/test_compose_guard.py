"""The start checks: re-validation and no-follow bind source checks.

Real filesystem throughout; only `docker compose up/start` and Pushover
are stood in for.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.compose_guard import (
    ComposeRefused, check_containers_start, compose_up_checked,
    start_containers_checked,
    compose_up_platform,
)
from boxmunge.docker_run import DockerError
from boxmunge.paths import BoxPaths

NAME = "shop"


@pytest.fixture
def box(tmp_path: Path):
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.config, paths.deploy_state, paths.logs):
        d.mkdir(parents=True)
    paths.config_file.write_text(yaml.safe_dump({
        "hostname": "box.example.com", "admin_email": "ops@example.com",
        "pushover": {"user_key": "u", "app_token": "t"},
    }))
    project_dir = paths.project_dir(NAME)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "project": NAME,
        "source": "bundle", "hosts": [f"{NAME}.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    _compose(project_dir, ["./data/uploads:/uploads", "./conf/app.toml:/etc/app.toml:ro"])
    (project_dir / "conf").mkdir()
    (project_dir / "conf" / "app.toml").write_text("")
    sent: list[str] = []
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.notify.send_notification",
                  lambda u, t, title, body, priority=0: sent.append(body) or True):
        yield paths, project_dir, up, start, sent


def _compose(project_dir: Path, volumes: list) -> None:
    (project_dir / "compose.yml").write_text(yaml.safe_dump(
        {"services": {"web": {"image": "nginx:1.27", "volumes": volumes}}}))


def _deploy(paths: BoxPaths) -> None:
    compose_up_checked(paths, NAME, component="deploy", compose_files=["compose.yml"],
                       record=True)


def _restart(paths: BoxPaths) -> None:
    compose_up_checked(paths, NAME, component="upgrade", compose_files=["compose.yml"])


def test_deploy_records_kinds_and_creates_missing_sources(box) -> None:
    paths, project_dir, up, _, sent = box
    _deploy(paths)
    assert (project_dir / "data" / "uploads").is_dir()
    record = json.loads(paths.project_bind_record(NAME).read_text())
    assert record["sources"] == {"data/uploads": "dir", "conf/app.toml": "file"}
    up.assert_called_once()
    assert sent == []


def test_a_later_start_of_an_unchanged_project_goes_ahead(box) -> None:
    paths, _, up, _, sent = box
    _deploy(paths)
    _restart(paths)
    assert up.call_count == 2
    assert sent == []


def _refused(box, match: str) -> None:
    paths, _, up, start, sent = box
    up.reset_mock()
    with pytest.raises(ComposeRefused, match=match):
        _restart(paths)
    up.assert_not_called()
    start.assert_not_called()
    assert len(sent) == 1 and NAME in sent[0]
    log = paths.log_file.read_text()
    assert "Refused to start shop" in log


# A link out of the project is already refused by the path rules (they
# resolve symlinks). These links stay inside it, which only the no-follow
# walk sees; it is also what stands between the check and a link swapped in
# after validation ran.

def test_bind_source_replaced_by_a_symlink_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "media").mkdir()
    (project_dir / "data" / "uploads").rmdir()
    os.symlink("../media", project_dir / "data" / "uploads")
    _refused(box, "data/uploads is a symlink")


def test_parent_of_a_bind_source_replaced_by_a_symlink_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "elsewhere" / "uploads").mkdir(parents=True)
    (project_dir / "data" / "uploads").rmdir()
    (project_dir / "data").rmdir()
    os.symlink("elsewhere", project_dir / "data")
    _refused(box, "data is a symlink")


def test_file_source_replaced_by_a_symlink_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "other.toml").write_text("")
    (project_dir / "conf" / "app.toml").unlink()
    os.symlink("../other.toml", project_dir / "conf" / "app.toml")
    _refused(box, "conf/app.toml is a symlink")


@pytest.mark.parametrize("rel", ["data/uploads", "data/uploads/deeper"])
def test_walk_refuses_a_link_out_of_the_project(tmp_path, rel) -> None:
    from boxmunge.bind_sources import BindSourceError, source_kind
    project_dir = tmp_path / "project"
    (project_dir / "data").mkdir(parents=True)
    os.symlink("/", project_dir / "data" / "uploads")
    with pytest.raises(BindSourceError, match="data/uploads is a symlink"):
        source_kind(project_dir, rel, create=True)
    assert not Path("/deeper").exists()


def test_missing_source_is_refused_after_deploy(box) -> None:
    """Docker would create it as root, through any symlink leading there."""
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "data" / "uploads").rmdir()
    _refused(box, "does not exist")
    assert not (project_dir / "data" / "uploads").exists()


def test_source_of_another_kind_than_deployed_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "data" / "uploads").rmdir()
    (project_dir / "data" / "uploads").write_text("")
    _refused(box, "was a dir when the project was deployed and is now a file")


def test_socket_or_fifo_bind_source_is_allowed_but_recorded(box) -> None:
    """A socket or FIFO an app keeps in its data dir is the container's own
    file, not one boxmunge reads, so it is allowed — but recorded, so a
    later change of kind is still caught."""
    paths, project_dir, up, _, sent = box
    (project_dir / "data").mkdir()
    os.mkfifo(project_dir / "data" / "uploads")
    _deploy(paths)  # records kind "special"
    up.assert_called_once()
    assert sent == []


def test_a_bind_source_whose_kind_changed_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "data" / "uploads").rmdir()
    os.mkfifo(project_dir / "data" / "uploads")
    _refused(box, "was a dir when the project was deployed and is now a special")


def test_mount_not_recorded_at_deploy_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "media").mkdir()
    _compose(project_dir, ["./data/uploads:/uploads", "./conf/app.toml:/etc/app.toml:ro",
                           "./media:/media"])
    _refused(box, "media was not mounted when the project was last deployed")


def test_project_never_recorded_is_refused(box) -> None:
    _refused(box, "no record of the bind sources")


def test_unreadable_record_is_refused(box) -> None:
    paths, *_ = box
    _deploy(paths)
    paths.project_bind_record(NAME).write_text('{"version": 1, "sources": {"x": "link"}}')
    _refused(box, "is not a bind source record")


def test_compose_file_rewritten_after_deploy_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx:1.27", "privileged": True}}}))
    _refused(box, "privileged")


def test_a_valid_manifest_change_is_still_refused_by_the_control_hash(box) -> None:
    """A container that rewrites manifest.yml to `security.profile: off` (a
    change validation accepts) is still refused: the manifest hashed at
    deploy no longer matches. Only a redeploy re-blesses it."""
    paths, project_dir, *_ = box
    _deploy(paths)
    import yaml as _yaml
    manifest = _yaml.safe_load((project_dir / "manifest.yml").read_text())
    manifest["security"] = {"profile": "off", "reason": "attacker-supplied"}
    (project_dir / "manifest.yml").write_text(_yaml.safe_dump(manifest))
    _refused(box, "control file manifest.yml changed")


def test_manifest_rewritten_after_deploy_is_refused(box) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump({"project": "other"}))
    _refused(box, "Manifest validation failed")


def test_deploy_refuses_a_symlinked_source_and_records_nothing(box, tmp_path) -> None:
    paths, project_dir, up, _, sent = box
    (project_dir / "data").mkdir()
    os.symlink(tmp_path, project_dir / "data" / "uploads")
    with pytest.raises(ComposeRefused, match="symlink"):
        _deploy(paths)
    up.assert_not_called()
    assert not paths.project_bind_record(NAME).exists()
    assert len(sent) == 1


def test_the_same_refusal_alerts_once_per_project(box) -> None:
    """A persistently tampered project is checked on every timer tick; the
    operator is paged once, not on each one. The refusal is logged every
    time."""
    paths, project_dir, _, _, sent = box
    _deploy(paths)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump({"project": "other"}))
    for _ in range(3):
        with pytest.raises(ComposeRefused):
            _restart(paths)
    assert len(sent) == 1
    assert paths.log_file.read_text().count("Refused to start shop") == 3


def test_a_refusal_is_a_docker_error(box) -> None:
    """Every caller already handles DockerError as a failed start."""
    assert issubclass(ComposeRefused, DockerError)


def test_start_also_checks_the_containers_own_mounts(box, tmp_path) -> None:
    """`docker start` mounts what the containers were created with, which
    may differ from the compose files on disk (during a stage, say)."""
    paths, project_dir, _, start, _ = box
    _deploy(paths)
    os.symlink(tmp_path, project_dir / "old-uploads")
    with patch("boxmunge.docker_containers.container_bind_sources",
               return_value=[(str(project_dir / "old-uploads"), True)]):
        with pytest.raises(ComposeRefused, match="old-uploads is a symlink"):
            start_containers_checked(paths, NAME, [f"{NAME}-web-1"], component="stage")
    start.assert_not_called()


def test_start_of_untampered_containers_goes_ahead(box) -> None:
    paths, project_dir, _, start, _ = box
    _deploy(paths)
    with patch("boxmunge.docker_containers.container_bind_sources",
               return_value=[(str(project_dir / "data" / "uploads"), True)]):
        start_containers_checked(paths, NAME, [f"{NAME}-web-1"], component="stage")
    start.assert_called_once_with([f"{NAME}-web-1"])


def test_container_mount_outside_the_project_is_refused(box) -> None:
    paths, *_ = box
    _deploy(paths)
    with patch("boxmunge.docker_containers.container_bind_sources", return_value=[("/", True)]):
        with pytest.raises(ComposeRefused, match="outside the project"):
            check_containers_start(paths, NAME, component="stage")


def test_staging_keeps_its_own_record(box) -> None:
    paths, *_ = box
    compose_up_checked(paths, NAME, component="stage", compose_files=["compose.yml"],
                       staging=True, record=True)
    assert paths.project_bind_record(NAME, staging=True).exists()
    assert not paths.project_bind_record(NAME).exists()


def test_platform_start_is_only_for_platform_stacks(box) -> None:
    paths, project_dir, up, *_ = box
    with pytest.raises(ValueError, match="not a platform stack"):
        compose_up_platform(project_dir, ["compose.yml"], NAME, build=False)
    compose_up_platform(paths.caddy, ["compose.yml"], "caddy", build=False)
    assert up.call_args.kwargs["project_name"] == "caddy"


def test_starting_containers_during_a_stage_ignores_the_staged_files(box) -> None:
    """While staged, the project dir holds the staged release: compose.yml
    no longer hashes to production's record. A `docker start` reads no
    compose file, so it is checked on the containers' mounts alone."""
    paths, project_dir, _, start, _ = box
    _deploy(paths)
    (project_dir / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx:1.28", "volumes": ["./data/uploads:/uploads"]}}}))
    (paths.project_releases(NAME) / "prestage" / "release").mkdir(parents=True)
    with patch("boxmunge.docker_containers.container_bind_sources",
               return_value=[(str(project_dir / "data" / "uploads"), True)]):
        start_containers_checked(paths, NAME, [f"{NAME}-web-1"], component="stage")
    start.assert_called_once()


def test_regenerating_the_overlay_refreshes_its_recorded_hash(box) -> None:
    """resume, recover and security resume regenerate the overlay outside a
    deploy; the record follows boxmunge's own output, so the next start is
    not refused for it."""
    from boxmunge import bind_sources
    paths, project_dir, *_ = box
    (project_dir / "compose.boxmunge.yml").write_text("services: {}\n")
    _deploy(paths)
    (project_dir / "compose.boxmunge.yml").write_text("services: {web: {init: true}}\n")
    bind_sources.refresh_overlay_hash(project_dir, paths.project_bind_record(NAME))
    _restart(paths)


def test_secrets_set_between_deploys_does_not_refuse_a_start(box) -> None:
    paths, project_dir, up, _, sent = box
    (project_dir / "secrets.env").write_text("A=1\n")
    _deploy(paths)
    (project_dir / "secrets.env").write_text("A=2\n")
    _restart(paths)
    assert up.call_count == 2 and sent == []
# ---------------------------------------------------------------------------
# Git projects: compose.yml and manifest.yml are symlinks into repo/
# ---------------------------------------------------------------------------


@pytest.fixture
def git_box(box):
    """The box's project turned into a git project: its compose.yml and
    manifest.yml live in repo/ and are linked from the project root, as
    add-git-project leaves them."""
    paths, project_dir, up, start, sent = box
    repo = project_dir / "repo"
    repo.mkdir()
    for name in ("compose.yml", "manifest.yml"):
        (project_dir / name).rename(repo / name)
        os.symlink(repo / name, project_dir / name)
    return box


def test_git_project_records_and_restarts_through_its_links(git_box) -> None:
    paths, project_dir, up, _, sent = git_box
    _deploy(paths)
    record = json.loads(paths.project_bind_record(NAME).read_text())
    assert record["control"]["compose.yml"] and record["control"]["manifest.yml"]
    _restart(paths)
    assert up.call_count == 2
    assert sent == []


def test_git_project_link_target_rewritten_is_refused(git_box) -> None:
    paths, project_dir, *_ = git_box
    _deploy(paths)
    manifest = yaml.safe_load((project_dir / "repo" / "manifest.yml").read_text())
    manifest["security"] = {"profile": "off", "reason": "attacker-supplied"}
    (project_dir / "repo" / "manifest.yml").write_text(yaml.safe_dump(manifest))
    _refused(git_box, "control file manifest.yml changed")


def test_git_project_link_repointed_inside_the_project_is_refused(git_box) -> None:
    paths, project_dir, *_ = git_box
    _deploy(paths)
    copy = project_dir / "repo" / "other.yml"
    copy.write_text((project_dir / "repo" / "compose.yml").read_text())
    (project_dir / "compose.yml").unlink()
    os.symlink(copy, project_dir / "compose.yml")
    _refused(git_box, "control file compose.yml changed")


def test_control_file_linking_out_of_the_project_is_refused(box, tmp_path) -> None:
    paths, project_dir, *_ = box
    _deploy(paths)
    outside = tmp_path / "elsewhere.env"
    outside.write_text("A=1\n")
    os.symlink(outside, project_dir / ".env")
    _refused(box, "resolves to .* outside the project directory")


def test_refusal_state_is_outside_every_project(box) -> None:
    """The alert-dedupe state lives under state/, which no bind mount may
    reach: validation refuses any source in the boxmunge root outside
    projects/."""
    from boxmunge.compose_mounts import denied_host_path
    paths, project_dir, *_ = box
    _deploy(paths)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump({"project": "other"}))
    with pytest.raises(ComposeRefused):
        _restart(paths)
    state = paths.state / "start-refused" / f"{NAME}.json"
    assert state.exists()
    assert not str(state).startswith(str(paths.projects) + os.sep)
    assert denied_host_path(str(paths.state), project_dir, paths) == str(paths.root)
    assert denied_host_path("../../state/start-refused", project_dir, paths) == str(paths.root)

"""Per-project image pins (image_pins): the record, the overlay that runs
them, the start check of the pinned images, the release switch that drops
them, the user-namespace remap, and the `security.autofix` key.

Real filesystem; `docker compose up`, the image store and Pushover are
stood in for, and the unit tier's literal `docker compose config`
(conftest) resolves compose.yml alone, so the merged model and a real
daemon are the integration tier's (tests/integration/test_image_pin_resolve.py,
image_identity_cases.case_a_start_runs_the_pinned_image on both stores).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge import bind_sources
from boxmunge.compose import (
    ComposeError, generate_compose_override, generate_staging_compose_override,
    prepare_compose_override,
)
from boxmunge.compose_guard import ComposeRefused, check_start, compose_up_checked
from boxmunge.docker_containers import LocalImage
from boxmunge.docker_run import DockerError
from boxmunge.image_pins import (
    ImagePin, clear_pins, forget_pins, pin_ref, read_pins, remap_image_pins,
    write_pins,
)
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

NAME = "shop"
PROD = ["compose.yml", "compose.boxmunge.yml"]
IMAGE_ID = "sha256:" + "a" * 64
PIN = ImagePin("web", pin_ref(NAME, "web", IMAGE_ID), IMAGE_ID, "autofix")
MANIFEST = {
    "schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "project": NAME,
    "source": "bundle", "hosts": [f"{NAME}.example.com"],
    "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
}
COMPOSE = {"services": {"web": {"image": "nginx:1.27"}, "db": {"image": "postgres:16"}}}


@pytest.fixture
def box(tmp_path: Path):
    """A deployed project: overlay generated, bind sources and control
    hashes recorded by a deploy's start."""
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.config, paths.deploy_state, paths.logs):
        d.mkdir(parents=True)
    paths.config_file.write_text(yaml.safe_dump({
        "hostname": "box.example.com", "admin_email": "ops@example.com",
        "pushover": {"user_key": "u", "app_token": "t"},
    }))
    project_dir = paths.project_dir(NAME)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump(MANIFEST))
    (project_dir / "compose.yml").write_text(yaml.safe_dump(COMPOSE))
    sent: list[str] = []
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.notify.send_notification",
                  lambda u, t, title, body, priority=0: sent.append(body) or True):
        prepare_compose_override(paths, MANIFEST)
        compose_up_checked(paths, NAME, component="deploy", compose_files=PROD,
                           record=True, deploying=True)
        yield paths, project_dir, up, sent


def _overlay(paths: BoxPaths) -> dict:
    return yaml.safe_load(paths.project_compose_override(NAME).read_text())


def _record(paths: BoxPaths, record: object) -> None:
    path = paths.project_image_pins(NAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record if isinstance(record, str) else json.dumps(record))


def _pin_doc(**changes: object) -> dict:
    pin = {"service": "web", "ref": PIN.ref, "image_id": IMAGE_ID, "reason": "autofix",
           **changes}
    return {"version": 1, "pins": [pin]}


# --- the pin --------------------------------------------------------------


def test_the_pin_names_the_image_under_the_projects_own_prefix() -> None:
    assert PIN.ref == f"boxmunge.invalid/{NAME}/web:autofix-aaaaaaaaaaaa"
    assert PIN.project == NAME


@pytest.mark.parametrize("field, value", [
    ("service", ""), ("service", "api"), ("ref", ""),
    ("ref", f"{PIN.ref}@{IMAGE_ID}"),
    ("ref", f"boxmunge.local/{NAME}/web:autofix-aaaaaaaaaaaa"),
    ("ref", f"boxmunge.invalid/{NAME}/web"),
    ("ref", f"boxmunge.invalid/{NAME}/web:latest"),
    ("ref", f"boxmunge.invalid/{NAME}/web:autofix-aaaa"),
    ("ref", f"boxmunge.invalid/{NAME}/web:autofix-AAAAAAAAAAAA"),
    ("ref", f"boxmunge.invalid/{NAME}/Web:autofix-aaaaaaaaaaaa"),
    ("ref", "nginx:1.27"),
    ("image_id", "sha256:abc"), ("image_id", "a" * 64), ("image_id", 1),
    ("reason", "manual"),
])
def test_a_malformed_pin_is_refused(field, value) -> None:
    with pytest.raises(ValueError):
        ImagePin(**{**PIN.__dict__, field: value})


# --- the overlay ----------------------------------------------------------


def test_overlay_emits_pinned_image_for_service() -> None:
    compose = {"services": {"web": {"image": "nginx:1.27"}, "app": {"build": "."},
                            "db": {"image": "postgres:16"}}}
    app_id = "sha256:" + "b" * 64
    app = ImagePin("app", pin_ref(NAME, "app", app_id), app_id, "autofix")
    services = yaml.safe_load(generate_compose_override(
        MANIFEST, user_compose=compose, pins=(PIN, app)))["services"]
    assert services["web"]["image"] == PIN.ref
    # A build service's pin replaces the platform name its build carries.
    assert services["app"]["image"] == app.ref
    assert "image" not in services["db"]
    # Staging runs the staged release's own images: pins are production's.
    staging = yaml.safe_load(generate_staging_compose_override(MANIFEST, user_compose=compose))
    assert staging["services"]["web"].get("image") is None


def test_the_overlay_on_disk_carries_the_recorded_pins(box) -> None:
    paths, *_ = box
    _record(paths, _pin_doc())
    prepare_compose_override(paths, MANIFEST)
    assert _overlay(paths)["services"]["web"]["image"] == PIN.ref


def test_a_release_being_installed_is_rendered_without_the_pins(box) -> None:
    """The pins are the running release's; the release a deploy, promote or
    rollback installs ships its own images."""
    paths, *_ = box
    _record(paths, _pin_doc())
    prepare_compose_override(paths, MANIFEST, installing=True)
    assert "image" not in _overlay(paths)["services"]["web"]


def test_a_pin_for_a_service_the_release_lacks_is_refused(box) -> None:
    paths, *_ = box
    gone_id = "sha256:" + "c" * 64
    _record(paths, _pin_doc(service="gone", ref=pin_ref(NAME, "gone", gone_id),
                            image_id=gone_id))
    with pytest.raises(ComposeError, match="gone.*compose.yml has no such service"):
        prepare_compose_override(paths, MANIFEST)


def test_an_unreadable_record_fails_the_render(box) -> None:
    paths, *_ = box
    _record(paths, "{not json")
    with pytest.raises(ComposeError, match="image_pins"):
        prepare_compose_override(paths, MANIFEST)


# --- writing --------------------------------------------------------------


def _overlay_hash(paths: BoxPaths) -> str:
    return hashlib.sha256(paths.project_compose_override(NAME).read_bytes()).hexdigest()


def test_pin_write_refreshes_control_hash(box) -> None:
    paths, project_dir, up, sent = box
    before = _overlay_hash(paths)
    write_pins(paths, NAME, (PIN,))
    assert read_pins(paths, NAME) == (PIN,)
    assert _overlay(paths)["services"]["web"]["image"] == PIN.ref
    assert _overlay_hash(paths) != before
    recorded = json.loads(paths.project_bind_record(NAME).read_text())["control"]
    assert recorded[bind_sources.OVERLAY] == _overlay_hash(paths)
    # So a start that renders nothing (a restart, container update, restore)
    # is not refused for the overlay boxmunge rewrote.
    check_start(paths, NAME, component="restart", compose_files=PROD)
    assert sent == []


def test_clearing_the_pins_renders_the_overlay_without_them(box) -> None:
    paths, *_ = box
    write_pins(paths, NAME, (PIN,))
    clear_pins(paths, NAME)
    assert not os.path.lexists(paths.project_image_pins(NAME))
    assert read_pins(paths, NAME) == ()
    assert "image" not in _overlay(paths)["services"]["web"]
    check_start(paths, NAME, component="restart", compose_files=PROD)


def test_clearing_no_pins_touches_nothing(box) -> None:
    paths, *_ = box
    before = paths.project_compose_override(NAME).stat().st_mtime_ns
    with patch("boxmunge.compose.prepare_compose_override") as render:
        clear_pins(paths, NAME)
    render.assert_not_called()
    assert paths.project_compose_override(NAME).stat().st_mtime_ns == before


def test_writing_no_pins_is_refused(box) -> None:
    paths, *_ = box
    with pytest.raises(ValueError, match="clear_pins"):
        write_pins(paths, NAME, ())


def test_no_pin_is_written_while_an_install_is_open(box) -> None:
    """The project dir holds the release the install puts in, which the
    pins are not for; its switch drops them anyway."""
    from boxmunge.release_txn import open_txn
    paths, *_ = box
    open_txn(paths, NAME, source="bundle", ref="shop-v2", replaced_ref="shop-v1",
             staged_id=None, snapshot="")
    with pytest.raises(ValueError, match="while an install is open"):
        write_pins(paths, NAME, (PIN,))
    assert not os.path.lexists(paths.project_image_pins(NAME))


def test_two_pins_for_one_service_are_refused(box) -> None:
    paths, *_ = box
    other_id = "sha256:" + "c" * 64
    other = ImagePin("web", pin_ref(NAME, "web", other_id), other_id, "autofix")
    with pytest.raises(ValueError, match="web"):
        write_pins(paths, NAME, (PIN, other))
    assert read_pins(paths, NAME) == ()


def test_a_pin_of_another_project_is_refused(box) -> None:
    paths, *_ = box
    with pytest.raises(ValueError, match="not an image of"):
        write_pins(paths, NAME, (ImagePin("web", pin_ref("blog", "web", IMAGE_ID), IMAGE_ID,
                                          "autofix"),))


# --- the start ------------------------------------------------------------


def _restart(paths: BoxPaths, **kwargs) -> None:
    compose_up_checked(paths, NAME, component="restart", compose_files=PROD, **kwargs)


def _store(monkeypatch, image_id: str | None) -> None:
    monkeypatch.setattr("boxmunge.docker_containers.local_image",
                        lambda ref: None if image_id is None or ref != PIN.ref
                        else LocalImage(image_id=image_id, repo_digests=()))


def test_a_start_runs_the_pinned_image_it_records(box, monkeypatch) -> None:
    paths, _, up, sent = box
    write_pins(paths, NAME, (PIN,))
    _store(monkeypatch, IMAGE_ID)
    up.reset_mock()
    _restart(paths)
    up.assert_called_once()
    assert sent == []


@pytest.mark.parametrize("found, says", [
    ("sha256:" + "f" * 64, r"the tag names sha256:ffffffffffff, the pin sha256:aaaaaaaaaaaa"),
    (None, "the tag names no image"),
])
def test_a_retagged_or_missing_pinned_image_is_refused(box, monkeypatch, found, says) -> None:
    paths, _, up, sent = box
    write_pins(paths, NAME, (PIN,))
    _store(monkeypatch, found)
    up.reset_mock()
    with pytest.raises(ComposeRefused, match=r"the pinned image for web \(boxmunge.invalid/"
                       r"shop/web:autofix-aaaaaaaaaaaa\) is not the one autofix built: " + says):
        _restart(paths)
    up.assert_not_called()
    assert "is not the one autofix built" in sent[0]


def test_a_start_of_other_services_does_not_check_the_pin(box, monkeypatch) -> None:
    paths, _, up, _ = box
    write_pins(paths, NAME, (PIN,))
    _store(monkeypatch, "sha256:" + "f" * 64)
    _restart(paths, services=["db"])


def test_pins_without_the_overlay_are_refused_saying_it_is_missing(box) -> None:
    paths, _, up, _ = box
    write_pins(paths, NAME, (PIN,))
    paths.project_compose_override(NAME).unlink()
    bind_sources.refresh_control_hash(paths.project_dir(NAME),
                                      paths.project_bind_record(NAME), bind_sources.OVERLAY)
    up.reset_mock()
    with pytest.raises(ComposeRefused, match="the overlay compose.boxmunge.yml that runs them "
                                             "is missing"):
        compose_up_checked(paths, NAME, component="restart", compose_files=["compose.yml"])
    up.assert_not_called()


def test_an_overlay_rendered_without_the_pin_is_refused(box, monkeypatch) -> None:
    paths, _, up, _ = box
    write_pins(paths, NAME, (PIN,))
    prepare_compose_override(paths, MANIFEST, installing=True)
    _store(monkeypatch, IMAGE_ID)
    with pytest.raises(ComposeRefused, match="generated without the pin"):
        _restart(paths)


def test_a_switching_start_runs_its_release_whatever_the_pins(box, monkeypatch) -> None:
    """A deploy's start runs the release it rendered without the pins,
    before its switch drops them."""
    paths, _, up, _ = box
    write_pins(paths, NAME, (PIN,))
    prepare_compose_override(paths, MANIFEST, installing=True)
    _store(monkeypatch, None)
    up.reset_mock()
    compose_up_checked(paths, NAME, component="deploy", compose_files=PROD, record=True,
                       deploying=True)
    up.assert_called_once()


def test_a_recreating_start_that_runs_the_pin_still_checks_it(box, monkeypatch) -> None:
    """resume recreates stale containers as a deploy does (`deploying`), from
    the overlay it rendered with the pins: those are checked all the same."""
    paths, _, up, _ = box
    write_pins(paths, NAME, (PIN,))
    _store(monkeypatch, "sha256:" + "f" * 64)
    with pytest.raises(ComposeRefused, match="is not the one autofix built"):
        _restart(paths, deploying=True)


# --- the release switch ---------------------------------------------------


def test_successful_switch_clears_pins_and_record(box) -> None:
    """A deploy, promote or rollback records the release it switched to
    (record_deploy_state); the pins of the release before go with it. The
    switch rendered its overlay without them, so nothing is rendered and
    Docker is not asked: a failing render cannot escape the switch."""
    from boxmunge.commands.deploy_steps import record_deploy_state
    paths, *_ = box
    record_deploy_state(paths, NAME, "v1", None)
    write_pins(paths, NAME, (PIN,))
    with patch("boxmunge.compose.prepare_compose_override",
               side_effect=DockerError("docker down")), \
            patch("boxmunge.docker_run.run", side_effect=DockerError("docker down")):
        record_deploy_state(paths, NAME, "v2", None)
    assert not os.path.lexists(paths.project_image_pins(NAME))
    assert forget_pins(paths, NAME) is False


def _pinned_myapp(paths: BoxPaths) -> None:
    """myapp deployed twice, its web service then pinned."""
    from boxmunge.project_registry import add_project
    from tests.test_commands.test_rollback import V1, V2, _deploy
    add_project("myapp", paths)
    _deploy(paths, V1, {"VERSION": "v1\n"})
    _deploy(paths, V2, {"VERSION": "v2\n"})
    with patch("boxmunge.notify.send_notification", lambda *a, **k: True):
        write_pins(paths, "myapp", (ImagePin("web", pin_ref("myapp", "web", IMAGE_ID),
                                             IMAGE_ID, "autofix"),))
    assert _myapp_web(paths)["image"] == pin_ref("myapp", "web", IMAGE_ID)


def _myapp_web(paths: BoxPaths) -> dict:
    return yaml.safe_load(paths.project_compose_override("myapp").read_text())["services"]["web"]


def test_a_deploy_runs_its_own_images_and_clears_the_pins(paths) -> None:
    from boxmunge.commands.deploy import run_deploy
    from tests.bundle_helpers import manifest_text, place_bundle
    _pinned_myapp(paths)
    started: list[dict] = []
    place_bundle(paths, timestamp="2026-10-13T110000000000",
                 files={"manifest.yml": manifest_text(), "VERSION": "v3\n"})
    with patch("boxmunge.compose_guard.compose_up",
               lambda *a, **k: started.append(_myapp_web(paths))), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        assert run_deploy("myapp", paths) == 0
    # The new release started on its own images, not the old release's pin.
    assert started and all("image" not in web for web in started)
    assert not os.path.lexists(paths.project_image_pins("myapp"))
    assert "image" not in _myapp_web(paths)


def test_a_rollback_runs_its_own_images_and_clears_the_pins(paths) -> None:
    """The rolled-back release ships its own images, which the deploy guard
    checks, so the pins of the release it replaces go too."""
    from boxmunge.commands.rollback import run_rollback
    from tests.test_commands.test_rollback import _docker
    _pinned_myapp(paths)
    with _docker(), patch("boxmunge.notify.send_notification", lambda *a, **k: True):
        assert run_rollback("myapp", paths, yes=True) == 0
    assert (paths.project_dir("myapp") / "VERSION").read_text() == "v1\n"
    assert not os.path.lexists(paths.project_image_pins("myapp"))
    assert "image" not in _myapp_web(paths)


def test_every_switch_records_through_record_deploy_state() -> None:
    """deploy, promote and git deploys switch in replace_release; rollback
    there too, or in its own record when the restore started the release."""
    import ast

    import boxmunge
    src = Path(boxmunge.__file__).parent
    sites = sorted(f"{p.relative_to(src)}:{fn.name}" for p in src.rglob("*.py")
                   for fn in ast.walk(ast.parse(p.read_text()))
                   if isinstance(fn, ast.FunctionDef)
                   for n in ast.walk(fn) if isinstance(n, ast.Call)
                   and getattr(n.func, "id", None) == "record_deploy_state")
    assert sites == ["commands/deploy.py:replace_release",
                     "commands/rollback.py:_report_not_started"]


def test_only_a_release_install_renders_without_the_pins() -> None:
    """Every other render (resume, recover, quarantine lift, upgrade, data
    chown, the user-namespace switch) keeps the pins in the overlay."""
    import ast

    import boxmunge
    src = Path(boxmunge.__file__).parent
    installing = sorted(f"{p.relative_to(src)}:{fn.name}" for p in src.rglob("*.py")
                        for fn in ast.walk(ast.parse(p.read_text()))
                        if isinstance(fn, ast.FunctionDef)
                        for n in ast.walk(fn) if isinstance(n, ast.Call)
                        for kw in n.keywords if kw.arg == "installing"
                        and fn.name not in ("prepare_compose_override",
                                            "render_compose_override"))
    assert installing == ["commands/release_config.py:decide_release_users",
                          "commands/release_config.py:generate_release_config",
                          "commands/rollback.py:restore_rolled_back_data"]


# --- the user-namespace migration -----------------------------------------


def test_the_migration_points_the_pins_at_the_loaded_ids(paths) -> None:
    new_id = "sha256:" + "d" * 64
    _record(paths, _pin_doc())
    remap_image_pins(paths, [NAME, "blog"], {IMAGE_ID: new_id})
    assert read_pins(paths, NAME) == (ImagePin("web", PIN.ref, new_id, "autofix"),)
    remap_image_pins(paths, [NAME], {IMAGE_ID: new_id})  # a resume
    assert read_pins(paths, NAME)[0].image_id == new_id


def test_the_rebuild_remaps_the_pins_after_loading_the_images(paths, monkeypatch,
                                                               tmp_path) -> None:
    from boxmunge.userns import engine as en
    from boxmunge.userns.inventory import ImageEntry, Inventory
    from boxmunge.userns.journal import FORWARD, Journal
    new_id = "sha256:" + "d" * 64
    _record(paths, _pin_doc())
    j = Journal(FORWARD, "switched", 100000, items={"network": "created"})

    def load(images, journal, directory, save):
        journal.image_map[IMAGE_ID] = new_id
    monkeypatch.setattr(en, "load_all", load)
    inv = Inventory("overlay2", "", str(tmp_path / "docker"), "29.9.0", projects=[NAME],
                    images=[ImageEntry(IMAGE_ID, [PIN.ref], 1, True)])
    en._rebuild(paths, j, inv, tmp_path / "img", lambda: None)
    assert read_pins(paths, NAME)[0].image_id == new_id


def test_the_rollback_remaps_the_pins_after_loading_the_images() -> None:
    import ast
    import inspect

    from boxmunge.userns import rollback
    body = ast.unparse(ast.parse(inspect.getsource(rollback._reverse)))
    assert body.index("load_all(rinv.images") < body.index("remap_image_pins(paths, rinv")


# --- reading --------------------------------------------------------------


@pytest.mark.parametrize("record", [
    "{not json", "[]", "\xff",
    {"pins": []},
    {"version": 2, "pins": _pin_doc()["pins"]},
    {"version": 1, "pins": []},
    {"version": 1, "pins": {"web": {}}},
    {"version": 1, "pins": ["web"]},
    {"version": 1, "pins": [{"service": "web"}]},
    _pin_doc(extra=1),
    _pin_doc(digest=IMAGE_ID),
    _pin_doc(image_id="sha256:abc"),
    _pin_doc(reason="manual"),
    _pin_doc(ref=pin_ref("blog", "web", IMAGE_ID)),
    {"version": 1, "pins": _pin_doc()["pins"] * 2},
])
def test_unreadable_pins_raise_state_error(paths, record) -> None:
    path = paths.project_image_pins(NAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(record, str):
        path.write_bytes(record.encode("latin-1"))
    else:
        path.write_text(json.dumps(record))
    with pytest.raises(StateError, match="image_pins"):
        read_pins(paths, NAME)


def test_a_linked_record_is_not_read_through(paths, tmp_path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps(_pin_doc()))
    path = paths.project_image_pins(NAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    with pytest.raises(StateError):
        read_pins(paths, NAME)


def test_no_record_is_no_pins(paths) -> None:
    assert read_pins(paths, NAME) == ()


# --- pulls ----------------------------------------------------------------


def _model_runs_the_pin(paths: BoxPaths) -> None:
    """compose.yml as the merged model reads with the overlay's pin."""
    project_dir = paths.project_dir(NAME)
    project_dir.mkdir(parents=True)
    (project_dir / "compose.yml").write_text(yaml.safe_dump(
        {"services": {"web": {"image": PIN.ref}, "db": {"image": "postgres:16"}}}))


def test_container_update_leaves_a_pinned_service_alone(paths) -> None:
    """A pinned tag is a platform name no registry serves: container update
    neither pulls nor compares it (deployed_inventory.pulled_services)."""
    from boxmunge.container_update import image_services
    from boxmunge.container_update_targets import UpdateTarget
    _model_runs_the_pin(paths)
    target = UpdateTarget(name=NAME, project_dir=paths.project_dir(NAME),
                          compose_files=["compose.yml"], strategy="leave_broken",
                          has_backup=False)
    assert list(image_services(target)) == ["db"]


def test_resume_pulls_no_pinned_service(paths) -> None:
    from boxmunge.commands.resume_cmd import _services_to_pull
    _model_runs_the_pin(paths)
    assert _services_to_pull(NAME, paths) == {"db": "postgres:16"}


# --- security.autofix -----------------------------------------------------


def test_autofix_key_bool_only_default_true() -> None:
    from boxmunge.commands.security_scan_inputs import ProjectScanError, project_meta
    from boxmunge.security_overlay import SecurityValidationError, validate_security_block
    validate_security_block({"autofix": False}, "project")
    validate_security_block({"autofix": True}, "project")
    for bad in ("no", 0, 1, None, "false"):
        with pytest.raises(SecurityValidationError, match="autofix"):
            validate_security_block({"autofix": bad}, "project")
    with pytest.raises(SecurityValidationError, match="only valid at the project level"):
        validate_security_block({"autofix": False}, "service:web")
    assert project_meta(NAME, {"project": NAME}, PROD).autofix is True
    assert project_meta(NAME, {"security": {"autofix": False}}, PROD).autofix is False
    with pytest.raises(ProjectScanError, match="autofix"):
        project_meta(NAME, {"security": {"autofix": "off"}}, PROD)


def test_first_write_leaves_the_directory_deploy_owned(paths: BoxPaths) -> None:
    """Root writing first must not leave state/image_pins root-owned."""
    from unittest.mock import patch

    from boxmunge.image_pins import _write
    chowned: list[str] = []
    with patch("boxmunge.fs_nofollow._chown_deploy", side_effect=chowned.append):
        _write(paths.project_image_pins(NAME), (PIN,))
    assert str(paths.project_image_pins(NAME).parent) in chowned

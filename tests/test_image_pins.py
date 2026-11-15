"""Per-project image pins (image_pins): the record, the overlay that runs
them, the release switch that clears them, and the `security.autofix` key.

Real filesystem; `docker compose up` and Pushover are stood in for, and
the unit tier's literal `docker compose config` (conftest) resolves
compose.yml alone, so the merged model is the integration tier's
(tests/integration/test_image_pin_resolve.py).
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
from boxmunge.compose_guard import check_start, compose_up_checked
from boxmunge.image_pins import ImagePin, clear_pins, pinned_services, read_pins, write_pins
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

NAME = "shop"
PROD = ["compose.yml", "compose.boxmunge.yml"]
DIGEST = "sha256:" + "a" * 64
PIN = ImagePin(service="web", ref=f"boxmunge.local/{NAME}/web:autofix-aaaaaaaaaaaa",
               digest=DIGEST, reason="autofix")
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
    pin = {"service": "web", "ref": PIN.ref, "digest": DIGEST, "reason": "autofix", **changes}
    return {"version": 1, "pins": [pin]}


# --- the overlay ----------------------------------------------------------


def test_overlay_emits_pinned_image_for_service() -> None:
    compose = {"services": {"web": {"image": "nginx:1.27"}, "app": {"build": "."},
                            "db": {"image": "postgres:16"}}}
    app = ImagePin("app", "boxmunge.local/shop/app:autofix-bbbbbbbbbbbb",
                   "sha256:" + "b" * 64, "autofix")
    services = yaml.safe_load(generate_compose_override(
        MANIFEST, user_compose=compose, pins=(PIN, app)))["services"]
    assert services["web"]["image"] == f"{PIN.ref}@{DIGEST}"
    # A build service's pin replaces the platform name its build carries.
    assert services["app"]["image"] == f"{app.ref}@{app.digest}"
    assert "image" not in services["db"]
    # Staging runs the staged release's own images: pins are production's.
    staging = yaml.safe_load(generate_staging_compose_override(MANIFEST, user_compose=compose))
    assert staging["services"]["web"].get("image") is None


def test_the_overlay_on_disk_carries_the_recorded_pins(box) -> None:
    paths, *_ = box
    _record(paths, _pin_doc())
    prepare_compose_override(paths, MANIFEST)
    assert _overlay(paths)["services"]["web"]["image"] == f"{PIN.ref}@{DIGEST}"


def test_a_release_being_installed_is_rendered_without_the_pins(box) -> None:
    """The pins are the running release's; the release a deploy, promote or
    rollback installs ships its own images."""
    paths, *_ = box
    _record(paths, _pin_doc())
    prepare_compose_override(paths, MANIFEST, installing=True)
    assert "image" not in _overlay(paths)["services"]["web"]


def test_a_pin_for_a_service_the_release_lacks_is_refused(box) -> None:
    paths, *_ = box
    _record(paths, _pin_doc(service="gone"))
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
    assert _overlay(paths)["services"]["web"]["image"] == f"{PIN.ref}@{DIGEST}"
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
    pins are not for; its switch renders and clears them anyway."""
    from boxmunge.release_txn import open_txn
    paths, *_ = box
    open_txn(paths, NAME, source="bundle", ref="shop-v2", replaced_ref="shop-v1",
             staged_id=None, snapshot="")
    with pytest.raises(ValueError, match="while an install is open"):
        write_pins(paths, NAME, (PIN,))
    assert not os.path.lexists(paths.project_image_pins(NAME))


def test_two_pins_for_one_service_are_refused(box) -> None:
    paths, *_ = box
    other = ImagePin("web", PIN.ref, "sha256:" + "c" * 64, "autofix")
    with pytest.raises(ValueError, match="web"):
        write_pins(paths, NAME, (PIN, other))
    assert read_pins(paths, NAME) == ()


@pytest.mark.parametrize("field, value", [
    ("service", ""), ("ref", ""), ("ref", f"{PIN.ref}@{DIGEST}"), ("ref", "a b"),
    ("digest", "sha256:abc"), ("digest", "a" * 64), ("reason", "manual"),
])
def test_a_malformed_pin_is_refused(field, value) -> None:
    with pytest.raises(ValueError):
        ImagePin(**{**PIN.__dict__, field: value})


# --- the release switch ---------------------------------------------------


def test_successful_switch_clears_pins_and_record(box) -> None:
    """A deploy, promote or rollback records the release it switched to
    (record_deploy_state); the pins of the release before go with it, and
    the overlay is rendered again without them."""
    from boxmunge.commands.deploy_steps import record_deploy_state
    paths, *_ = box
    record_deploy_state(paths, NAME, "v1", None)
    write_pins(paths, NAME, (PIN,))
    record_deploy_state(paths, NAME, "v2", None)
    assert not os.path.lexists(paths.project_image_pins(NAME))
    assert "image" not in _overlay(paths)["services"]["web"]
    check_start(paths, NAME, component="restart", compose_files=PROD)


def _pinned_myapp(paths: BoxPaths) -> str:
    """myapp deployed twice, its web service then pinned. Returns the image
    the pin runs."""
    from boxmunge.project_registry import add_project
    from tests.test_commands.test_rollback import V1, V2, _deploy
    add_project("myapp", paths)
    _deploy(paths, V1, {"VERSION": "v1\n"})
    _deploy(paths, V2, {"VERSION": "v2\n"})
    with patch("boxmunge.notify.send_notification", lambda *a, **k: True):
        write_pins(paths, "myapp", (ImagePin("web", "boxmunge.local/myapp/web:autofix-a",
                                             DIGEST, "autofix"),))
    web = yaml.safe_load(paths.project_compose_override("myapp").read_text())["services"]["web"]
    return web["image"]


def _myapp_web(paths: BoxPaths) -> dict:
    return yaml.safe_load(paths.project_compose_override("myapp").read_text())["services"]["web"]


def test_a_deploy_runs_its_own_images_and_clears_the_pins(paths) -> None:
    from boxmunge.commands.deploy import run_deploy
    from tests.bundle_helpers import manifest_text, place_bundle
    assert _pinned_myapp(paths).endswith(DIGEST)
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
    assert _pinned_myapp(paths).endswith(DIGEST)
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
    _pin_doc(digest="sha256:abc"),
    _pin_doc(reason="manual"),
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
    assert pinned_services(paths, NAME) == frozenset()


def test_pinned_services(paths) -> None:
    _record(paths, _pin_doc())
    assert pinned_services(paths, NAME) == frozenset({"web"})


# --- container update -----------------------------------------------------


def test_container_update_leaves_a_pinned_service_alone(paths) -> None:
    """A pinned service runs the image its pin names, whatever its tag
    names after a pull: container update neither pulls nor compares it."""
    from boxmunge.container_update import image_services
    from boxmunge.container_update_targets import build_targets
    project_dir = paths.project_dir(NAME)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump(MANIFEST))
    (project_dir / "compose.yml").write_text(yaml.safe_dump(COMPOSE))
    _record(paths, _pin_doc())
    with patch("boxmunge.container_update_targets.classify"):
        targets = [t for t in build_targets(paths, {}) if t.name == NAME]
    assert targets[0].pinned == frozenset({"web"})
    assert list(image_services(targets[0])) == ["db"]


def test_resume_pulls_no_pinned_service(paths) -> None:
    from boxmunge.commands.resume_cmd import _services_to_pull
    project_dir = paths.project_dir(NAME)
    project_dir.mkdir(parents=True)
    (project_dir / "compose.yml").write_text(yaml.safe_dump(COMPOSE))
    _record(paths, _pin_doc())
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

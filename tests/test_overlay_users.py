"""The overlay emits exactly the recorded user; tmpfs follows a numeric non-root user."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.compose import (
    ComposeError, generate_compose_override, generate_staging_compose_override,
    prepare_compose_override,
)
from boxmunge.compose_hardening import apply_run_user, tmpfs_for
from boxmunge.run_as import ServiceUser, write_users

MANIFEST = {"project": "app", "services": {"web": {"port": 8080, "writable": {
    "ephemeral": ["/var/cache/app"]}}}}
USER_COMPOSE = {"services": {"web": {"build": "."}, "db": {"image": "postgres:16"}}}


def _services(users, staging=False):
    gen = generate_staging_compose_override if staging else generate_compose_override
    return yaml.safe_load(gen(MANIFEST, user_compose=USER_COMPOSE, users=users))["services"]


def test_default_user_and_tmpfs_options() -> None:
    web = _services({"web": ServiceUser("10001:10001", "default")})["web"]
    assert web["user"] == "10001:10001"
    assert web["tmpfs"] == ["/tmp:mode=1777", "/var/cache/app:uid=10001,gid=10001,mode=0700"]


def test_no_record_emits_no_user_as_today() -> None:
    services = _services(None)
    assert "user" not in services["web"] and "user" not in services["db"]
    assert services["web"]["tmpfs"] == ["/tmp", "/var/cache/app"]


def test_image_and_compose_sources_emit_nothing() -> None:
    services = _services({"web": ServiceUser("1000", "compose"),
                          "db": ServiceUser(None, "manifest", "")})
    assert "user" not in services["web"] and "user" not in services["db"]


def test_root_declaration_emits_root_and_keeps_tmpfs() -> None:
    web = _services({"web": ServiceUser("0:0", "manifest")})["web"]
    assert web["user"] == "0:0" and web["tmpfs"] == ["/tmp", "/var/cache/app"]


def test_compose_only_service_gets_its_user_without_tmpfs() -> None:
    db = _services({"db": ServiceUser("999:1000", "manifest")})["db"]
    assert db["user"] == "999:1000" and "tmpfs" not in db


def test_staging_overlay_uses_the_users_it_is_given() -> None:
    web = _services({"web": ServiceUser("10001:10001", "default")}, staging=True)["web"]
    assert web["user"] == "10001:10001"


def test_explicit_tmpfs_options_are_left_alone() -> None:
    assert tmpfs_for("/run:size=8m", (10001, 10001)) == "/run:size=8m"
    assert apply_run_user({"tmpfs": ["/tmp"]}, None) == {"tmpfs": ["/tmp"]}


def _project(paths):
    project_dir = paths.project_dir("app")
    project_dir.mkdir(parents=True)
    (project_dir / "compose.yml").write_text(yaml.safe_dump(USER_COMPOSE))
    return project_dir


def test_prepare_replays_the_record(paths) -> None:
    _project(paths)
    write_users(paths, "app", {"web": ServiceUser("10001:10001", "default")})
    prepare_compose_override(paths, MANIFEST)
    overlay = yaml.safe_load(paths.project_compose_override("app").read_text())
    assert overlay["services"]["web"]["user"] == "10001:10001"


def test_prepare_refuses_a_malformed_record(paths) -> None:
    _project(paths)
    paths.project_users_record("app").write_text("[]")
    with pytest.raises(ComposeError, match="users record"):
        prepare_compose_override(paths, MANIFEST)

"""Who each service runs as, where operators look."""
from __future__ import annotations

import json

import pytest

from boxmunge.commands.security_views import format_project_json, format_project_text
from boxmunge.docker_containers import ImageFacts
from boxmunge.health_checks.service_users import check_service_users, pending_declarations
from boxmunge.project_registry import add_project
from boxmunge.run_as import ServiceUser, default_user_hint, write_users

MANIFEST = {"project": "shop", "schema_version": 3, "services": {
    "web": {"port": 8080}, "db": {"internal": True,
                                  "security": {"user": "image", "reason": "drops to postgres"}}}}
VIEW = dict(posture="balanced", dangerously_disable_quarantine=False, quarantined=False,
            quarantine_state=None, scan_state=None, active_suppressions=())


def test_view_shows_the_decision_and_the_reason() -> None:
    text = format_project_text(MANIFEST, **VIEW, users={
        "web": ServiceUser("10001:10001", "default"), "db": ServiceUser(None, "manifest"),
        "cache": ServiceUser("999:1000", "manifest")})
    assert "web:" in text and "10001:10001 (the default for a build: service" in text
    assert "the image's user, root (security.user: image), reason: 'drops to postgres'" in text
    assert "cache:" in text and "999:1000 (security.user)" in text


def test_view_says_when_nothing_was_decided() -> None:
    assert "not decided: deployed before boxmunge decided" in format_project_text(
        MANIFEST, **VIEW, users={})
    assert json.loads(format_project_json(MANIFEST, **VIEW, users={}))["users"] is None
    payload = json.loads(format_project_json(MANIFEST, **VIEW, users={
        "web": ServiceUser("10001:10001", "default")}))
    assert payload["users"]["web"] == {"user": "10001:10001", "source": "default",
                                       "image_user": ""}


def _deployed(paths, *names):
    for name in names:
        add_project(name, paths)
        paths.project_dir(name).mkdir(parents=True, exist_ok=True)
        (paths.project_dir(name) / "manifest.yml").write_text(
            f"project: {name}\nhosts: [{name}.example.com]\nservices:\n  web:\n"
            f"    port: 8080\n    routes:\n      - path: /\n")


def test_health_warns_for_deployed_projects_without_a_record(paths) -> None:
    _deployed(paths, "old", "new")
    write_users(paths, "new", {"web": ServiceUser("10001:10001", "default")})
    check = check_service_users(paths)
    assert check.status == "warn" and "old" in check.detail and "new" not in check.detail
    write_users(paths, "old", {"web": ServiceUser(None, "image", "node")})
    assert check_service_users(paths).status == "ok"


def test_doctor_lists_every_service_the_next_deploy_will_refuse(paths, monkeypatch) -> None:
    _deployed(paths, "shop", "blog")
    for name, compose in (("shop", "services:\n  web:\n    build: .\n  db:\n    image: postgres:16\n"
                                   "  cache:\n    image: redis:7\n"),
                          ("blog", "services:\n  web:\n    image: node:22\n")):
        (paths.project_dir(name) / "compose.yml").write_text(compose)
    monkeypatch.setattr("boxmunge.docker_containers.image_facts", lambda ref: ImageFacts(
        "sha256:" + "a" * 64, "node" if ref.startswith("node") else "", ()))
    pending, unchecked = pending_declarations(paths)
    assert pending == ["shop/cache (redis:7)", "shop/db (postgres:16)"] and unchecked == []


def test_doctor_names_a_project_it_cannot_check(paths) -> None:
    _deployed(paths, "shop")
    pending, unchecked = pending_declarations(paths)
    assert pending == [] and unchecked and unchecked[0].startswith("shop:")


@pytest.mark.parametrize("user, hinted", [(ServiceUser("10001:10001", "default"), True),
                                          (ServiceUser(None, "manifest"), False)])
def test_default_user_hint_only_for_the_default(paths, user, hinted) -> None:
    write_users(paths, "shop", {"web": user})
    hint = default_user_hint(paths, "shop", "web")
    assert (hint is not None and "passwd entry" in hint) is hinted
    assert default_user_hint(paths, "shop", "web", staging=True) is None


def test_a_record_only_data_chown_wrote_is_still_undecided(paths) -> None:
    _deployed(paths, "old")
    write_users(paths, "old", {"app": ServiceUser("10001:10001", "data-chown")})
    assert check_service_users(paths).status == "warn"

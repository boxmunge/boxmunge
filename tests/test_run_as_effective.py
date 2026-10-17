"""effective_user: compose, manifest, image USER, profile off, build default, refuse."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.run_as import (
    DEFAULT_USER, RunAsError, ServiceUser, effective_user, identity, read_users, write_users,
)

BUILD = {"build": {"context": "."}, "image": "boxmunge.invalid/app/web"}
REGISTRY = {"image": "postgres:16-alpine"}


def _manifest(svc_security=None, project_security=None, service="web"):
    svc = {"port": 8080} if svc_security is None else {"port": 8080, "security": svc_security}
    m = {"project": "app", "services": {service: svc}}
    if project_security is not None:
        m["security"] = project_security
    return m


def test_compose_user_wins_and_the_overlay_emits_nothing() -> None:
    u = effective_user("web", {**BUILD, "user": 1000}, _manifest(), "")
    assert (u.source, u.user, u.emitted(), u.runs_as()) == ("compose", "1000", None, "1000")


@pytest.mark.parametrize("declared, user, emitted", [
    ({"user": "999:1000"}, "999:1000", "999:1000"),
    ({"user": "root", "reason": "r"}, "0:0", "0:0"),
    ({"user": "image", "reason": "r"}, None, None),
])
def test_manifest_declaration(declared, user, emitted) -> None:
    u = effective_user("db", REGISTRY, _manifest(declared, service="db"), "")
    assert (u.source, u.user, u.emitted()) == ("manifest", user, emitted)


def test_project_level_declaration_applies_to_compose_only_services() -> None:
    u = effective_user("cache", REGISTRY, _manifest(project_security={"user": "999:999"}), "")
    assert u.emitted() == "999:999"


def test_image_with_a_non_root_user_runs_as_it() -> None:
    u = effective_user("db", REGISTRY, _manifest(service="db"), "node")
    assert (u.source, u.emitted(), u.runs_as()) == ("image", None, "node")


@pytest.mark.parametrize("image_user", ["", "0", "root", "0:0", "root:root", "0:1000"])
def test_build_service_without_non_root_user_gets_the_default(image_user) -> None:
    u = effective_user("web", BUILD, _manifest(), image_user)
    assert (u.source, u.emitted()) == ("default", DEFAULT_USER)
    assert u.nonroot_ids() == (10001, 10001)


def _pasted(text: str, manifest: dict) -> dict:
    """Merge the refusal's YAML block into `manifest` as an operator would."""
    block = text.split(":\n\n", 1)[1].split("\n\n", 1)[0]
    added = yaml.safe_load(block)
    merged = dict(manifest)
    merged["services"] = {**manifest["services"], **added["services"]}
    for name, svc in added["services"].items():
        if name in manifest["services"]:
            merged["services"][name] = {**manifest["services"][name], **svc}
    return merged


def test_compose_only_registry_root_image_is_refused_with_lines_that_paste() -> None:
    manifest = _manifest()
    with pytest.raises(RunAsError) as e:
        effective_user("db", REGISTRY, manifest, "")
    text = str(e.value)
    assert "postgres:16-alpine" in text and "internal: true" in text
    assert 'user: "<uid>:<gid>"' in text
    fixed = _pasted(text, manifest)
    assert effective_user("db", REGISTRY, fixed, "").source == "manifest"
    from boxmunge.run_as import validate_user_field
    validate_user_field(fixed["services"]["db"]["security"], "db")


def test_a_declared_service_is_told_to_add_a_security_block() -> None:
    manifest = _manifest(service="db")
    with pytest.raises(RunAsError) as e:
        effective_user("db", REGISTRY, manifest, "")
    text = str(e.value)
    assert "internal: true" not in text and "merge into services.db in manifest.yml" in text
    assert effective_user("db", REGISTRY, _pasted(text, manifest), "").user is None


def test_an_existing_security_block_gains_only_the_missing_keys() -> None:
    with pytest.raises(RunAsError) as e:
        effective_user("db", REGISTRY, _manifest({"reason": "kept"}, service="db"), "")
    text = str(e.value)
    assert "merge into services.db.security" in text
    assert "reason:" not in text.split(":\n\n", 1)[1].split("\n\n", 1)[0]


def test_profile_off_skips_the_default_and_the_refusal() -> None:
    off = {"profile": "off", "reason": "legacy"}
    assert effective_user("db", REGISTRY, _manifest(off, service="db"), "").source == "profile-off"
    assert effective_user("web", BUILD, _manifest(off), "").emitted() is None


def test_compose_user_spellings() -> None:
    """Review Focus 3: what Docker runs, normalised the same way everywhere."""
    for raw, who in [(1000, "1000"), ("1000", "1000"), ("postgres:postgres", "postgres"),
                     ("0", "root"), ("root:root", "root"), ("0:0", "root"), ("999:1000", "999")]:
        u = effective_user("web", {**BUILD, "user": raw}, _manifest(), "")
        assert u.runs_as() == who, raw
    assert identity("") == identity(None) == "root"
    assert ServiceUser("1000", "compose").nonroot_ids() is None  # uid only: no gid to give tmpfs
    assert ServiceUser("1000:1000", "compose").nonroot_ids() == (1000, 1000)
    assert ServiceUser("0:0", "manifest").nonroot_ids() is None
    assert ServiceUser(None, "image", "1000:1000").nonroot_ids() is None


def test_users_record_round_trip_and_validation(paths) -> None:
    users = {"web": ServiceUser(DEFAULT_USER, "default", ""),
             "db": ServiceUser(None, "manifest", "")}
    write_users(paths, "app", users)
    assert read_users(paths, "app") == users
    assert paths.project_users_record("app").name == "app.users.json"
    assert paths.project_users_record("app", staging=True).name == "app-staging.users.json"
    assert read_users(paths, "app", staging=True) == {}
    paths.project_users_record("app").write_text('{"web": {"user": 5, "source": "x"}}')
    with pytest.raises(RunAsError, match="is not"):
        read_users(paths, "app")


def test_a_linked_record_is_not_followed(paths, tmp_path) -> None:
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("{}")
    paths.project_users_record("app").symlink_to(elsewhere)
    with pytest.raises(RunAsError, match="cannot read"):
        read_users(paths, "app")


def test_project_delete_removes_both_records(paths) -> None:
    from boxmunge.commands.project_delete_cmd import project_state_files
    files = project_state_files(paths, "app")
    assert paths.project_users_record("app") in files
    assert paths.project_users_record("app", staging=True) in files

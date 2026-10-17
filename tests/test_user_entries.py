"""A manifest entry that only says who a compose-only service runs as."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.compose import generate_compose_override
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.manifest import get_routable_services, load_manifest, validate_manifest
from boxmunge.run_as import ServiceUser, effective_user
from boxmunge.user_entries import USER_ENTRIES

DB_ENTRY = {"security": {"user": "image", "reason": "postgres drops to postgres"}}


def _manifest(**db) -> dict:
    return {"schema_version": 3, "id": "01TESTULID0000000000000000", "project": "shop",
            "source": "bundle", "hosts": ["shop.example.com"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}, "db": db}}


def test_a_user_entry_validates() -> None:
    errors, _ = validate_manifest(_manifest(**DB_ENTRY), "shop")
    assert errors == []


@pytest.mark.parametrize("db, says", [
    ({**DB_ENTRY, "limits": {"memory": "1g"}}, "it also has limits"),
    ({"security": {"user": "image", "reason": "r", "profile": "off"}}, "only user and reason"),
    ({"security": {"reason": "r"}}, "give it security.user"),
    ({"security": {"user": "image"}}, "needs a non-empty reason"),
])
def test_a_user_entry_holds_only_the_user(db, says) -> None:
    errors, _ = validate_manifest(_manifest(**db), "shop")
    assert any(says in e for e in errors), errors


def test_the_loaded_name_is_reserved() -> None:
    errors, _ = validate_manifest({**_manifest(**DB_ENTRY), USER_ENTRIES: {}}, "shop")
    assert any("boxmunge's own name" in e for e in errors)


def test_loading_moves_user_entries_out_of_services(tmp_path) -> None:
    path = tmp_path / "manifest.yml"
    path.write_text(yaml.safe_dump(_manifest(**DB_ENTRY)))
    manifest = load_manifest(path)
    assert list(manifest["services"]) == ["web"] and manifest[USER_ENTRIES] == {"db": DB_ENTRY}
    assert list(get_routable_services(manifest)) == ["web"]
    u = effective_user("db", {"image": "postgres:16"}, manifest, "")
    assert (u.source, u.user) == ("manifest", None)


def test_the_overlay_treats_it_as_compose_only_but_for_the_user(tmp_path) -> None:
    path = tmp_path / "manifest.yml"
    path.write_text(yaml.safe_dump(_manifest(security={"user": "999:1000"})))
    manifest = load_manifest(path)
    compose = {"services": {"web": {"image": "nginx"}, "db": {"image": "redis:7-alpine"}}}
    db = yaml.safe_load(generate_compose_override(
        manifest, env_files={"project_env": "./project.env"}, user_compose=compose,
        users={"db": ServiceUser("999:1000", "manifest")}))["services"]["db"]
    assert db["user"] == "999:1000"
    assert not {"read_only", "tmpfs", "env_file", "networks"} & set(db)


def _compose(tmp_path, text):
    path = tmp_path / "compose.yml"
    path.write_text(text)
    return path


def test_compose_validation_accepts_its_named_volumes(tmp_path, paths) -> None:
    compose = _compose(tmp_path, "services:\n  db:\n    image: postgres:16\n    volumes:\n"
                                 "      - pgdata:/var/lib/postgresql/data\nvolumes:\n  pgdata: {}\n")
    validate_user_compose(compose, paths, project_name="shop", manifest_services={},
                          user_entries={"db": DB_ENTRY})


def test_an_entry_for_a_service_compose_lacks_is_refused(tmp_path, paths) -> None:
    compose = _compose(tmp_path, "services:\n  web:\n    image: nginx\n")
    with pytest.raises(ComposeSecurityError, match="does not define it"):
        validate_user_compose(compose, paths, project_name="shop", manifest_services={},
                              user_entries={"db": DB_ENTRY})


def test_an_entry_and_a_compose_user_conflict(tmp_path, paths) -> None:
    compose = _compose(tmp_path, "services:\n  db:\n    image: postgres:16\n    user: '70'\n")
    with pytest.raises(ComposeSecurityError, match="keep one"):
        validate_user_compose(compose, paths, project_name="shop", manifest_services={},
                              user_entries={"db": DB_ENTRY})

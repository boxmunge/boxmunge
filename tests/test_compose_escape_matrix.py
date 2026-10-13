"""Regression matrix for the v0.11 compose-escape audit (area F).

Each case is a crafted service fragment from the auditor's probe scripts.
The compose file lives where a real project's would — inside
``projects/myapp/`` under the boxmunge root — so relative paths resolve the
way they do on a server.
"""
from __future__ import annotations

from typing import Any

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import SecurityValidationError, validate_security_block


def _validate(paths: BoxPaths, svc: dict[str, Any], top: dict | None = None) -> None:
    doc: dict[str, Any] = {"services": {"web": {"image": "alpine", **svc}}}
    doc.update(top or {})
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True, exist_ok=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump(doc))
    validate_user_compose(compose, paths, project_name="myapp")


# ---------------------------------------------------------------------------
# F-01 — normalisation, parent paths, strict booleans
# ---------------------------------------------------------------------------

F01_REJECTED = {
    "privileged as string": {"privileged": "true"},
    "read_only as string": {"read_only": "true"},
    "init as string": {"init": "false"},
    "cap CAP_ prefix": {"cap_add": ["CAP_SYS_ADMIN"]},
    "cap lower case": {"cap_add": ["cap_dac_read_search"]},
    "cap padded": {"cap_add": [" sys_admin "]},
    "cap ALL": {"cap_add": ["ALL"]},
    "cap SYS_MODULE": {"cap_add": ["SYS_MODULE"]},
    "cap SYS_RAWIO": {"cap_add": ["SYS_RAWIO"]},
    "cap MAC_ADMIN": {"cap_add": ["MAC_ADMIN"]},
    "nnp with equals": {"security_opt": ["no-new-privileges=false"]},
    "label with equals": {"security_opt": ["label=disable"]},
    "custom seccomp file": {"security_opt": ["seccomp=./allow-all.json"]},
    "custom seccomp colon": {"security_opt": ["seccomp:/srv/allow.json"]},
    "pid padded upper": {"pid": " HOST "},
    "ipc joins container": {"ipc": "container:projb-db-1"},
    "network joins container": {"network_mode": "container:projb-db-1"},
    "uts host": {"uts": "host"},
    "root double slash": {"volumes": ["//:/host"]},
    "root dot": {"volumes": ["/.:/host"]},
    "root via dotdot": {"volumes": ["/tmp/..:/host"]},
    "etc double slash": {"volumes": ["//etc:/h"]},
    "etc via dotdot": {"volumes": ["/tmp/../etc:/h"]},
    "parent of docker.sock": {"volumes": ["/var/run:/h"]},
    "run": {"volumes": ["/run:/h"]},
    "containerd socket": {"volumes": ["/run/containerd/containerd.sock:/c.sock"]},
    "docker state": {"volumes": ["/var/lib/docker:/d"]},
    "root home": {"volumes": ["/root:/r"]},
    "deploy ssh": {"volumes": ["/home/deploy/.ssh:/s"]},
    "boot": {"volumes": ["/boot:/b"]},
    "relative to host root": {"volumes": ["../../../../../../../..:/host"]},
    "relative to boxmunge config": {"volumes": ["../../config:/c"]},
    "relative to projects dir": {"volumes": ["..:/all"]},
    "tilde to root": {"volumes": ["~/../..:/host"]},
    "long bind root": {"volumes": [{"type": "bind", "source": "/", "target": "/h"}]},
    "long bind relative": {
        "volumes": [{"type": "bind", "source": "../../../..", "target": "/h"}],
    },
}


@pytest.mark.parametrize("svc", F01_REJECTED.values(), ids=F01_REJECTED.keys())
def test_f01_hostile_spellings_rejected(paths: BoxPaths, svc: dict) -> None:
    with pytest.raises(ComposeSecurityError):
        _validate(paths, svc)


def test_f01_boxmunge_root_rejected(paths: BoxPaths) -> None:
    with pytest.raises(ComposeSecurityError, match="protected host path"):
        _validate(paths, {"volumes": [f"{paths.root}:/bm"]})


def test_f01_string_flag_error_says_what_to_write(paths: BoxPaths) -> None:
    with pytest.raises(ComposeSecurityError, match="unquoted true or false"):
        _validate(paths, {"privileged": "true"})


F01_ACCEPTED = {
    "lower-case benign cap": {"cap_add": ["net_raw"]},
    "dropped cap re-added": {"cap_add": ["NET_ADMIN", "SYS_PTRACE"]},
    "default seccomp": {"security_opt": ["seccomp=runtime/default"]},
    "named apparmor profile": {"security_opt": ["apparmor=docker-default"]},
    "project data dir": {"volumes": ["./data:/data", "data:/d"]},
    "network via sibling service": {"network_mode": "service:db"},
    "shareable ipc": {"ipc": "shareable"},
    "booleans": {"read_only": False, "init": True, "privileged": False},
}


@pytest.mark.parametrize("svc", F01_ACCEPTED.values(), ids=F01_ACCEPTED.keys())
def test_f01_benign_values_accepted(paths: BoxPaths, svc: dict) -> None:
    _validate(paths, svc)


# Manifest `security.cap_add` shares the compose denylist.

@pytest.mark.parametrize("cap", ["SYS_ADMIN", "DAC_READ_SEARCH", "SYS_MODULE", "BPF", "ALL"])
def test_f01_manifest_cap_add_denylist(cap: str) -> None:
    with pytest.raises(SecurityValidationError, match="never allowed"):
        validate_security_block({"cap_add": [cap]}, "project")


def test_f01_manifest_cap_add_denylist_any_spelling() -> None:
    with pytest.raises(SecurityValidationError, match="never allowed"):
        validate_security_block({"cap_add": ["cap_sys_admin"]}, "service:web")


def test_f01_manifest_cap_requires_canonical_spelling() -> None:
    with pytest.raises(SecurityValidationError, match="'NET_RAW'"):
        validate_security_block({"cap_add": ["cap_net_raw"]}, "project")


def test_f01_manifest_benign_cap_add_accepted() -> None:
    validate_security_block({"cap_add": ["NET_RAW"]}, "project")


def test_f01_manifest_cap_drop_of_denied_cap_accepted() -> None:
    # Dropping a dangerous capability only ever tightens the posture.
    validate_security_block({"cap_drop": ["SYS_ADMIN"]}, "project")


# ---------------------------------------------------------------------------
# F-03 — every compose service is hardened, not only manifest services
# ---------------------------------------------------------------------------

_MANIFEST = {
    "project": "myapp",
    "hosts": ["myapp.example.com"],
    "services": {"web": {"port": 80, "routes": [{"path": "/"}]}},
}
_USER_COMPOSE = {
    "services": {
        "web": {"build": "."},
        "db": {"image": "postgres:16-alpine"},
        "cache": {"image": "redis:7", "read_only": False},
    },
}


def _overlay(manifest: dict, user_compose: dict) -> dict:
    from boxmunge.compose import generate_compose_override
    return yaml.safe_load(generate_compose_override(manifest, user_compose=user_compose))


def test_f03_compose_only_services_get_default_hardening() -> None:
    services = _overlay(_MANIFEST, _USER_COMPOSE)["services"]
    db = services["db"]
    assert db["security_opt"] == ["no-new-privileges:true"]
    assert db["init"] is True
    assert db["pids_limit"] == 512
    assert "SYS_PTRACE" in db["cap_drop"]
    assert db["read_only"] is True
    assert db["tmpfs"] == ["/tmp"]


def test_f03_compose_only_services_get_no_routing_or_env() -> None:
    db = _overlay(_MANIFEST, _USER_COMPOSE)["services"]["db"]
    assert "networks" not in db
    assert "env_file" not in db


def test_f03_compose_only_service_keeps_user_read_only_choice() -> None:
    cache = _overlay(_MANIFEST, _USER_COMPOSE)["services"]["cache"]
    assert "read_only" not in cache
    assert cache["security_opt"] == ["no-new-privileges:true"]


def test_f03_compose_only_services_follow_project_security_block() -> None:
    manifest = {**_MANIFEST, "security": {"pids_limit": 2048, "cap_add": ["NET_RAW"]}}
    db = _overlay(manifest, _USER_COMPOSE)["services"]["db"]
    assert db["pids_limit"] == 2048
    assert "NET_RAW" not in db["cap_drop"]


def test_f03_compose_only_services_unhardened_only_by_project_off() -> None:
    manifest = {**_MANIFEST, "security": {"profile": "off", "reason": "lab box"}}
    services = _overlay(manifest, _USER_COMPOSE).get("services", {})
    assert "db" not in services


def test_f03_staging_overlay_hardens_compose_only_services() -> None:
    from boxmunge.compose import generate_staging_compose_override
    overlay = yaml.safe_load(
        generate_staging_compose_override(_MANIFEST, user_compose=_USER_COMPOSE)
    )
    assert overlay["services"]["db"]["security_opt"] == ["no-new-privileges:true"]


def test_f03_overlay_refuses_missing_compose_file(paths: BoxPaths) -> None:
    from boxmunge.compose import ComposeError, prepare_compose_override
    paths.project_dir("myapp").mkdir(parents=True)
    with pytest.raises(ComposeError, match="compose.yml"):
        prepare_compose_override(paths, _MANIFEST)


def _write_two_service_compose(paths: BoxPaths):
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump({
        "services": {"web": {"image": "nginx"}, "db": {"image": "x", "privileged": True}},
    }))
    return compose


def test_f03_compose_only_service_validated_under_default(paths: BoxPaths) -> None:
    compose = _write_two_service_compose(paths)
    with pytest.raises(ComposeSecurityError, match="service db"):
        validate_user_compose(
            compose, paths, project_name="myapp",
            manifest_services=_MANIFEST["services"],
        )


def test_f03_compose_only_service_inherits_project_off(paths: BoxPaths) -> None:
    compose = _write_two_service_compose(paths)
    validate_user_compose(
        compose, paths, project_name="myapp",
        off_services={"web"},
        cve_policy={"profile": "off", "reason": "lab box"},
        manifest_services=_MANIFEST["services"],
    )


# ---------------------------------------------------------------------------
# F-09 — a project's compose file stays inside its own project
# ---------------------------------------------------------------------------

_EXT = {"external": True}

F09_REJECTED = {
    "join other project's network": (
        {"networks": ["projb_default"]}, {"networks": {"projb_default": _EXT}},
        "external",
    ),
    "join host network by name": (
        {"networks": ["hostnet"]}, {"networks": {"hostnet": {"external": True, "name": "host"}}},
        "external",
    ),
    "declare the shared proxy network": (
        {"networks": {"boxmunge-proxy": {"aliases": ["projb-web"]}, "default": {}}},
        {"networks": {"boxmunge-proxy": _EXT}},
        "boxmunge attaches routed services",
    ),
    "rename own network onto another's": (
        {"networks": ["backend"]}, {"networks": {"backend": {"name": "projb_default"}}},
        "name:",
    ),
    "macvlan network": (
        {"networks": ["lan"]}, {"networks": {"lan": {"driver": "macvlan"}}}, "driver",
    ),
    "undeclared network": ({"networks": ["projb_default"]}, None, "does not declare"),
    "alias in another project's namespace": (
        {"networks": {"default": {"aliases": ["projb-web"]}}}, None, "alias",
    ),
    "unprefixed alias": ({"networks": {"default": {"aliases": ["db"]}}}, None, "alias"),
    "external volume": (
        {"volumes": ["data:/d"]}, {"volumes": {"data": {"external": True, "name": "projb_data"}}},
        "external",
    ),
    "volume renamed onto another's": (
        {"volumes": ["data:/d"]}, {"volumes": {"data": {"name": "projb_data"}}}, "name:",
    ),
    "volume bound to host root": (
        {"volumes": ["hostroot:/host"]},
        {"volumes": {"hostroot": {"driver": "local", "driver_opts": {
            "type": "none", "o": "bind", "device": "/"}}}},
        "driver_opts",
    ),
    "external_links": ({"external_links": ["projb-db-1:db"]}, None, "external_links"),
    "volumes_from container": (
        {"volumes_from": ["container:projb-db-1"]}, None, "volumes_from",
    ),
    "secret file in boxmunge config": (
        {"secrets": ["k"]}, {"secrets": {"k": {"file": "../../config/backup.key"}}},
        "outside the project",
    ),
    "config file in another project": (
        {"configs": ["c"]}, {"configs": {"c": {"file": "../projb/secrets.env"}}},
        "outside the project",
    ),
    "build context outside project": (
        {"build": {"context": "../.."}}, None, "build context",
    ),
    "bind other project": ({"volumes": ["../projb:/b"]}, None, "outside the project"),
    "bind arbitrary host dir": ({"volumes": ["/srv/media:/m"]}, None, "outside the project"),
    "build on host network": (
        {"build": {"context": ".", "network": "host"}}, None, "build.network",
    ),
}


@pytest.mark.parametrize(
    "svc,top,match", F09_REJECTED.values(), ids=F09_REJECTED.keys(),
)
def test_f09_cross_project_reach_rejected(
    paths: BoxPaths, svc: dict, top: dict | None, match: str,
) -> None:
    with pytest.raises(ComposeSecurityError, match=match):
        _validate(paths, svc, top)


F09_ACCEPTED = {
    "prefixed alias": ({"networks": {"default": {"aliases": ["myapp-db"]}}}, None),
    "own internal network": (
        {"networks": ["backend"]}, {"networks": {"backend": {"internal": True}}},
    ),
    "own named volume": ({"volumes": ["data:/d"]}, {"volumes": {"data": {}}}),
    "secret file in project": ({"secrets": ["k"]}, {"secrets": {"k": {"file": "./k.txt"}}}),
    "build context in project": ({"build": {"context": "./repo/web"}}, None),
    "build from remote git": ({"build": "https://example.com/app.git#main"}, None),
    "volumes_from sibling": ({"volumes_from": ["db"]}, None),
}


@pytest.mark.parametrize("svc,top", F09_ACCEPTED.values(), ids=F09_ACCEPTED.keys())
def test_f09_own_project_resources_accepted(
    paths: BoxPaths, svc: dict, top: dict | None,
) -> None:
    _validate(paths, svc, top)


def test_f09_absolute_path_inside_project_accepted(paths: BoxPaths) -> None:
    _validate(paths, {"volumes": [f"{paths.project_dir('myapp')}/data:/d"]})


def test_f09_symlink_out_of_project_rejected(paths: BoxPaths, tmp_path) -> None:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (project_dir / "data").symlink_to(outside)
    with pytest.raises(ComposeSecurityError, match="outside the project"):
        _validate(paths, {"volumes": ["./data:/d"]})


def _validate_off(paths: BoxPaths, svc: dict) -> None:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True, exist_ok=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": {"image": "x", **svc}}}))
    validate_user_compose(compose, paths, project_name="myapp", off_services={"web"})


def test_f09_profile_off_relaxes_bind_confinement_with_warning(paths: BoxPaths) -> None:
    _validate_off(paths, {"volumes": ["/srv/media:/m"]})


def test_f09_profile_off_does_not_relax_alias_namespace(paths: BoxPaths) -> None:
    with pytest.raises(ComposeSecurityError, match="alias"):
        _validate_off(paths, {"networks": {"default": {"aliases": ["projb-web"]}}})

"""F-05: host-published ports are refused in compose.yml and published only
through the manifest's opt-in `security.published_ports`, on 127.0.0.1
unless explicitly widened."""
from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest
import yaml

from boxmunge.compose import generate_compose_override, generate_staging_compose_override
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import SecurityValidationError, validate_security_block
from boxmunge.security_warn import warn_published_ports

_DB = {"service": "db", "port": 5432, "reason": "admin access over an SSH tunnel"}


def _compose(paths: BoxPaths, services: dict) -> Path:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True, exist_ok=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": services}))
    return compose


@pytest.mark.parametrize("ports", [
    ["5432:5432"],
    ["0.0.0.0:5432:5432"],
    ["127.0.0.1:5432:5432"],
    [{"target": 5432, "published": "5432", "host_ip": "127.0.0.1", "mode": "ingress"}],
], ids=["short", "all interfaces", "loopback", "resolved long syntax"])
def test_compose_ports_rejected(paths: BoxPaths, ports: list) -> None:
    compose = _compose(paths, {"web": {"image": "nginx"}, "db": {"image": "x", "ports": ports}})
    with pytest.raises(ComposeSecurityError, match="security.published_ports"):
        validate_user_compose(compose, paths, project_name="myapp")


def test_compose_ports_rejected_even_when_profile_off(paths: BoxPaths) -> None:
    compose = _compose(paths, {"web": {"image": "nginx", "ports": ["8080:80"]}})
    with pytest.raises(ComposeSecurityError, match="ports"):
        validate_user_compose(compose, paths, project_name="myapp", off_services={"web"})


def test_expose_is_not_publishing(paths: BoxPaths) -> None:
    compose = _compose(paths, {"web": {"image": "nginx", "expose": ["80"]}})
    validate_user_compose(compose, paths, project_name="myapp")


def test_declared_service_must_exist(paths: BoxPaths) -> None:
    compose = _compose(paths, {"web": {"image": "nginx"}})
    with pytest.raises(ComposeSecurityError, match="does not define"):
        validate_user_compose(
            compose, paths, project_name="myapp",
            cve_policy={"published_ports": [_DB]},
        )


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,match", [
    ([], "non-empty list"),
    ([{"service": "db", "port": 5432}], "reason"),
    ([{**_DB, "reason": "  "}], "reason"),
    ([{**_DB, "port": "5432"}], "container port"),
    ([{**_DB, "port": 70000}], "container port"),
    ([{**_DB, "host_port": True}], "host_port"),
    ([{**_DB, "host_ip": "everywhere"}], "host_ip"),
    ([{**_DB, "protocol": "sctp"}], "protocol"),
    ([{**_DB, "bind": "0.0.0.0"}], "unknown key"),
    ([{k: v for k, v in _DB.items() if k != "service"}], "service"),
    ([_DB, _DB], "twice"),
])
def test_manifest_published_ports_validation(value: list, match: str) -> None:
    with pytest.raises(SecurityValidationError, match=match):
        validate_security_block({"published_ports": value}, "project")


def test_manifest_published_ports_project_level_only() -> None:
    with pytest.raises(SecurityValidationError, match="project level"):
        validate_security_block({"published_ports": [_DB]}, "service:db")


def test_manifest_published_ports_accepted() -> None:
    validate_security_block(
        {"published_ports": [_DB, {**_DB, "port": 9090, "host_ip": "0.0.0.0",
                                   "protocol": "udp", "host_port": 19090}]},
        "project",
    )


# ---------------------------------------------------------------------------
# Overlay and warnings
# ---------------------------------------------------------------------------

_MANIFEST = {
    "project": "myapp",
    "hosts": ["myapp.example.com"],
    "services": {"web": {"port": 80, "routes": [{"path": "/"}]}},
    "security": {"published_ports": [_DB]},
}
_USER = {"services": {"web": {"image": "nginx"}, "db": {"image": "postgres"}}}


def test_overlay_publishes_declared_port_on_loopback() -> None:
    overlay = yaml.safe_load(generate_compose_override(_MANIFEST, user_compose=_USER))
    assert overlay["services"]["db"]["ports"] == [
        {"target": 5432, "published": "5432", "host_ip": "127.0.0.1", "protocol": "tcp"},
    ]
    assert overlay["services"]["db"]["security_opt"] == ["no-new-privileges:true"]
    assert "ports" not in overlay["services"]["web"]


def test_overlay_honours_explicit_widening() -> None:
    manifest = {**_MANIFEST, "security": {"published_ports": [
        {**_DB, "host_ip": "0.0.0.0", "host_port": 15432},
    ]}}
    db = yaml.safe_load(generate_compose_override(manifest, user_compose=_USER))["services"]["db"]
    assert db["ports"] == [
        {"target": 5432, "published": "15432", "host_ip": "0.0.0.0", "protocol": "tcp"},
    ]


def test_staging_overlay_publishes_nothing() -> None:
    overlay = yaml.safe_load(generate_staging_compose_override(_MANIFEST, user_compose=_USER))
    assert "ports" not in overlay["services"]["db"]


def test_overlay_publishes_for_service_whose_profile_is_off() -> None:
    manifest = {**_MANIFEST, "security": {
        "profile": "off", "reason": "lab", "published_ports": [_DB],
    }}
    db = yaml.safe_load(generate_compose_override(manifest, user_compose=_USER))["services"]["db"]
    assert db == {"ports": [
        {"target": 5432, "published": "5432", "host_ip": "127.0.0.1", "protocol": "tcp"},
    ]}


def test_every_deploy_warns_about_published_ports(paths: BoxPaths) -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        warn_published_ports(paths, _MANIFEST, component="deploy")
    out = buf.getvalue()
    assert "[WARNING] myapp publishes 127.0.0.1:5432 -> db:5432/tcp" in out
    assert "this host only" in out
    assert "SSH tunnel" in out


def test_widened_port_warning_says_network_reachable(paths: BoxPaths) -> None:
    manifest = {**_MANIFEST, "security": {"published_ports": [{**_DB, "host_ip": "0.0.0.0"}]}}
    buf = io.StringIO()
    with redirect_stdout(buf):
        warn_published_ports(paths, manifest, component="deploy")
    assert "REACHABLE FROM THE NETWORK" in buf.getvalue()

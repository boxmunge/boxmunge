"""F-04: manifest values that reach the Caddyfile, and recovery from a bad
site file when Caddy rejects it."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.caddy import prepare_caddy_config
from boxmunge.docker import DockerError, caddy_reload
from boxmunge.manifest import validate_manifest
from boxmunge.paths import BoxPaths


def _manifest(port: object = 8080, path: object = "/") -> dict:
    return {
        "schema_version": 3, "id": "01KN107SD5WQTA9DC8EXKFF2NP",
        "project": "myapp", "source": "bundle", "hosts": ["myapp.example.com"],
        "services": {"web": {"port": port, "routes": [{"path": path}]}},
        "backup": {"type": "none"},
    }


def _errors(manifest: dict) -> list[str]:
    errors, _ = validate_manifest(manifest, "myapp")
    return errors


def test_auditor_injection_payload_rejected() -> None:
    manifest = _manifest(
        port="80\n    }\n    handle /loot/* {\n        root * /data\n",
        path="/api/* {\n        respond \"injected\"\n    }\n}\nvictim.example.com {",
    )
    errors = _errors(manifest)
    assert any("port" in e for e in errors), errors
    assert any("route 0: path" in e for e in errors), errors


@pytest.mark.parametrize("path", [
    "/api/* {", "/a b", "/a\n", "/a\tb", "api", "", "/a{b}", '/"q"', "/a;b",
    "/a*b", "//x\nfoo", 7, None,
])
def test_hostile_or_malformed_route_path_rejected(path: object) -> None:
    assert any("route 0: path" in e for e in _errors(_manifest(path=path)))


@pytest.mark.parametrize("path", ["/", "/api/*", "/api*", "/static/v1.2/~x-y_z/"])
def test_plain_route_paths_accepted(path: str) -> None:
    assert _errors(_manifest(path=path)) == []


@pytest.mark.parametrize("port", ["8080", True, 0, 65536, -1, 80.5, None, "80 {"])
def test_bad_port_rejected(port: object) -> None:
    errors = _errors(_manifest(port=port))
    assert any("port" in e and "1 to 65535" in e for e in errors), errors


@pytest.mark.parametrize("port", [1, 80, 65535])
def test_valid_port_accepted(port: int) -> None:
    assert _errors(_manifest(port=port)) == []


def test_non_mapping_service_reported_not_crashing() -> None:
    manifest = _manifest()
    manifest["services"]["web"] = ["not", "a", "mapping"]
    assert any("must be a mapping" in e for e in _errors(manifest))


# ---------------------------------------------------------------------------
# Restore the previous site file when Caddy rejects the new one
# ---------------------------------------------------------------------------

def _site(paths: BoxPaths):
    return paths.project_caddy_site("myapp")


def _reload_with(paths: BoxPaths, *, valid: bool, running: bool = True) -> None:
    with patch("boxmunge.docker.caddy_validate", return_value=valid), \
         patch("boxmunge.docker.container_running", return_value=running), \
         patch("boxmunge.docker._run"):
        caddy_reload(paths.caddy, paths.state)


def test_rejected_config_restores_previous_site(paths: BoxPaths) -> None:
    site = _site(paths)
    site.parent.mkdir(parents=True, exist_ok=True)
    site.write_text("last accepted\n")
    prepare_caddy_config(paths, _manifest())
    assert "myapp.example.com" in site.read_text()

    with pytest.raises(DockerError, match="Restored .* myapp.conf"):
        _reload_with(paths, valid=False)
    assert site.read_text() == "last accepted\n"


def test_rejected_config_removes_site_that_did_not_exist(paths: BoxPaths) -> None:
    prepare_caddy_config(paths, _manifest())
    assert _site(paths).exists()
    with pytest.raises(DockerError):
        _reload_with(paths, valid=False)
    assert not _site(paths).exists()


def test_accepted_config_becomes_the_restore_point(paths: BoxPaths) -> None:
    prepare_caddy_config(paths, _manifest(port=8080))
    _reload_with(paths, valid=True)
    accepted = _site(paths).read_text()

    prepare_caddy_config(paths, _manifest(port=9090))
    with pytest.raises(DockerError):
        _reload_with(paths, valid=False)
    assert _site(paths).read_text() == accepted


def test_repeated_writes_restore_the_last_accepted_content(paths: BoxPaths) -> None:
    site = _site(paths)
    site.parent.mkdir(parents=True, exist_ok=True)
    site.write_text("last accepted\n")
    prepare_caddy_config(paths, _manifest(port=8080))
    prepare_caddy_config(paths, _manifest(port=9090))
    with pytest.raises(DockerError):
        _reload_with(paths, valid=False)
    assert site.read_text() == "last accepted\n"


def test_caddy_not_running_keeps_new_site(paths: BoxPaths) -> None:
    prepare_caddy_config(paths, _manifest(port=9090))
    with pytest.raises(DockerError, match="not running"):
        _reload_with(paths, valid=False, running=False)
    assert "9090" in _site(paths).read_text()


def test_site_file_is_world_readable(paths: BoxPaths) -> None:
    prepare_caddy_config(paths, _manifest())
    assert _site(paths).stat().st_mode & 0o777 == 0o644


def test_restore_leaves_files_another_operation_rewrote(paths: BoxPaths) -> None:
    # A pause or quarantine maintenance page written after the deploy must
    # survive a restore triggered by some other project's bad config.
    site = _site(paths)
    site.parent.mkdir(parents=True, exist_ok=True)
    site.write_text("last accepted\n")
    prepare_caddy_config(paths, _manifest())
    site.write_text("maintenance page\n")
    with pytest.raises(DockerError):
        _reload_with(paths, valid=False)
    assert site.read_text() == "maintenance page\n"

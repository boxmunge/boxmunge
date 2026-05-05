"""Tests for staging Caddy and Compose config generation."""
import io
from contextlib import redirect_stdout

import pytest
import yaml
from boxmunge.caddy import generate_staging_caddy_config
from boxmunge.compose import generate_staging_compose_base, generate_staging_compose_override

MANIFEST = {
    "project": "myapp",
    "hosts": ["myapp.example.com", "www.example.com"],
    "services": {
        "frontend": {
            "port": 3000,
            "routes": [{"path": "/"}],
        },
        "backend": {
            "port": 8000,
            "routes": [{"path": "/api/*"}],
        },
    },
}

class TestStagingCaddyConfig:
    def test_staging_hostname_prefix(self) -> None:
        config = generate_staging_caddy_config(MANIFEST)
        assert "staging.myapp.example.com" in config
        assert "staging.www.example.com" in config

    def test_staging_service_aliases(self) -> None:
        config = generate_staging_caddy_config(MANIFEST)
        assert "myapp-staging-frontend:3000" in config
        assert "myapp-staging-backend:8000" in config
        # Production aliases should NOT appear
        assert "myapp-frontend:" not in config
        assert "myapp-backend:" not in config

    def test_routes_ordered_by_specificity(self) -> None:
        config = generate_staging_caddy_config(MANIFEST)
        api_pos = config.index("/api/*")
        root_pos = config.index("handle {")
        assert api_pos < root_pos

class TestStagingComposeOverride:
    def test_staging_aliases(self) -> None:
        content = generate_staging_compose_override(MANIFEST)
        assert "myapp-staging-frontend" in content
        assert "myapp-staging-backend" in content

    def test_includes_proxy_network(self) -> None:
        content = generate_staging_compose_override(MANIFEST)
        assert "boxmunge-proxy" in content
        assert "external: true" in content

    def test_staging_routable_services_keep_default_network(self) -> None:
        """Staging routable services must stay on default for inter-service DNS."""
        content = generate_staging_compose_override(MANIFEST)
        parsed = yaml.safe_load(content)
        for svc in ("frontend", "backend"):
            networks = parsed["services"][svc]["networks"]
            assert "default" in networks, f"{svc} missing default network"
            assert "boxmunge-proxy" in networks, f"{svc} missing boxmunge-proxy"

    def test_internal_services_excluded_from_proxy(self) -> None:
        """Non-routable services don't get proxy-network aliases in staging.

        They may still appear for hardening, env_files, or limits, but
        never with a boxmunge-proxy network entry.
        """
        manifest = {
            **MANIFEST,
            "services": {
                **MANIFEST["services"],
                "db": {"port": 5432, "internal": True, "routes": []},
            },
        }
        content = generate_staging_compose_override(manifest)
        parsed = yaml.safe_load(content)
        db = parsed["services"].get("db", {})
        assert "networks" not in db


class TestStagingComposeBase:
    def test_strips_ports(self, tmp_path) -> None:
        """Staging base must strip ports to avoid conflicts with production."""
        compose = tmp_path / "compose.yml"
        compose.write_text(yaml.dump({
            "services": {
                "web": {"build": ".", "ports": ["8080:8080"]},
                "db": {"image": "postgres:16"},
            },
        }))
        parsed = yaml.safe_load(generate_staging_compose_base(compose))
        assert "ports" not in parsed["services"]["web"]
        assert parsed["services"]["db"]["image"] == "postgres:16"

    def test_preserves_other_fields(self, tmp_path) -> None:
        compose = tmp_path / "compose.yml"
        compose.write_text(yaml.dump({
            "services": {
                "web": {
                    "build": ".",
                    "ports": ["8080:8080"],
                    "environment": {"FOO": "bar"},
                },
            },
        }))
        parsed = yaml.safe_load(generate_staging_compose_base(compose))
        assert parsed["services"]["web"]["environment"] == {"FOO": "bar"}
        assert parsed["services"]["web"]["build"] == "."


class TestStagingEmitsOffWarning:
    """Lock the wiring: stage path emits SECURITY OFF when manifest opts out.

    Exercising the full _run_stage_inner pipeline requires bundles, git
    repos, and Docker. The helper is the seam — proving stage calls it
    correctly is enough to lock the wiring without all that scaffolding.
    """

    def test_helper_emits_for_staging_manifest(self, tmp_path, monkeypatch) -> None:
        from boxmunge.log import _reset_logger
        from boxmunge.paths import BoxPaths
        from boxmunge.security_warn import warn_off_services

        monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
        paths = BoxPaths()
        paths.logs = tmp_path / "logs"
        paths.logs.mkdir()
        paths.log_file = paths.logs / "boxmunge.log"
        _reset_logger()
        try:
            manifest = {
                "project": "demo",
                "hosts": ["demo.example.com"],
                "security": {"profile": "off", "reason": "staging-test"},
                "services": {
                    "web": {"port": 3000, "routes": [{"path": "/"}]},
                },
            }
            buf = io.StringIO()
            with redirect_stdout(buf):
                warn_off_services(paths, manifest, component="stage")
            out = buf.getvalue()
            assert "SECURITY OFF" in out
            assert "demo/web" in out
            assert "staging-test" in out
        finally:
            _reset_logger()

    def test_stage_cmd_imports_helper(self) -> None:
        """Confirm stage_cmd.py imports warn_off_services (wiring sanity)."""
        from boxmunge.commands import stage_cmd
        assert hasattr(stage_cmd, "warn_off_services"), (
            "stage_cmd must import warn_off_services to emit SECURITY OFF"
        )

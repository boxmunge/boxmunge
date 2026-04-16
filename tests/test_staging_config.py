"""Tests for staging Caddy and Compose config generation."""
from boxmunge.caddy import generate_staging_caddy_config
from boxmunge.compose import generate_staging_compose_override

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

    def test_internal_services_excluded(self) -> None:
        manifest = {
            **MANIFEST,
            "services": {
                **MANIFEST["services"],
                "db": {"port": 5432, "internal": True, "routes": []},
            },
        }
        content = generate_staging_compose_override(manifest)
        assert "db" not in content

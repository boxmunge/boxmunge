"""Tests for staging Caddy and Compose config generation."""
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

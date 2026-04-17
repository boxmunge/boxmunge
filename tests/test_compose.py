"""Tests for boxmunge.compose — compose overlay generation."""

import pytest
import yaml

from boxmunge.compose import generate_compose_override, generate_staging_compose_override


FULL_MANIFEST = {
    "project": "myapp",
    "hosts": ["myapp.example.com"],
    "services": {
        "frontend": {
            "type": "frontend",
            "port": 3000,
            "routes": [{"path": "/"}],
        },
        "backend": {
            "type": "backend",
            "port": 8000,
            "internal": True,
            "routes": [{"path": "/api/*"}],
        },
        "db": {
            "type": "database",
            "port": 5432,
            "internal": True,
            "routes": [],
        },
    },
}


class TestGenerateComposeOverride:
    def test_routable_services_get_proxy_network(self) -> None:
        override = generate_compose_override(FULL_MANIFEST)
        parsed = yaml.safe_load(override)
        assert "frontend" in parsed["services"]
        networks = parsed["services"]["frontend"]["networks"]
        assert "boxmunge-proxy" in networks

    def test_internal_services_excluded(self) -> None:
        override = generate_compose_override(FULL_MANIFEST)
        parsed = yaml.safe_load(override)
        assert "db" not in parsed["services"]

    def test_backend_with_routes_gets_proxy_network(self) -> None:
        override = generate_compose_override(FULL_MANIFEST)
        parsed = yaml.safe_load(override)
        assert "backend" in parsed["services"]
        aliases = parsed["services"]["backend"]["networks"]["boxmunge-proxy"]["aliases"]
        assert "myapp-backend" in aliases

    def test_routable_services_keep_default_network(self) -> None:
        """Routable services must stay on default network for inter-service DNS."""
        override = generate_compose_override(FULL_MANIFEST)
        parsed = yaml.safe_load(override)
        networks = parsed["services"]["frontend"]["networks"]
        assert "default" in networks
        assert "boxmunge-proxy" in networks

    def test_aliases_are_project_scoped(self) -> None:
        override = generate_compose_override(FULL_MANIFEST)
        parsed = yaml.safe_load(override)
        aliases = parsed["services"]["frontend"]["networks"]["boxmunge-proxy"]["aliases"]
        assert aliases == ["myapp-frontend"]

    def test_declares_external_network(self) -> None:
        override = generate_compose_override(FULL_MANIFEST)
        parsed = yaml.safe_load(override)
        assert parsed["networks"]["boxmunge-proxy"]["external"] is True


class TestComposeEnvFiles:
    def test_includes_env_files_in_order(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest, env_files={
            "host_secrets": "/opt/boxmunge/config/secrets.env",
            "project_env": "./project.env",
            "project_secrets": "./secrets.env",
        })
        parsed = yaml.safe_load(content)
        env_list = parsed["services"]["web"]["env_file"]
        assert env_list[0] == "/opt/boxmunge/config/secrets.env"
        assert env_list[1] == "./project.env"
        assert env_list[2] == "./secrets.env"

    def test_omits_missing_env_files(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest, env_files={
            "host_secrets": "/opt/boxmunge/config/secrets.env",
        })
        parsed = yaml.safe_load(content)
        assert len(parsed["services"]["web"]["env_file"]) == 1

    def test_no_env_files_by_default(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert "env_file" not in parsed["services"]["web"]


class TestComposeResourceLimits:
    def test_includes_limits(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "limits": {"memory": "512m", "cpus": "0.5"},
            }},
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        limits = parsed["services"]["web"]["deploy"]["resources"]["limits"]
        assert limits["memory"] == "512m"
        assert limits["cpus"] == "0.5"

    def test_no_limits_by_default(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert "deploy" not in parsed["services"]["web"]

    def test_limits_on_some_services(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}], "limits": {"memory": "256m"}},
                "api": {"port": 9000, "routes": [{"path": "/api/*"}]},
            },
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert "deploy" in parsed["services"]["web"]
        assert "deploy" not in parsed["services"]["api"]


class TestNonRoutableServices:
    def test_worker_gets_env_files(self) -> None:
        """Non-routable services (workers, databases) still need secrets."""
        manifest = {
            "project": "myapp",
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}]},
                "worker": {"port": 9000, "internal": True, "routes": []},
            },
        }
        content = generate_compose_override(manifest, env_files={
            "host_secrets": "/opt/boxmunge/config/secrets.env",
        })
        parsed = yaml.safe_load(content)
        # Worker should get env_files even without routes
        assert "worker" in parsed["services"]
        assert parsed["services"]["worker"]["env_file"] == [
            "/opt/boxmunge/config/secrets.env"
        ]
        # Worker should NOT have network aliases
        assert "networks" not in parsed["services"]["worker"]

    def test_worker_gets_limits(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}]},
                "worker": {"port": 9000, "routes": [], "limits": {"memory": "256m"}},
            },
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert "worker" in parsed["services"]
        assert parsed["services"]["worker"]["deploy"]["resources"]["limits"]["memory"] == "256m"


class TestSmokeScriptMount:
    def test_smoke_service_gets_volume_mount(self) -> None:
        """A service with smoke gets boxmunge-scripts mounted."""
        manifest = {
            "project": "myapp",
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "smoke": "boxmunge-scripts/smoke.sh",
            }},
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert "./boxmunge-scripts:/boxmunge-scripts:ro" in parsed["services"]["web"]["volumes"]

    def test_only_smoke_services_get_mount(self) -> None:
        """Only services with smoke get the volume mount."""
        manifest = {
            "project": "myapp",
            "services": {
                "web": {
                    "port": 8080, "routes": [{"path": "/"}],
                    "smoke": "boxmunge-scripts/smoke.sh",
                },
                "worker": {"port": 9000, "routes": [{"path": "/work"}]},
            },
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert "volumes" in parsed["services"]["web"]
        assert "volumes" not in parsed["services"]["worker"]

    def test_multiple_smoke_services(self) -> None:
        """Multiple services can each have their own smoke test."""
        manifest = {
            "project": "myapp",
            "services": {
                "web": {
                    "port": 8080, "routes": [{"path": "/"}],
                    "smoke": "boxmunge-scripts/smoke-web.sh",
                },
                "api": {
                    "port": 9000, "routes": [{"path": "/api/*"}],
                    "smoke": "boxmunge-scripts/smoke-api.sh",
                },
            },
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert "volumes" in parsed["services"]["web"]
        assert "volumes" in parsed["services"]["api"]

    def test_no_smoke_no_mount(self) -> None:
        """Services without smoke get no volume mount."""
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert "volumes" not in parsed["services"]["web"]


class TestStagingOverrideEnvAndLimits:
    def test_staging_includes_env_files(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_staging_compose_override(manifest, env_files={
            "project_secrets": "./secrets.env",
        })
        parsed = yaml.safe_load(content)
        assert parsed["services"]["web"]["env_file"] == ["./secrets.env"]

    def test_staging_includes_limits(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "limits": {"memory": "512m"},
            }},
        }
        content = generate_staging_compose_override(manifest)
        parsed = yaml.safe_load(content)
        assert parsed["services"]["web"]["deploy"]["resources"]["limits"]["memory"] == "512m"

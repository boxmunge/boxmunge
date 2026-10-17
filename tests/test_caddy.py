"""Tests for boxmunge.caddy — Caddy config generation from manifests."""


from boxmunge.caddy import generate_caddy_config, generate_staging_caddy_config


SIMPLE_MANIFEST = {
    "project": "myapp",
    "hosts": ["myapp.example.com"],
    "services": {
        "frontend": {
            "type": "frontend",
            "port": 3000,
            "routes": [{"path": "/"}],
        },
    },
}

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
    },
}

MULTI_HOST = {
    "project": "multi",
    "hosts": ["multi.example.com", "www.multi.example.com"],
    "services": {
        "web": {
            "type": "frontend",
            "port": 8080,
            "routes": [{"path": "/"}],
        },
    },
}


class TestGenerateCaddyConfig:
    def test_simple_frontend(self) -> None:
        config = generate_caddy_config(SIMPLE_MANIFEST)
        assert "myapp.example.com" in config
        assert "reverse_proxy myapp-frontend:3000" in config

    def test_frontend_backend_routes(self) -> None:
        config = generate_caddy_config(FULL_MANIFEST)
        assert "handle /api/*" in config
        assert "reverse_proxy myapp-backend:8000" in config
        api_pos = config.index("/api/*")
        root_pos = config.index("handle {")
        assert api_pos < root_pos

    def test_multi_host(self) -> None:
        config = generate_caddy_config(MULTI_HOST)
        assert "multi.example.com" in config
        assert "www.multi.example.com" in config

    def test_internal_services_still_get_routes(self) -> None:
        config = generate_caddy_config(FULL_MANIFEST)
        assert "myapp-backend:8000" in config

    def test_access_log_goes_to_stdout_as_json(self) -> None:
        # CrowdSec reads Caddy's stdout through the Docker API; without the
        # directive there is no HTTP-layer detection on the proxy.
        config = generate_caddy_config(SIMPLE_MANIFEST)
        assert "    log {\n        output stdout\n        format json\n    }\n" in config

    def test_access_log_is_never_a_file(self) -> None:
        # A file would live in a directory the remapped Caddy controls, and
        # root CrowdSec would open whatever Caddy put there.
        assert "output file" not in generate_caddy_config(SIMPLE_MANIFEST)
        assert "/var/log/caddy" not in generate_caddy_config(SIMPLE_MANIFEST)


class TestStagingCaddyConfig:
    def test_no_auth_by_default(self) -> None:
        config = generate_staging_caddy_config(SIMPLE_MANIFEST)
        assert "basicauth" not in config
        assert "staging.myapp.example.com" in config

    def test_access_log_goes_to_stdout_as_json(self) -> None:
        config = generate_staging_caddy_config(SIMPLE_MANIFEST)
        assert "    log {\n        output stdout\n        format json\n    }\n" in config
        assert "output file" not in config

    def test_auth_injected_when_provided(self) -> None:
        config = generate_staging_caddy_config(
            SIMPLE_MANIFEST,
            auth=("alice", "$2b$12$hashedpasswordhere"),
        )
        assert "basicauth" in config
        assert "alice" in config
        assert "$2b$12$hashedpasswordhere" in config

    def test_auth_wraps_all_routes(self) -> None:
        manifest = {
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
                    "routes": [{"path": "/api/*"}],
                },
            },
        }
        config = generate_staging_caddy_config(manifest, auth=("bob", "$2b$12$hash"))
        assert "basicauth" in config
        # Auth block should appear before route handles
        auth_pos = config.index("basicauth")
        api_pos = config.index("/api/*")
        root_pos = config.index("reverse_proxy myapp-staging-frontend:3000")
        assert auth_pos < api_pos
        assert auth_pos < root_pos

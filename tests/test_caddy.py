"""Tests for boxmunge.caddy — Caddy config generation from manifests."""

import pytest

from boxmunge.caddy import generate_caddy_config


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

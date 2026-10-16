"""Route paths are exact matches in Caddy unless they end in `*` (issue #7).

A route written as a directory, `/api/`, reaches only the literal path
`/api/`; `/api/health` falls through to the `/` route. Validation warns, and
the documented examples use the wildcard form.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from boxmunge.manifest import validate_manifest

CONVENTIONS = Path(__file__).resolve().parents[1] / "docs" / "on-server" / "PROJECT_CONVENTIONS.md"


def _manifest(path: str) -> dict:
    return {
        "schema_version": 3, "id": "01KN107SD5WQTA9DC8EXKFF2NP",
        "project": "myapp", "source": "bundle", "hosts": ["myapp.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": path}],
                             "limits": {"memory": "256m"},
                             "smoke": "boxmunge-scripts/smoke.sh"}},
        "backup": {"type": "none"},
    }


def _route_warnings(path: str) -> list[str]:
    errors, warnings = validate_manifest(_manifest(path), "myapp")
    assert errors == []
    return [w for w in warnings if "route" in w]


@pytest.mark.parametrize("path", ["/api/", "/admin/", "/static/v1/"])
def test_directory_style_route_warns(path: str) -> None:
    warnings = _route_warnings(path)
    assert len(warnings) == 1, warnings
    assert "exact" in warnings[0] and f"{path}*" in warnings[0]


@pytest.mark.parametrize("path", ["/", "/api/*", "/api*", "/legacy", "/healthz"])
def test_wildcard_root_and_single_paths_do_not_warn(path: str) -> None:
    assert _route_warnings(path) == []


def test_documented_route_paths_do_not_warn() -> None:
    text = CONVENTIONS.read_text()
    paths = re.findall(r"path: (/[^\s}\]]*)", text)
    assert "/api/*" in paths, "the multi-service example routes a subtree"
    for path in paths:
        assert _route_warnings(path) == [], f"PROJECT_CONVENTIONS.md documents {path!r}"

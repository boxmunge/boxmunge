"""End-to-end Caddy maintenance-page tests.

Closes the v0.4.0 → v0.4.1 hotfix gap: the bundle bug (caddy/ missing) was
not caught until the live site was curl'd after deploying. These tests run
real Caddy with our config + maintenance HTML and assert the wire-level
behavior we promise: HTTP 503 with the expected body and Retry-After header.

Requires Docker.
"""

from __future__ import annotations

import socket
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path

import pytest

from boxmunge.pause import render_maintenance_caddy_config

from tests.integration.conftest import skip_no_docker


pytestmark = [pytest.mark.integration, skip_no_docker]


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MAINTENANCE_DIR = REPO_ROOT / "caddy" / "maintenance"


def _free_port() -> int:
    """Bind to port 0 and return the kernel-assigned high port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_test_caddyfile(port: int, host: str) -> str:
    """Wrap render_maintenance_caddy_config output for HTTP-only test serving.

    Production uses host-matching with auto-HTTPS. For tests we override the
    site address to bind explicitly to http://:PORT and disable auto-HTTPS.
    The maintenance fragment is included verbatim apart from the address.
    """
    fragment = render_maintenance_caddy_config([host])
    # Replace the host-block address with a port-bound HTTP address, keeping
    # the inner handle/header/file_server contents intact.
    rewritten = fragment.replace(f"{host} {{", f":{port} {{", 1)
    return (
        "{\n"
        "  auto_https off\n"
        "  admin off\n"
        "}\n"
        + rewritten
    )


@pytest.fixture
def caddy_container(tmp_path: Path):
    """Boot a Caddy container with our maintenance config; tear down after."""
    port = _free_port()
    host = "test.maintenance.local"

    config_dir = tmp_path / "caddy"
    config_dir.mkdir()
    (config_dir / "Caddyfile").write_text(_build_test_caddyfile(port, host))

    # Use the actual repo maintenance dir so a regression in the HTML or any
    # stylesheet would surface in this test.
    container_name = f"boxmunge-test-caddy-{port}"
    proc = subprocess.run(
        [
            "docker", "run", "-d", "--rm",
            "--name", container_name,
            "-p", f"127.0.0.1:{port}:{port}",
            "-v", f"{config_dir / 'Caddyfile'}:/etc/caddy/Caddyfile:ro",
            "-v", f"{MAINTENANCE_DIR}:/etc/caddy/maintenance:ro",
            "caddy:2-alpine",
        ],
        capture_output=True, text=True, check=False, timeout=30,
    )
    if proc.returncode != 0:
        pytest.fail(f"docker run failed: {proc.stderr}")

    # Wait for Caddy to start serving — poll the port up to ~10 s
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            break
        except urllib.error.HTTPError:
            # 503 also means Caddy is up — we expect it
            break
        except (urllib.error.URLError, ConnectionResetError):
            time.sleep(0.2)
    else:
        logs = subprocess.run(
            ["docker", "logs", container_name],
            capture_output=True, text=True, timeout=5,
        )
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        pytest.fail(f"Caddy did not start within 10s. Logs:\n{logs.stdout}\n{logs.stderr}")

    try:
        yield port, host, container_name
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=10)


class TestCaddyMaintenancePage:
    def test_returns_503(self, caddy_container):
        """Production promise: paused projects return HTTP 503."""
        port, host, _ = caddy_container
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
        except urllib.error.HTTPError as e:
            assert e.code == 503, f"expected 503, got {e.code}"
            return
        pytest.fail("expected HTTP 503 but request succeeded")

    def test_includes_retry_after_header(self, caddy_container):
        """Retry-After hints to operators / monitors that this is intentional."""
        port, _, _ = caddy_container
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
        except urllib.error.HTTPError as e:
            assert e.headers.get("Retry-After") == "3600", (
                f"expected Retry-After: 3600, got {e.headers.get('Retry-After')!r}"
            )

    def test_serves_maintenance_html_body(self, caddy_container):
        """v0.4.1 hotfix regression: the actual maintenance/index.html must be served."""
        port, _, _ = caddy_container
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            # Body should look like a real maintenance page, not Caddy's
            # default 404/error template.
            assert "<!DOCTYPE html>" in body, "body is not the maintenance HTML"
            assert "maintenance" in body.lower(), (
                "body missing 'maintenance' keyword"
            )

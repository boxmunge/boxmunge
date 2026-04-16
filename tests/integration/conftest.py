"""Integration test fixtures — real Docker, real file I/O, temporary boxmunge root."""

import os
import random
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from boxmunge.paths import BoxPaths


def _docker_available() -> bool:
    """Check if Docker daemon is reachable."""
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10, check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


skip_no_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available"
)


def _random_port() -> int:
    """Pick a random high port for test services."""
    return random.randint(19000, 29999)


@pytest.fixture(scope="session")
def integration_root(tmp_path_factory) -> Path:
    """Create a temporary boxmunge root for integration tests."""
    root = tmp_path_factory.mktemp("boxmunge-int")
    for subdir in [
        "bin", "config", "caddy/sites", "projects", "state/health",
        "state/deploy", "state/staging", "docs", "logs",
        "inbox/.tmp", "inbox/.consumed", "system",
    ]:
        (root / subdir).mkdir(parents=True)

    # Generate a test age key
    try:
        result = subprocess.run(
            ["age-keygen"], capture_output=True, text=True, check=True, timeout=10,
        )
        (root / "config" / "backup.key").write_text(result.stdout)
        (root / "config" / "backup.key").chmod(0o600)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("age-keygen not available")

    # Write minimal config
    (root / "config" / "boxmunge.yml").write_text(
        "hostname: integration-test.localhost\n"
        "admin_email: test@test.com\n"
    )

    yield root


@pytest.fixture
def int_paths(integration_root: Path) -> BoxPaths:
    """BoxPaths pointing at the integration test root."""
    return BoxPaths(root=integration_root)


@pytest.fixture
def test_port() -> int:
    """Random high port for this test."""
    return _random_port()


@pytest.fixture
def fixture_project_dir() -> Path:
    """Path to the integration test fixture project."""
    return Path(__file__).parent / "fixture_project"


@pytest.fixture
def deployed_fixture(int_paths: BoxPaths, fixture_project_dir: Path, test_port: int):
    """Deploy the fixture project and yield (paths, project_name, port).

    Tears down containers after the test.
    """
    project_name = "inttest"
    compose_project = project_name  # Must match what boxmunge uses for -p
    project_dir = int_paths.project_dir(project_name)

    # Copy fixture into project dir
    if project_dir.exists():
        shutil.rmtree(project_dir)
    shutil.copytree(fixture_project_dir, project_dir)

    # Write test port — both as project.env and .env (Docker Compose reads .env automatically)
    (project_dir / "project.env").write_text(f"TEST_PORT={test_port}\n")
    (project_dir / ".env").write_text(f"TEST_PORT={test_port}\n")

    try:
        # Build and start containers
        subprocess.run(
            ["docker", "compose", "-f", "compose.yml",
             "-p", compose_project,
             "up", "-d", "--build"],
            cwd=project_dir, check=True, capture_output=True, text=True,
            timeout=120,
            env={**os.environ, "TEST_PORT": str(test_port)},
        )

        # Wait for healthcheck
        for _ in range(30):
            try:
                import urllib.request
                urllib.request.urlopen(
                    f"http://localhost:{test_port}/healthz", timeout=2,
                )
                break
            except Exception:
                time.sleep(1)
        else:
            # Dump logs for debugging
            logs = subprocess.run(
                ["docker", "compose", "-f", "compose.yml",
                 "-p", compose_project, "logs"],
                cwd=project_dir, capture_output=True, text=True, timeout=10,
            )
            pytest.fail(
                f"Fixture project did not become healthy within 30s.\n"
                f"Logs:\n{logs.stdout}\n{logs.stderr}"
            )

        yield int_paths, project_name, test_port, compose_project

    finally:
        # Tear down containers and volumes
        subprocess.run(
            ["docker", "compose", "-f", "compose.yml",
             "-p", compose_project,
             "down", "-v", "--remove-orphans"],
            cwd=project_dir, check=False, capture_output=True,
            timeout=60,
        )

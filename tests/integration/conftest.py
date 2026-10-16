"""Integration test fixtures — real Docker, real file I/O, temporary boxmunge root."""

import os
import random
import shutil
import uuid
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


# CI sets BOXMUNGE_REQUIRE_INTEGRATION=1 so a missing prerequisite fails the
# run instead of silently skipping every test and reporting green.
REQUIRE_INTEGRATION = os.environ.get("BOXMUNGE_REQUIRE_INTEGRATION") == "1"

if REQUIRE_INTEGRATION and not _docker_available():
    raise RuntimeError(
        "BOXMUNGE_REQUIRE_INTEGRATION=1 but the Docker daemon is not reachable"
    )

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
        if REQUIRE_INTEGRATION:
            pytest.fail("BOXMUNGE_REQUIRE_INTEGRATION=1 but age-keygen is not available")
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

    Tears down its containers, volumes and built image after the test.
    """
    # A name of its own per run: concurrent runs on one Docker daemon would
    # otherwise share (and tear down) one another's containers and network.
    project_name = f"inttest{uuid.uuid4().hex[:8]}"
    compose_project = project_name  # Must match what boxmunge uses for -p
    project_dir = int_paths.project_dir(project_name)

    # Copy fixture into project dir, renamed to this run's project
    if project_dir.exists():
        shutil.rmtree(project_dir)
    shutil.copytree(fixture_project_dir, project_dir)
    manifest = project_dir / "manifest.yml"
    manifest.write_text(manifest.read_text().replace("inttest", project_name))

    # Write test port — both as project.env and .env (Docker Compose reads .env automatically)
    (project_dir / "project.env").write_text(f"TEST_PORT={test_port}\n")
    (project_dir / ".env").write_text(f"TEST_PORT={test_port}\n")
    # Stands in for the generated overlay, which publishes a manifest's
    # security.published_ports on 127.0.0.1; compose.yml itself may not.
    (project_dir / "compose.boxmunge.yml").write_text(
        f"services:\n  web:\n    ports: [\"127.0.0.1:{test_port}:8080\"]\n")
    from tests.deploy_helpers import mark_deployed
    mark_deployed(int_paths, project_name)

    try:
        # Build and start containers
        subprocess.run(
            ["docker", "compose", "-f", "compose.yml", "-f", "compose.boxmunge.yml",
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
        # Tear down containers, volumes and the web image `up --build` made:
        # each run's image is tagged for its own name, so they pile up.
        subprocess.run(
            ["docker", "compose", "-f", "compose.yml",
             "-p", compose_project,
             "down", "-v", "--rmi", "local", "--remove-orphans"],
            cwd=project_dir, check=False, capture_output=True,
            timeout=60,
        )


# ---------------------------------------------------------------------------
# The real boxmunge-system container (age, rclone), built from system/.
# ---------------------------------------------------------------------------

_REPO = Path(__file__).resolve().parents[2]


def _system_compose(project: str, override: Path) -> list[str]:
    return ["docker", "compose", "-p", project,
            "-f", str(_REPO / "system" / "compose.yml"), "-f", str(override)]


@pytest.fixture(scope="session")
def real_system_container(integration_root: Path, tmp_path_factory):
    """Build system/Dockerfile and start it from system/compose.yml.

    Mounts point at the integration root (the compose file's BOXMUNGE_CONFIG
    and BOXMUNGE_PROJECTS variables). Only the container name is overridden,
    so a developer's real boxmunge-system is never touched. Yields the name;
    tests use ``system_container`` to point the module at it.
    """
    import uuid

    if not _docker_available():
        pytest.skip("Docker not available")
    paths = BoxPaths(root=integration_root)
    paths.rclone_config_dir.mkdir(exist_ok=True)
    paths.rclone_config.touch()
    name = f"bmsys-it-{uuid.uuid4().hex[:10]}"
    override = tmp_path_factory.mktemp("system-compose") / "override.yml"
    override.write_text(
        "services:\n"
        "  system:\n"
        f"    container_name: {name}\n"
    )
    # The same variables install.sh writes to system/.env on a real box.
    owner = paths.projects.stat()
    env = {**os.environ,
           "BOXMUNGE_UID": str(owner.st_uid),
           "BOXMUNGE_GID": str(owner.st_gid),
           "BOXMUNGE_CONFIG": str(paths.config),
           "BOXMUNGE_PROJECTS": str(paths.projects)}
    cmd = _system_compose(name, override)
    try:
        up = subprocess.run(cmd + ["up", "-d", "--build", "--wait"], env=env,
                            capture_output=True, text=True, timeout=900, check=False)
        if up.returncode != 0:
            pytest.fail(f"system container failed to start:\n{up.stdout}\n{up.stderr}")
        yield name
    finally:
        subprocess.run(cmd + ["down", "--volumes", "--rmi", "local"], env=env,
                       capture_output=True, timeout=120, check=False)


@pytest.fixture
def system_container(real_system_container: str, monkeypatch) -> str:
    """Point system_container.CONTAINER_NAME at the session's container for
    one test only. A session-wide patch outlived the integration tests and
    sent later unit tests to the wrong container name."""
    import boxmunge.system_container as sc

    monkeypatch.setattr(sc, "CONTAINER_NAME", real_system_container)
    return real_system_container

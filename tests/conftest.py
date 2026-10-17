"""Shared test fixtures for boxmunge tests."""

import logging

import pytest
from pathlib import Path

from boxmunge.paths import BoxPaths

# Provides the `system_container` fixture (a fake boxmunge-system container),
# and refuses real docker spawns outside the integration tier.
pytest_plugins = ["tests.fake_system_container", "tests.real_docker_guard"]


@pytest.fixture(autouse=True)
def _reset_boxmunge_logger():
    """Reset the cached "boxmunge" logger between tests.

    `boxmunge.log.get_logger` caches its logger (and its rotating file
    handler) in a module global and sets propagate=False. A test that logs
    through a handler rooted at its own tmp_path leaves that handler attached
    after the tmp_path is torn down; a later test that logs on the "boxmunge"
    logger then writes to a dead stream (a "Logging error"), and because
    propagate stays False, caplog captures nothing.

    On teardown we detach the factory-owned handlers, restore propagation,
    and drop the module cache so the next test starts from a pristine logger.
    `get_logger` now leaves foreign handlers (a test's own capture handler)
    in place, so a cold rebuild no longer wipes them.
    """
    yield
    import boxmunge.log as _log

    logger = logging.getLogger("boxmunge")
    for handler in list(logger.handlers):
        if isinstance(handler, logging.StreamHandler):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass
    logger.propagate = True
    _log._logger = None


@pytest.fixture(autouse=True)
def _no_writable_diagnostic_sleep(monkeypatch):
    """Skip the 8s post-deploy diagnostic sleep in unit tests.

    Tests that explicitly pass `sleep_fn=...` to
    `run_post_deploy_diagnostics` get their own injection; everything
    else (including the deploy-command integration tests) takes the
    no-op path via this module-level indirection.
    """
    monkeypatch.setattr(
        "boxmunge.writable_diagnostics._sleep_fn",
        lambda _: None,
    )


@pytest.fixture(autouse=True)
def _no_writable_diagnostic_logs(request, monkeypatch):
    """Outside the integration tier the writable diagnostics' default log
    fetch (after a deploy, on a smoke failure) finds no logs, as on a box
    without Docker; tests that need logs pass `log_fetcher=...`."""
    if request.node.get_closest_marker("integration"):
        return
    monkeypatch.setattr("boxmunge.writable_diagnostics._compose_logs",
                        lambda project_dir, service, tail, project: "")


class FakeContainers:
    """Stands in for `docker_containers.project_containers`.

    A project the test gave containers with ``run`` (or emptied with
    ``remove``) has exactly those. Any other project is running as its
    compose file says: one container per `image:` service of the model
    `docker compose config` last resolved for it, and the fake names each
    image by that compose reference, so tests see the refs they declared.
    A build-only service has no container unless a test runs one.

    ``local_image`` stands in for `docker_containers.local_image` the same
    way: a ref set in ``images`` (to a LocalImage, or None for absent) is
    that; any other ref is present when it is the `image:` of a service in
    a resolved model, again named by that reference.
    """

    def __init__(self) -> None:
        self.by_project: dict[str, list] = {}
        self.models: dict[str, dict] = {}
        self.images: dict[str, object] = {}

    def run(self, project: str, service: str, image_id: str, *,
            repo_digests: tuple[str, ...] = (), name: str | None = None,
            running: bool = True, health: str | None = None, oneoff: bool = False,
            exit_code: int | None = None, restart_policy: str = "unless-stopped"):
        from boxmunge.docker_containers import ProjectContainer

        existing = self.by_project.setdefault(project, [])
        replica = 1 + sum(1 for c in existing if c.service == service)
        container = ProjectContainer(
            name=name or f"{project}-{service}-{replica}",
            service=service, image_id=image_id, repo_digests=tuple(repo_digests),
            running=running, health=health, oneoff=oneoff,
            # A stopped container failed unless the test says otherwise.
            exit_code=None if running else (1 if exit_code is None else exit_code),
            restart_policy=restart_policy,
        )
        existing.append(container)
        return container

    def remove(self, project: str) -> None:
        """The project has no containers at all."""
        self.by_project[project] = []

    @staticmethod
    def _declared_id(ref: str) -> str:
        import hashlib
        return "sha256:" + hashlib.sha256(ref.encode()).hexdigest()

    def _as_declared(self, project: str) -> list:
        from boxmunge.docker_containers import ProjectContainer

        services = (self.models.get(project) or {}).get("services") or {}
        return [
            ProjectContainer(
                name=f"{project}-{svc}-1", service=svc,
                image_id=self._declared_id(spec["image"]),
                repo_digests=(spec["image"],), running=True, health=None, oneoff=False,
                exit_code=None, restart_policy="unless-stopped",
            )
            for svc, spec in services.items()
            if isinstance(spec, dict) and isinstance(spec.get("image"), str)
        ]

    def local_image(self, ref: str):
        from boxmunge.docker_containers import LocalImage

        if ref in self.images:
            return self.images[ref]
        declared = {
            spec.get("image") for model in self.models.values()
            for spec in ((model or {}).get("services") or {}).values()
            if isinstance(spec, dict)
        }
        if ref in declared:
            return LocalImage(image_id=self._declared_id(ref), repo_digests=(ref,))
        return None

    def __call__(self, project_name: str) -> list:
        if project_name in self.by_project:
            return list(self.by_project[project_name])
        return self._as_declared(project_name)


@pytest.fixture(autouse=True)
def fake_containers(request, monkeypatch) -> FakeContainers:
    """Keep container discovery and restart-policy holds off the real Docker
    daemon outside the integration tier."""
    # Quarantine and pause hold restart policies through boxmunge.restart_hold;
    # by default the project has no containers to hold.
    monkeypatch.setattr("boxmunge.restart_hold.project_restart_policies",
        lambda *, project_name: {})
    monkeypatch.setattr("boxmunge.restart_hold.set_restart_policy", lambda n, p: None)
    fake = FakeContainers()
    if not request.node.get_closest_marker("integration"):
        monkeypatch.setattr("boxmunge.docker_containers.project_containers", fake)
        monkeypatch.setattr("boxmunge.docker_containers.local_image", fake.local_image)
        # The start guard inspects a project's existing container bind mounts;
        # off the integration tier there are none unless a test says otherwise.
        monkeypatch.setattr("boxmunge.docker_containers.container_bind_sources",
                            lambda project_name: [])
        monkeypatch.setattr("boxmunge.docker_containers.container_mounts",
                            lambda project_name: [])
        # Who a project's containers run as (deploy's user-change check).
        monkeypatch.setattr("boxmunge.docker_containers.container_users",
                            lambda project_name: {})
        # The legacy-stage evidence asks when production's containers were made.
        monkeypatch.setattr("boxmunge.docker_containers.created_times",
                            lambda project_name: {})
    return fake


@pytest.fixture(autouse=True)
def _no_built_image_removal(request, monkeypatch):
    """Overlay generation drops pre-boxmunge.invalid built-image names and
    project-delete removes a project's built images; outside the integration
    tier neither touches the Docker daemon."""
    if request.node.get_closest_marker("integration"):
        return
    monkeypatch.setattr("boxmunge.built_images.untag_old_built_names", lambda project, build_services, image_services: [])
    monkeypatch.setattr("boxmunge.commands.project_delete_cmd.remove_built_images",
                        lambda compose_project: [])


@pytest.fixture(autouse=True)
def _no_kev_network(monkeypatch):
    """Prevent any test from hitting the CISA KEV feed over the network.

    refresh_kev() makes a real HTTP request; calling it in tests would cause
    non-deterministic failures (no network in CI, slow on dev machines).
    This autouse fixture stubs it to a no-op fleet-wide and also stubs
    load_kev to return a fresh, empty catalog so tests that don't explicitly
    exercise KEV staleness don't trigger the stale-feed alert path.

    Tests that need to exercise KEV behavior can override by constructing
    a KevCatalog directly and passing it via the kev= parameter, or by
    monkeypatching load_kev after this fixture runs.
    """
    from datetime import datetime, timezone
    from boxmunge.cve.kev import KevCatalog

    _fresh_empty = KevCatalog(
        cve_ids=frozenset(),
        fetched_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        "boxmunge.cve.kev.refresh_kev", lambda paths: None,
    )
    from boxmunge.cve.kev import KevRefresh

    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_kev",
        lambda paths: KevRefresh(updated=False),
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.load_kev", lambda paths: _fresh_empty,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.load_kev", lambda paths: _fresh_empty,
    )


@pytest.fixture(autouse=True)
def _compose_config_without_docker(request, monkeypatch, fake_containers):
    """Stand in for `docker compose config` outside the integration tier.

    The compose validator and overlay generator read the resolved model
    from `docker.compose_config`, which needs the Docker CLI. Unit tests
    run without Docker, so this returns the literal compose file as JSON:
    no interpolation, no extends/include merging. That exercises every
    rule on the literal shapes; the real resolution is covered by the
    integration-marked tests, which this fixture leaves alone.
    """
    if request.node.get_closest_marker("integration"):
        return
    import json

    import yaml

    from boxmunge import docker

    def _literal_config(project_dir, compose_files=None, *, project_name,
                        all_profiles=False, project_directory=None, env_file=None):
        docker.check_compose_project_name(project_name)
        path = Path(project_dir) / (compose_files or ["compose.yml"])[0]
        try:
            doc = yaml.safe_load(path.read_text())
        except (OSError, yaml.YAMLError) as e:
            raise docker.DockerError(f"compose config failed: {e}") from e
        services = doc.get("services") if isinstance(doc, dict) else None
        # Like Compose, bring in the services of included files (one level),
        # so the resolver's literal-versus-resolved service check holds.
        includes = doc.get("include") if isinstance(doc, dict) else None
        for ref in includes if isinstance(includes, list) else []:
            inc = path.parent / (ref if isinstance(ref, str) else "")
            if isinstance(ref, str) and inc.is_file() and isinstance(services, dict):
                inc_doc = yaml.safe_load(inc.read_text()) or {}
                services.update(inc_doc.get("services") or {})
        if not all_profiles and isinstance(services, dict):
            # Like Compose, leave out services behind a profile.
            doc["services"] = {n: s for n, s in services.items()
                               if not (isinstance(s, dict) and s.get("profiles"))}
        if not all_profiles and isinstance(doc, dict):
            fake_containers.models[project_name] = doc
        return json.dumps(doc)

    monkeypatch.setattr(docker, "compose_config", _literal_config)


@pytest.fixture
def tmp_root(tmp_path: Path) -> Path:
    """Create a temporary boxmunge root directory with standard structure."""
    root = tmp_path / "boxmunge"
    for subdir in [
        "bin", "config", "caddy/sites", "projects", "state/health",
        "state/deploy", "templates/project", "docs", "logs",
        "inbox/.tmp", "inbox/.consumed",
    ]:
        (root / subdir).mkdir(parents=True)
    return root


@pytest.fixture
def paths(tmp_root: Path) -> BoxPaths:
    """BoxPaths pointing at a temporary root."""
    return BoxPaths(root=tmp_root)


@pytest.fixture(autouse=True)
def _unremapped_daemon(request, monkeypatch, tmp_path_factory):
    """Outside the integration tier the box is not remapped: an empty /etc
    and a daemon reporting no userns. tests.userns_helpers.remap_box makes
    one test's box remapped."""
    if request.node.get_closest_marker("integration"):
        return
    from tests.userns_helpers import UNREMAPPED_INFO

    monkeypatch.setattr("boxmunge.userns.offset.ETC", tmp_path_factory.mktemp("etc"))
    monkeypatch.setattr("boxmunge.userns.offset.docker_info", lambda: dict(UNREMAPPED_INFO))

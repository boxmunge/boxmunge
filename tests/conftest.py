"""Shared test fixtures for boxmunge tests."""

import logging

import pytest
from pathlib import Path

from boxmunge.paths import BoxPaths


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
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.refresh_kev", lambda paths: None,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_actions.load_kev", lambda paths: _fresh_empty,
    )
    monkeypatch.setattr(
        "boxmunge.commands.security_scan_core.load_kev", lambda paths: _fresh_empty,
    )


@pytest.fixture
def tmp_root(tmp_path: Path) -> Path:
    """Create a temporary boxmunge root directory with standard structure."""
    root = tmp_path / "boxmunge"
    for subdir in [
        "bin", "config", "caddy/sites", "projects", "state/health",
        "state/deploy", "state/staging", "templates/project", "docs", "logs",
        "inbox/.tmp", "inbox/.consumed",
    ]:
        (root / subdir).mkdir(parents=True)
    return root


@pytest.fixture
def paths(tmp_root: Path) -> BoxPaths:
    """BoxPaths pointing at a temporary root."""
    return BoxPaths(root=tmp_root)

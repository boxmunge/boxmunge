"""prepare_deploy_dirs with real ownership: root in a Debian 13 container, a
real unprivileged deploy user, and a root-owned state/scans as v0.6-v0.9.2 left it."""
from __future__ import annotations

import pytest

from tests.integration.conftest import skip_no_docker
from tests.integration.test_bootstrap_trixie import _run_on_trixie

pytestmark = [pytest.mark.integration, skip_no_docker]

_WRITE = ("from boxmunge.cve.scan_state import write_scan_state; "
          "from boxmunge.paths import BoxPaths; "
          "write_scan_state(BoxPaths().project_scan_state('demo'), decisions=())")
_PREPARE = ("from boxmunge.deploy_dirs import prepare_deploy_dirs; "
            "from boxmunge.paths import BoxPaths; "
            "r = prepare_deploy_dirs(BoxPaths()); print('done', r.done, 'failed', r.failed)")


def test_a_root_made_scans_dir_is_writable_by_deploy_after_the_migration() -> None:
    result = _run_on_trixie(
        "apt-get install -y -qq python3 python3-yaml >/dev/null\n"
        "useradd -m deploy\n"
        "mkdir -p /opt/boxmunge/state/scans /opt/boxmunge/projects/demo/security\n"
        "chown deploy:deploy /opt/boxmunge/state /opt/boxmunge/projects "
        "/opt/boxmunge/projects/demo\n"  # scans and security stay root's
        "export PYTHONPATH=/src\n"
        f"if su deploy -s /bin/sh -c \"python3 -c \\\"{_WRITE}\\\"\" 2>/dev/null; then "
        "echo UNEXPECTED_WRITE; exit 1; fi\n"
        f"python3 -c \"{_PREPARE}\"\n"
        f"su deploy -s /bin/sh -c \"python3 -c \\\"{_WRITE}\\\"\"\n"
        "stat -c '%U %n' /opt/boxmunge/state/scans /opt/boxmunge/projects/demo/security "
        "/opt/boxmunge /opt/boxmunge/state/scans/demo.json\n"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "deploy /opt/boxmunge/state/scans\n" in result.stdout
    assert "deploy /opt/boxmunge/projects/demo/security\n" in result.stdout
    assert "root /opt/boxmunge\n" in result.stdout
    assert "failed []" in result.stdout

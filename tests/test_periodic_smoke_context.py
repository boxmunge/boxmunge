"""The periodic health check tells a smoke script it is the periodic check.

Smoke results gate deploy, recover, quarantine lifts, resume and userns
bring-up. A project may want a check that only alerts (the version-check
service's failure-report alert, which anyone can trigger): it runs that
check only when BOXMUNGE_CHECK=periodic, which only check-all's tick sets,
so it can never hold up an operation.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from boxmunge.commands.check import PERIODIC_ENV, run_check
from boxmunge.commands.check_all import run_check_all
from boxmunge.paths import BoxPaths
from tests.deploy_helpers import mark_deployed

NAME = "myapp"


@pytest.fixture
def paths(tmp_path: Path, fake_containers) -> BoxPaths:
    fake_containers.run(NAME, "web", "sha256:" + "1" * 64)
    p = BoxPaths(root=tmp_path / "bm")
    for d in ["config", f"projects/{NAME}", "state/deploy", "state/health",
              "caddy/sites", "logs"]:
        (p.root / d).mkdir(parents=True, exist_ok=True)
    p.config_file.write_text("hostname: t\nadmin_email: a@b\n"
                             "pushover:\n  user_key: u\n  app_token: a\n")
    (p.project_dir(NAME) / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": NAME,
        "source": "bundle", "hosts": [f"{NAME}.test"],
        "services": {"web": {"port": 8080, "smoke": "smoke.sh",
                             "routes": [{"path": "/"}]}},
    }))
    (p.project_dir(NAME) / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    mark_deployed(p, NAME)
    return p


class _Exec:
    def __init__(self) -> None:
        self.cmds: list[list[str]] = []

    def __call__(self, cmd, **_kw):
        self.cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def test_the_periodic_tick_sets_the_context(paths):
    run = _Exec()
    with patch("boxmunge.commands.check.subprocess.run", run), \
         patch("boxmunge.notify.send_notification", MagicMock(return_value=True)):
        assert run_check_all(paths, read_only=False) == 0
    [cmd] = run.cmds
    assert cmd[:4] == ["docker", "exec", "-e", PERIODIC_ENV]
    assert cmd[-2:] == ["/boxmunge-scripts/smoke.sh", "web"]


def test_check_does_not_set_it(paths):
    """`check` (and run_check, which userns commit gates on) is not the tick."""
    run = _Exec()
    with patch("boxmunge.commands.check.subprocess.run", run):
        assert run_check(NAME, paths, verbose=False) == 0
    [cmd] = run.cmds
    assert PERIODIC_ENV not in cmd


def test_gating_smoke_runs_do_not_set_it(paths):
    """Deploy, recover, lift, resume and bring-up go through run_smoke."""
    from boxmunge.health_checks.smoke import run_smoke
    run = _Exec()
    with patch("boxmunge.commands.check.subprocess.run", run):
        assert run_smoke(NAME, paths)[0]
    [cmd] = run.cmds
    assert PERIODIC_ENV not in cmd


def test_the_variable_is_named_in_the_conventions():
    text = (Path(__file__).parent.parent / "docs" / "on-server" /
            "PROJECT_CONVENTIONS.md").read_text()
    assert PERIODIC_ENV in text

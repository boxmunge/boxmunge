"""Tests for boxmunge.commands.deploy."""

import io
from contextlib import redirect_stdout
from unittest.mock import patch


from boxmunge.commands.deploy import run_deploy
from boxmunge.compose import prepare_compose_override
from boxmunge.paths import BoxPaths


BUNDLE_MANIFEST = """\
id: 01TEST00000000000000000000
project: testapp
source: bundle
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
    smoke: boxmunge-scripts/smoke.sh
backup:
  type: none
"""


class TestDeployEnvFiles:
    @patch("boxmunge.compose_guard.compose_up")
    @patch("boxmunge.commands.deploy.caddy_reload")
    def test_compose_override_includes_env_files(self, mock_reload, mock_up, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(BUNDLE_MANIFEST)
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        (pdir / "secrets.env").write_text("SECRET=value\n")
        # A previously recorded deploy: the release already on disk.
        from boxmunge.state import write_state
        write_state(paths.project_deploy_state("testapp"), {"current_ref": "testapp-1"})
        paths.host_secrets.write_text("HOST_TOKEN=abc\n")

        run_deploy("testapp", paths)

        override = (pdir / "compose.boxmunge.yml").read_text()
        assert "secrets.env" in override


class TestComposeOverrideEmitsOffWarning:
    def test_warning_printed_when_off(self, tmp_path, monkeypatch) -> None:
        # Build a paths-like with a real project_compose_override target.
        proj = tmp_path / "projects" / "demo"
        proj.mkdir(parents=True)
        (proj / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        (proj / "project.env").write_text("X=1\n")

        # Monkey-patch BoxPaths to point at tmp_path.
        monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
        paths = BoxPaths()
        paths.host_secrets = tmp_path / "host_secrets.env"  # absent
        paths.project_compose_override = lambda name: proj / "compose.boxmunge.yml"
        paths.project_compose = lambda name: proj / "compose.yml"
        paths.project_dir = lambda name: proj
        paths.project_releases = lambda name: proj / ".releases"
        paths.project_secrets = lambda name: proj / "secrets.env"
        paths.project_bind_record = lambda name, staging=False: tmp_path / "no-record.json"
        paths.project_users_record = lambda name, staging=False: tmp_path / "no-users.json"
        # get_logger reads paths.logs; the deploy warning path logs, and
        # a pristine logger (no warm cache) triggers a cold build.
        paths.logs = tmp_path / "logs"

        manifest = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "security": {"profile": "off", "reason": "test"},
            "services": {
                "web": {"port": 3000, "routes": [{"path": "/"}]},
            },
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            prepare_compose_override(paths, manifest)
        out = buf.getvalue()
        assert "SECURITY OFF" in out
        assert "demo/web" in out
        assert "test" in out

    def test_no_warning_when_default(self, tmp_path, monkeypatch) -> None:
        proj = tmp_path / "projects" / "demo"
        proj.mkdir(parents=True)
        (proj / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
        paths = BoxPaths()
        paths.host_secrets = tmp_path / "host_secrets.env"
        paths.project_compose_override = lambda name: proj / "compose.boxmunge.yml"
        paths.project_compose = lambda name: proj / "compose.yml"
        paths.project_dir = lambda name: proj
        paths.project_releases = lambda name: proj / ".releases"
        paths.project_secrets = lambda name: proj / "secrets.env"
        paths.project_bind_record = lambda name, staging=False: tmp_path / "no-record.json"
        paths.project_users_record = lambda name, staging=False: tmp_path / "no-users.json"
        # get_logger reads paths.logs; the deploy warning path logs, and
        # a pristine logger (no warm cache) triggers a cold build.
        paths.logs = tmp_path / "logs"

        manifest = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            prepare_compose_override(paths, manifest)
        assert "SECURITY OFF" not in buf.getvalue()

    def test_component_param_threads_through(self, tmp_path, monkeypatch) -> None:
        """`component=` is forwarded to warn_off_services so upgrade/resume
        don't get misattributed as 'deploy' in the structured log."""
        proj = tmp_path / "projects" / "demo"
        proj.mkdir(parents=True)
        (proj / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
        paths = BoxPaths()
        paths.host_secrets = tmp_path / "host_secrets.env"
        paths.project_compose_override = lambda name: proj / "compose.boxmunge.yml"
        paths.project_compose = lambda name: proj / "compose.yml"
        paths.project_dir = lambda name: proj
        paths.project_releases = lambda name: proj / ".releases"
        paths.project_secrets = lambda name: proj / "secrets.env"
        paths.project_bind_record = lambda name, staging=False: tmp_path / "no-record.json"
        paths.project_users_record = lambda name, staging=False: tmp_path / "no-users.json"
        # get_logger reads paths.logs; the deploy warning path logs, and
        # a pristine logger (no warm cache) triggers a cold build.
        paths.logs = tmp_path / "logs"

        manifest = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "security": {"profile": "off", "reason": "test"},
            "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
        }

        captured: list[str] = []

        def fake_warn(p, m, *, component):
            captured.append(component)

        monkeypatch.setattr(
            "boxmunge.compose.warn_off_services", fake_warn,
        )

        # Default
        prepare_compose_override(paths, manifest)
        # Explicit override (mirrors upgrade_cmd / resume_cmd call sites)
        prepare_compose_override(paths, manifest, component="upgrade")
        prepare_compose_override(paths, manifest, component="resume")

        assert captured == ["deploy", "upgrade", "resume"]

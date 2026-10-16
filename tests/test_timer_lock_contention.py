"""Timer lock contention is a skip, and slow network work leaves the lock (C-16, C-17)."""
from __future__ import annotations

import json
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from boxmunge.fileutil import project_lock
from boxmunge.paths import BoxPaths
from tests.lock_holder import hold_project_lock, project_lock_is_held


def _paths(tmp_path: Path) -> BoxPaths:
    p = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "caddy/sites", "state/deploy", "state/health", "logs"]:
        (p.root / d).mkdir(parents=True, exist_ok=True)
    p.upgrade_state.mkdir(parents=True)
    (p.caddy / "compose.yml").write_text(
        "services:\n  caddy:\n    image: caddy:2-alpine\n    container_name: boxmunge-caddy\n"
    )
    p.config_file.write_text(
        "hostname: t\nadmin_email: t@t\n"
        "pushover:\n  user_key: u\n  app_token: a\n"
    )
    return p


def _project(paths: BoxPaths, name: str) -> None:
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": name,
        "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.25\n")


# ---------------------------------------------------------------------------
# container-update: a held project lock is a logged skip, retried once
# ---------------------------------------------------------------------------

class TestContainerUpdateContention:
    def _run(self, paths, on_pull=None):
        import boxmunge.container_update as cu
        from boxmunge.commands.container_update_cmd import run_container_update
        pulls: list[str] = []

        def fake_pull(project_dir, **_kw):
            pulls.append(project_dir.name)
            if on_pull:
                on_pull(project_dir.name)

        alert = MagicMock()
        with patch.object(cu, "compose_pull", fake_pull), \
             patch.object(cu, "compose_up"), \
             patch.object(cu, "detect_image_changes", return_value={}), \
             patch("boxmunge.commands.container_update_cmd._send_summary_alert", alert):
            rc = run_container_update(paths)
        return rc, pulls, alert

    def test_held_lock_is_a_skip_not_a_failure(self, tmp_path, capsys):
        from boxmunge.container_update_targets import read_target_state
        paths = _paths(tmp_path)
        _project(paths, "app")
        with hold_project_lock("app", paths):
            rc, pulls, alert = self._run(paths)
        assert rc == 0, "contention must not fail the timer run"
        assert "app" not in pulls
        alert.assert_not_called()
        out = capsys.readouterr().out
        assert "skipped" in out.lower() and "app" in out
        # Nothing recorded for the skipped project: staleness stays visible
        # to the container-updates health check if it keeps being skipped.
        assert read_target_state(paths, "app") is None
        entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
        skips = [e for e in entries if e.get("project") == "app" and "lock" in e["msg"]]
        assert skips and all(e["level"] == "warn" for e in skips)

    def test_locked_project_is_retried_after_the_others(self, tmp_path):
        paths = _paths(tmp_path)
        _project(paths, "app")
        _project(paths, "other")
        stack = ExitStack()
        stack.enter_context(hold_project_lock("app", paths))

        def release_when_other_runs(name):
            if name == "other":
                stack.close()

        try:
            rc, pulls, alert = self._run(paths, on_pull=release_when_other_runs)
        finally:
            stack.close()
        assert rc == 0
        assert pulls == ["caddy", "other", "app"]
        alert.assert_not_called()


# ---------------------------------------------------------------------------
# webhooks: delivery never holds the caller's lock
# ---------------------------------------------------------------------------

class TestWebhookDelivery:
    def test_webhook_safe_returns_before_delivery_finishes(self, paths):
        from boxmunge.webhooks import webhook_safe
        release = threading.Event()
        delivered = threading.Event()

        def slow_urlopen(request, timeout):
            release.wait(5)
            delivered.set()
            return MagicMock()

        config = {"hostname": "h",
                  "webhooks": [{"url": "https://hooks.example.com/x", "events": ["deploy"]}]}
        with patch("boxmunge.webhooks.load_config", return_value=config), \
             patch("boxmunge.webhooks.urllib.request.urlopen", slow_urlopen):
            with project_lock("myapp", paths):
                start = time.monotonic()
                thread = webhook_safe("deploy", "myapp", paths)
                assert time.monotonic() - start < 1
            # The caller has left its lock while the POST is still in flight.
            assert not project_lock_is_held("myapp", paths)
            assert not delivered.is_set()
            release.set()
            assert thread is not None
            thread.join(5)
        assert delivered.is_set()

    def test_delivery_failure_is_logged(self, paths):
        from boxmunge.webhooks import webhook_safe
        config = {"hostname": "h",
                  "webhooks": [{"url": "https://hooks.example.com/secret-token",
                                "events": ["deploy"]}]}
        with patch("boxmunge.webhooks.load_config", return_value=config), \
             patch("boxmunge.webhooks.urllib.request.urlopen",
                   side_effect=OSError("connection refused")), \
             patch("boxmunge.webhooks.log_warning") as warn:
            thread = webhook_safe("deploy", "myapp", paths)
            assert thread is not None
            thread.join(5)
        warn.assert_called_once()
        msg = warn.call_args[0][1]
        assert "hooks.example.com" in msg and "connection refused" in msg
        assert "secret-token" not in msg, "webhook URL paths can carry secrets"

    def test_no_matching_hooks_starts_no_thread(self, paths):
        from boxmunge.webhooks import webhook_safe
        config = {"hostname": "h",
                  "webhooks": [{"url": "https://hooks.example.com/x", "events": ["promote"]}]}
        with patch("boxmunge.webhooks.load_config", return_value=config):
            assert webhook_safe("deploy", "myapp", paths) is None


# ---------------------------------------------------------------------------
# resume: the smoke-failure Pushover is sent after the lock is released
# ---------------------------------------------------------------------------

class TestResumeAlertOutsideLock:
    def test_pushover_sent_after_lock_release(self, tmp_path):
        from boxmunge.commands import resume_cmd
        from boxmunge.pause import write_paused_state
        paths = _paths(tmp_path)
        _project(paths, "app")
        write_paused_state("app", paths)
        sent: list[bool] = []

        def fake_send(*_a, **_kw):
            sent.append(project_lock_is_held("app", paths))
            return True

        with patch.object(resume_cmd, "compose_pull"), \
             patch.object(resume_cmd, "compose_up"), \
             patch.object(resume_cmd, "caddy_reload"), \
             patch.object(resume_cmd, "prepare_caddy_config"), \
             patch.object(resume_cmd, "prepare_compose_override"), \
             patch.object(resume_cmd, "validate_user_compose"), \
             patch.object(resume_cmd, "run_smoke", return_value=(False, "boom")), \
             patch("boxmunge.notify.send_notification", fake_send):
            rc = resume_cmd.run_resume("app", paths, yes=True)
        assert rc == 0
        assert sent == [False]

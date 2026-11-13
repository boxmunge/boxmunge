"""What a wrong setting leaves working: the hooks beside a malformed one,
a call that reads only the hostname, and a tick while Pushover is down."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
import yaml

from boxmunge import host_config_alert
from boxmunge.api.principal import Principal, Tier
from boxmunge.commands.backup_sync_cmd import run_backup_sync
from boxmunge.config import read_config
from boxmunge.health_checks.host_config import check_host_config
from boxmunge.paths import BoxPaths
from boxmunge.webhooks import webhook_safe
from tests.api.fakes import make_invoker

CONFIG = {
    "hostname": "box.example.com", "admin_email": "ops@example.com",
    "pushover": {"user_key": "u", "app_token": "t"},
}
SECRET = "s3cr3t-T0KEN"
GOOD = f"https://hooks.example.com/good/{SECRET}"
BAD = f"https://hooks.example.com/bad/{SECRET}"


def _write(paths: BoxPaths, **settings) -> None:
    paths.config_file.write_text(yaml.safe_dump({**CONFIG, **settings}))


def _fired(paths: BoxPaths, event: str = "deploy") -> list[str]:
    """The URLs POSTed to for `event`."""
    urls: list[str] = []

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def urlopen(request, timeout):
        urls.append(request.full_url)
        return _Response()

    with patch("boxmunge.webhooks.urllib.request.urlopen", urlopen):
        thread = webhook_safe(event, "shop", paths)
        if thread is not None:
            thread.join()
    return urls


class TestOneMalformedHook:
    @pytest.mark.parametrize("bad", [
        {"url": BAD, "events": 5},
        {"url": BAD, "events": "deploy rollback"},
        {"url": BAD, "events": "deployed"},
        {"url": 5, "events": ["deploy"]},
        BAD,
    ], ids=["events a number", "two names in a string", "an unknown name as a string",
            "url a number", "a bare URL"])
    def test_the_other_hooks_still_fire(self, paths, bad) -> None:
        _write(paths, webhooks=[{"url": GOOD, "events": ["deploy"]}, bad])
        assert _fired(paths) == [GOOD]

    def test_it_is_named_by_its_place_and_never_its_url(self, paths) -> None:
        _write(paths, webhooks=[{"url": GOOD, "events": ["deploy"]},
                                {"url": BAD, "events": 5}])
        _, problems = read_config(paths)
        assert [p.setting for p in problems] == ["webhooks[1].events"]
        sent: list[str] = []
        with patch("boxmunge.notify.send_notification",
                   lambda key, token, title, body, priority=0: sent.append(body) or True):
            host_config_alert.report(paths, "check-all")
        _fired(paths)
        result = check_host_config(paths)
        told = [sent[0], result.detail, paths.log_file.read_text()]
        assert all("webhooks[1].events" in text for text in told)
        assert not any(SECRET in text for text in told)
        assert result.status == "warn"

    def test_webhooks_that_is_no_list_fires_nothing(self, paths) -> None:
        _write(paths, webhooks={"url": GOOD, "events": ["deploy"]})
        assert _fired(paths) == []
        assert "'webhooks'" in paths.log_file.read_text()


class TestOneEventNameOnItsOwn:
    def test_it_fires_for_that_event_as_it_did(self, paths) -> None:
        _write(paths, webhooks=[{"url": GOOD, "events": "deploy"}])
        assert read_config(paths)[1] == []
        assert _fired(paths) == [GOOD]

    def test_and_for_no_other(self, paths) -> None:
        _write(paths, webhooks=[{"url": GOOD, "events": "deploy"}])
        assert _fired(paths, "rollback") == []


def test_platform_info_reads_only_the_hostname(paths) -> None:
    _write(paths, logging={"docker_max_file": "5"})
    info = make_invoker(paths).invoke("platform.info", {},
                                      Principal.plugin("webui", Tier.OBSERVE))
    assert info.data["hostname"] == "box.example.com"


class TestWhilePushoverFails:
    @pytest.fixture
    def box(self, paths):
        _write(paths, logging={"docker_max_file": "5"})
        attempts: list[str] = []
        delivery = {"ok": False}

        def send(key, token, title, body, priority=0):
            attempts.append(title)
            return delivery["ok"]

        with patch("boxmunge.notify.send_notification", send):
            yield paths, attempts, delivery

    def _an_hour_passes(self, paths: BoxPaths) -> None:
        record = paths.state / "start-refused" / "boxmunge.yml.json"
        earlier = (datetime.now(timezone.utc) - timedelta(minutes=61)).isoformat()
        record.write_text(json.dumps({key: earlier for key in json.loads(record.read_text())}))

    def test_the_alert_is_tried_once_an_hour_not_every_tick(self, box) -> None:
        paths, attempts, delivery = box
        for _ in range(3):
            host_config_alert.report(paths, "check-all")
        assert len(attempts) == 1
        self._an_hour_passes(paths)
        host_config_alert.report(paths, "check-all")
        assert len(attempts) == 2
        delivery["ok"] = True
        self._an_hour_passes(paths)
        for _ in range(3):
            host_config_alert.report(paths, "check-all")
        assert len(attempts) == 3  # delivered, then quiet for the day

    def test_a_record_that_cannot_be_written_does_not_fail_the_tick(self, box) -> None:
        paths, attempts, _ = box
        paths.state.mkdir(parents=True, exist_ok=True)
        (paths.state / "start-refused").write_text("not a directory")
        host_config_alert.report(paths, "check-all")
        host_config_alert.report(paths, "check-all")
        assert len(attempts) == 2  # nothing says it was tried, so it is tried again
        assert "Cannot record" in paths.log_file.read_text()


def test_a_refused_backup_sync_is_logged(paths, capsys) -> None:
    _write(paths, backup_remote=["offsite:bucket"])
    with patch("boxmunge.notify.send_notification", lambda *a, **k: True):
        assert run_backup_sync(paths) == 1
    assert "'backup_remote'" in capsys.readouterr().err
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    assert [e["component"] for e in entries if e["level"] == "error"
            and "'backup_remote'" in e["msg"]] == ["backup-sync"]

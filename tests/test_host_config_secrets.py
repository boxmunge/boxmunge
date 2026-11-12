"""No error, alert, log line, health detail or API message quotes a
setting's value: boxmunge.yml holds secrets, and one pasted on the wrong
line is still a secret.

Real config, state and log files; only Pushover's HTTP call is stood in for.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import yaml

from boxmunge import host_config_alert
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError
from boxmunge.commands.check_all import run_check_all
from boxmunge.config import ConfigError, load_config
from boxmunge.cve.kev_refresh import kev_sources
from boxmunge.health_checks.alerts import check_alerts
from boxmunge.paths import BoxPaths
from boxmunge.userns.offset import RemapError, recorded_offset
from boxmunge.webhooks import webhook_safe
from tests.api.fakes import make_invoker

SECRET = "s3cr3t-T0ken-9f8e7d"
BASE = {"hostname": "box.example.com", "admin_email": "ops@example.com",
        "pushover": {"user_key": "u", "app_token": "t"}}

# name -> (the settings, the setting every surface must name)
CASES = {
    "a webhook URL beside events that is no list": (
        {"webhooks": [{"url": f"https://hooks.example.com/{SECRET}", "events": "deploy"}]},
        "webhooks"),
    "pushover as one string": ({"pushover": f"user:{SECRET}"}, "pushover"),
    "a key in a list": ({"pushover": {"user_key": [SECRET], "app_token": "t"}},
                        "pushover.user_key"),
    "a remote with its credentials, in a list": (
        {"backup_remote": [f"s3:key:{SECRET}@bucket"]}, "backup_remote"),
    "a token where a strategy goes": (
        {"container_updates": {"strategy": SECRET}}, "container_updates.strategy"),
    "a token where a number goes": ({"ssh_port": SECRET}, "ssh_port"),
    "a token where a switch goes": ({"auto_update": {"breakfix": SECRET}},
                                    "auto_update.breakfix"),
    "a KEV mirror with a token in its URL": (
        {"kev": {"sources": [f"http://mirror.example.com/{SECRET}/kev.json"]}}, "kev.sources"),
    "a userns record that is a token": ({"userns": {"name": SECRET, "offset": 3}}, "userns"),
}


def _said(paths: BoxPaths, capsys) -> str:
    """Everything the box says about its config, on every surface."""
    said: list[str] = []

    def attempt(call, *errors) -> None:
        try:
            call()  # what it returns is the config's to hold
        except errors as e:
            said.append(str(e) + str(getattr(e, "message", "")))

    def send(user_key, app_token, title, body, priority=0):
        said.extend((title, body))
        return True

    def platform_info():
        invoker = make_invoker(paths)
        return invoker.invoke("platform.info", {}, Principal.plugin("webui", Tier.OBSERVE)).data

    with patch("boxmunge.notify.send_notification", send):
        attempt(lambda: load_config(paths, strict=True), ConfigError)
        attempt(lambda: kev_sources(paths), ConfigError)
        attempt(lambda: recorded_offset(paths), RemapError)
        attempt(platform_info, ActionError)
        host_config_alert.report_at_start(paths, "upgrade")
        thread = webhook_safe("deploy", "shop", paths)
        assert thread is None, "a webhook was fired in a test"
        said.append(check_alerts(paths).detail)
        try:
            from boxmunge.health_checks.host_config import check_host_config
            said.append(check_host_config(paths).detail)
        except ImportError:  # the release under review had no such check
            pass
        run_check_all(paths, read_only=False)
    out = capsys.readouterr()
    said += [out.out, out.err]
    if paths.log_file.exists():
        said.append(paths.log_file.read_text())
    return "\n".join(said)


@pytest.mark.parametrize("extra,setting", CASES.values(), ids=CASES.keys())
def test_a_value_is_never_repeated(paths: BoxPaths, capsys, extra, setting) -> None:
    paths.config_file.write_text(yaml.safe_dump({**BASE, **extra}))
    said = _said(paths, capsys)
    assert f"'{setting}'" in said or f"{setting} " in said, said
    assert SECRET not in said


def test_a_config_that_is_not_yaml_is_not_quoted(paths: BoxPaths, capsys) -> None:
    paths.config_file.write_text(f"hostname: box.example.com\npushover: [u, {SECRET}\n")
    said = _said(paths, capsys)
    assert "not valid YAML" in said
    assert SECRET not in said

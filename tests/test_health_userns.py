"""docker-userns: warn until migrated, error when the daemon disagrees."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.health_checks import userns as hc
from boxmunge.userns import offset
from tests.userns_helpers import S, remap_box, remapped_info

T0 = datetime(2026, 10, 16, tzinfo=timezone.utc)


def test_unmigrated_box_warns_with_the_check_command(paths) -> None:
    check = hc.check_docker_userns(paths)
    assert (check.name, check.status) == ("docker-userns", "warn")
    assert "userns-migrate --check" in check.detail


def _caddy_logs(paths, monkeypatch, uid: int, gid: int):
    """caddy/logs as a directory owned uid:gid (a unit test cannot chown to S)."""
    import os
    logs = paths.caddy / "logs"
    logs.mkdir(parents=True)
    real = os.lstat

    def lstat(p):
        st = real(p)
        return os.stat_result((*st[:4], uid, gid, *st[6:])) if str(p) == str(logs) else st
    monkeypatch.setattr(hc.os, "lstat", lstat)
    return logs


def _caddyfile(paths, mode: int = 0o644):
    caddyfile = paths.caddy / "Caddyfile"
    caddyfile.write_text("import /etc/caddy/sites/*.conf\n")
    caddyfile.chmod(mode)
    return caddyfile


def test_remapped_box_is_ok(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    _caddy_logs(paths, monkeypatch, S, S)
    _caddyfile(paths)
    check = hc.check_docker_userns(paths)
    assert check.status == "ok" and str(S) in check.detail


def test_caddy_logs_must_belong_to_container_root(paths, monkeypatch) -> None:
    """Caddy runs remapped as container root (host uid S) and appends to
    caddy/logs/access.log; owned by host root, it cannot."""
    remap_box(paths, monkeypatch)
    _caddy_logs(paths, monkeypatch, 0, 0)
    check = hc.check_docker_userns(paths)
    assert check.status == "error" and "caddy/logs" in check.detail
    assert f"chown -hR {S}:{S} {paths.caddy / 'logs'}" in check.detail


@pytest.mark.parametrize("mode", [0o500, 0o650, 0o600])
def test_caddy_logs_must_be_writable_by_its_owner(paths, monkeypatch, mode) -> None:
    """S:S is not enough: Caddy has no DAC override, so without the owner's
    write and search bits it still cannot create access.log."""
    remap_box(paths, monkeypatch)
    logs = _caddy_logs(paths, monkeypatch, S, S)
    logs.chmod(mode)
    try:
        check = hc.check_docker_userns(paths)
    finally:
        logs.chmod(0o750)
    assert check.status == "error" and f"mode {mode:04o}" in check.detail
    assert f"sudo chmod 750 {logs}" in check.detail


@pytest.mark.parametrize("mode", [0o640, 0o600, 0o440])
def test_caddyfile_must_be_readable_by_other(paths, monkeypatch, mode) -> None:
    """Remapped, Caddy's root (host uid S) is neither the owner nor in the
    group of a root:deploy Caddyfile: it reads through the "other" bits."""
    remap_box(paths, monkeypatch)
    _caddy_logs(paths, monkeypatch, S, S)
    caddyfile = _caddyfile(paths, mode)
    check = hc.check_docker_userns(paths)
    assert check.status == "error" and f"mode {mode:04o}" in check.detail
    assert f"sudo chmod 0644 {caddyfile}" in check.detail


def test_missing_or_linked_caddyfile_is_an_error(paths, monkeypatch, tmp_path) -> None:
    remap_box(paths, monkeypatch)
    _caddy_logs(paths, monkeypatch, S, S)
    check = hc.check_docker_userns(paths)
    assert check.status == "error" and "Caddyfile does not exist" in check.detail
    (tmp_path / "real").write_text("x")
    (tmp_path / "real").chmod(0o644)
    (paths.caddy / "Caddyfile").symlink_to(tmp_path / "real")
    check = hc.check_docker_userns(paths)
    assert check.status == "error" and "not a regular file" in check.detail


def test_missing_caddy_logs_is_an_error_not_a_crash(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    check = hc.check_docker_userns(paths)
    assert check.status == "error" and "caddy/logs" in check.detail
    assert "does not exist" in check.detail


def test_symlinked_caddy_logs_is_an_error(paths, monkeypatch, tmp_path) -> None:
    remap_box(paths, monkeypatch)
    (tmp_path / "elsewhere").mkdir()
    (paths.caddy / "logs").symlink_to(tmp_path / "elsewhere")
    check = hc.check_docker_userns(paths)
    assert check.status == "error" and "not a directory" in check.detail


def test_unremapped_box_never_looks_at_caddy_logs(paths) -> None:
    assert not (paths.caddy / "logs").exists()
    assert hc.check_docker_userns(paths).status == "warn"


def test_flipped_daemon_is_an_error(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    info = remapped_info()
    info["Driver"] = "overlayfs"
    monkeypatch.setattr(offset, "docker_info", lambda: info)
    check = hc.check_docker_userns(paths)
    assert check.status == "error" and "storage driver" in check.detail


def test_error_alerts_once_a_day(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    sent = []
    monkeypatch.setattr(hc, "notify", lambda p, title, body, **kw: sent.append((title, kw)) or True)
    hc.alert_docker_userns(paths, now=T0)
    hc.alert_docker_userns(paths, now=T0 + timedelta(hours=2))
    hc.alert_docker_userns(paths, now=T0 + timedelta(hours=25))
    assert len(sent) == 2 and sent[0][1]["priority"] == 1


def test_warning_does_not_alert(paths, monkeypatch) -> None:
    sent = []
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: sent.append(a) or True)
    assert hc.alert_docker_userns(paths, now=T0).status == "warn"
    assert sent == []


def test_health_and_doctor_include_the_check() -> None:
    import inspect

    from boxmunge.commands import check, doctor, health_cmd
    assert "check_docker_userns" in inspect.getsource(health_cmd.collect_health)
    assert "check_docker_userns" in inspect.getsource(doctor.run_doctor)
    assert "alert_docker_userns" in inspect.getsource(check.run_check_all)


def test_check_all_exits_critical_on_an_error_even_without_projects(paths, monkeypatch) -> None:
    from boxmunge.commands.check import run_check_all
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: True)
    paths.projects.rmdir()
    assert run_check_all(paths, read_only=False) == 2


def test_unreadable_config_on_an_unremapped_box_only_warns(paths) -> None:
    paths.config_file.write_text("hostname: [unclosed\n")
    check = hc.check_docker_userns(paths)
    assert check.status == "warn" and "cannot tell" in check.detail


def test_unreachable_daemon_on_an_unremapped_box_only_warns(paths, monkeypatch) -> None:
    def down():
        raise offset.RemapError("cannot ask the Docker daemon whether it is remapped: down")
    monkeypatch.setattr(offset, "docker_info", down)
    sent = []
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: sent.append(a) or True)
    assert hc.alert_docker_userns(paths, now=T0).status == "warn"
    assert sent == []


def test_unreachable_daemon_on_a_remapped_box_is_an_error(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    def down():
        raise offset.RemapError("cannot ask the Docker daemon whether it is remapped: down")
    monkeypatch.setattr(offset, "docker_info", down)
    assert hc.check_docker_userns(paths).status == "error"


def test_undelivered_alert_is_retried_on_the_next_run(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    delivered = iter([False, True, True])
    sent = []
    monkeypatch.setattr(hc, "notify",
                        lambda *a, **kw: sent.append(a) or next(delivered))
    hc.alert_docker_userns(paths, now=T0)
    hc.alert_docker_userns(paths, now=T0 + timedelta(minutes=5))
    hc.alert_docker_userns(paths, now=T0 + timedelta(minutes=10))
    assert len(sent) == 2


@pytest.mark.parametrize("content", ["{not json", '["a"]', '{"k": 5}', '{"k": "yesterday"}',
                                     '{"k": "2026-10-16T00:00:00"}'])
def test_unusable_alert_state_is_reported_and_replaced(paths, monkeypatch, capsys,
                                                       content) -> None:
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    (paths.state / "userns-alert.json").write_text(content)
    sent = []
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: sent.append(a) or True)
    assert hc.alert_docker_userns(paths, now=T0).status == "error"
    assert len(sent) == 1 and "userns-alert.json" in capsys.readouterr().err
    hc.alert_docker_userns(paths, now=T0 + timedelta(hours=1))
    assert len(sent) == 1


def test_foreign_remap_identity_warns_and_names_the_way_out(paths, monkeypatch) -> None:
    (offset.ETC / "docker").mkdir()
    (offset.ETC / "docker" / "daemon.json").write_text('{"userns-remap": "default"}')
    monkeypatch.setattr(offset, "docker_info", lambda: remapped_info(165536))
    check = hc.check_docker_userns(paths)
    assert check.status == "warn" and "'default'" in check.detail
    assert "OPERATIONS.md" in check.detail


def test_unreadable_daemon_json_on_a_never_remapped_box_warns(paths) -> None:
    (offset.ETC / "docker").mkdir()
    (offset.ETC / "docker" / "daemon.json").write_text("{not json")
    assert hc.check_docker_userns(paths).status == "warn"


def test_symlinked_alert_state_is_not_followed(paths, monkeypatch, tmp_path, capsys) -> None:
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    elsewhere = tmp_path / "elsewhere.json"
    key = __import__("hashlib").sha256(hc.check_docker_userns(paths).detail.encode()).hexdigest()[:16]
    elsewhere.write_text('{"%s": "%s"}' % (key, T0.isoformat()))
    (paths.state / "userns-alert.json").symlink_to(elsewhere)
    sent = []
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: sent.append(a) or True)
    hc.alert_docker_userns(paths, now=T0 + timedelta(minutes=1))
    assert len(sent) == 1 and "userns-alert.json" in capsys.readouterr().err
    assert elsewhere.read_text().startswith('{"%s"' % key)  # never written through


def test_future_alert_time_is_unusable_and_not_logged(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: {**remapped_info(), "SecurityOptions": []})
    (paths.state / "userns-alert.json").write_text('{"k": "2999-01-01T00:00:00+00:00"}')
    sent = []
    monkeypatch.setattr(hc, "notify", lambda *a, **kw: sent.append(a) or True)
    hc.alert_docker_userns(paths, now=T0)
    assert len(sent) == 1
    assert "2999" not in paths.log_file.read_text()

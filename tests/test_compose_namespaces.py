"""D9: userns_mode is never relaxable; privileged and host pid/net/ipc are
unrelaxable only on a remapped box; uts and cgroup stay relaxable."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from tests.userns_helpers import remap_box

OFF = {"profile": "off", "reason": "needs host access"}


def _validate(paths, svc: dict, *, off: bool) -> None:
    project = paths.project_dir("app")
    project.mkdir(parents=True, exist_ok=True)
    compose = project / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": {"image": "nginx:1.27", **svc}}}))
    validate_user_compose(compose, paths, project_name="app",
                          off_services={"web"} if off else set(),
                          cve_policy=OFF if off else None, manifest_services={"web": {}})


@pytest.mark.parametrize("value", ["host", "private", ""])
@pytest.mark.parametrize("remapped", [False, True])
def test_userns_mode_refused_even_under_profile_off(paths, monkeypatch, value, remapped) -> None:
    if remapped:
        remap_box(paths, monkeypatch)
    with pytest.raises(ComposeSecurityError, match=r"userns_mode .*\(not relaxed by profile: off\)"):
        _validate(paths, {"userns_mode": value}, off=True)


@pytest.mark.parametrize("svc", [{"privileged": True}, {"pid": "host"},
                                 {"network_mode": "host"}, {"ipc": "host"}])
def test_host_namespaces_unrelaxable_on_a_remapped_box(paths, monkeypatch, svc) -> None:
    remap_box(paths, monkeypatch)
    with pytest.raises(ComposeSecurityError, match="remaps user namespaces"):
        _validate(paths, svc, off=True)


@pytest.mark.parametrize("svc", [{"privileged": True}, {"pid": "host"},
                                 {"network_mode": "host"}, {"ipc": "host"}])
def test_host_namespaces_still_relaxable_before_migration(paths, svc) -> None:
    _validate(paths, svc, off=True)  # a warning, as today
    with pytest.raises(ComposeSecurityError, match="defeats boxmunge hardening"):
        _validate(paths, svc, off=False)


@pytest.mark.parametrize("svc", [{"uts": "host"}, {"cgroup": "host"}])
def test_uts_and_cgroup_stay_relaxable_when_remapped(paths, monkeypatch, svc) -> None:
    remap_box(paths, monkeypatch)
    _validate(paths, svc, off=True)


def test_record_the_daemon_disagrees_with_refuses_validation(paths, monkeypatch) -> None:
    from boxmunge.userns import offset
    from tests.userns_helpers import UNREMAPPED_INFO
    remap_box(paths, monkeypatch)
    monkeypatch.setattr(offset, "docker_info", lambda: dict(UNREMAPPED_INFO))
    with pytest.raises(ComposeSecurityError, match="cannot tell whether this box remaps"):
        _validate(paths, {}, off=False)


def test_unreadable_daemon_json_on_a_never_remapped_box_does_not_block(paths) -> None:
    from boxmunge.userns import offset
    (offset.ETC / "docker").mkdir()
    (offset.ETC / "docker" / "daemon.json").write_text("{not json")
    _validate(paths, {}, off=False)
    _validate(paths, {"pid": "host"}, off=True)  # unremapped rules: a warning


@pytest.mark.parametrize("value", ["default", "dockremap:dockremap", ""])
def test_foreign_or_empty_userns_remap_does_not_block(paths, monkeypatch, value) -> None:
    import json

    from boxmunge.userns import offset
    from tests.userns_helpers import remapped_info
    (offset.ETC / "docker").mkdir()
    (offset.ETC / "docker" / "daemon.json").write_text(json.dumps({"userns-remap": value}))
    if value:
        monkeypatch.setattr(offset, "docker_info", lambda: remapped_info(165536))
    _validate(paths, {}, off=False)
    if value:  # the running daemon is remapped, so it cannot start host namespaces
        with pytest.raises(ComposeSecurityError, match="remaps user namespaces"):
            _validate(paths, {"pid": "host"}, off=True)


def test_unmappable_compose_user_refused_only_when_remapped(paths, monkeypatch) -> None:
    _validate(paths, {"user": "70000"}, off=False)  # a warning before the migration
    remap_box(paths, monkeypatch)
    with pytest.raises(ComposeSecurityError, match="above 65535"):
        _validate(paths, {"user": "70000"}, off=False)


def test_signed_compose_user_refused_everywhere(paths) -> None:
    with pytest.raises(ComposeSecurityError, match="without a sign"):
        _validate(paths, {"user": "+70000"}, off=False)

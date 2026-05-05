"""Tests for boxmunge.compose_validate — silent-floor compose.yml guard."""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge.compose_validate import (
    ComposeSecurityError,
    validate_user_compose,
)


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


# ---------------------------------------------------------------------------
# Benign / accepted compose files
# ---------------------------------------------------------------------------

class TestBenignCompose:
    def test_normal_compose_passes(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./data:/data
""")
        validate_user_compose(compose, paths)

    def test_no_new_privileges_security_opt_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - no-new-privileges:true
""")
        validate_user_compose(compose, paths)

    def test_seccomp_runtime_default_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - seccomp=runtime/default
""")
        validate_user_compose(compose, paths)

    def test_legitimate_cap_add_net_raw_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cap_add:
      - NET_RAW
""")
        validate_user_compose(compose, paths)

    def test_relative_volume_source_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - ./data:/data
      - data_vol:/var/lib/data
""")
        validate_user_compose(compose, paths)

    def test_named_volume_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - dbdata:/var/lib/postgres
volumes:
  dbdata: {}
""")
        validate_user_compose(compose, paths)

    def test_long_syntax_safe_bind_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: ./conf
        target: /etc/nginx/conf.d
""")
        validate_user_compose(compose, paths)


# ---------------------------------------------------------------------------
# Rejection paths — one per hostile-key class
# ---------------------------------------------------------------------------

class TestRejectsPrivileged:
    def test_privileged_true_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    privileged: true
""")
        with pytest.raises(ComposeSecurityError, match="privileged"):
            validate_user_compose(compose, paths)


class TestRejectsPid:
    def test_pid_host_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    pid: host
""")
        with pytest.raises(ComposeSecurityError, match="pid"):
            validate_user_compose(compose, paths)

    def test_pid_container_namespace_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    pid: "container:abc"
""")
        with pytest.raises(ComposeSecurityError, match="pid"):
            validate_user_compose(compose, paths)

    def test_pid_unset_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        validate_user_compose(compose, paths)


class TestRejectsUsernsHost:
    def test_userns_host_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    userns_mode: host
""")
        with pytest.raises(ComposeSecurityError, match="userns"):
            validate_user_compose(compose, paths)


class TestRejectsNetworkHost:
    def test_network_mode_host_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    network_mode: host
""")
        with pytest.raises(ComposeSecurityError, match="network_mode"):
            validate_user_compose(compose, paths)


class TestRejectsSecurityOpt:
    def test_seccomp_unconfined_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - seccomp=unconfined
""")
        with pytest.raises(ComposeSecurityError, match="security_opt"):
            validate_user_compose(compose, paths)

    def test_apparmor_unconfined_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - apparmor=unconfined
""")
        with pytest.raises(ComposeSecurityError, match="security_opt"):
            validate_user_compose(compose, paths)

    def test_label_disable_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - label:disable
""")
        with pytest.raises(ComposeSecurityError, match="security_opt"):
            validate_user_compose(compose, paths)

    def test_label_disable_case_insensitive_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - LABEL:DISABLE
""")
        with pytest.raises(ComposeSecurityError, match="security_opt"):
            validate_user_compose(compose, paths)


class TestRejectsCapAdd:
    def test_sys_admin_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cap_add:
      - SYS_ADMIN
""")
        with pytest.raises(ComposeSecurityError, match="cap_add"):
            validate_user_compose(compose, paths)

    def test_dac_read_search_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cap_add:
      - DAC_READ_SEARCH
""")
        with pytest.raises(ComposeSecurityError, match="cap_add"):
            validate_user_compose(compose, paths)

    def test_bpf_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cap_add:
      - BPF
""")
        with pytest.raises(ComposeSecurityError, match="cap_add"):
            validate_user_compose(compose, paths)

    def test_perfmon_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cap_add:
      - PERFMON
""")
        with pytest.raises(ComposeSecurityError, match="cap_add"):
            validate_user_compose(compose, paths)

    def test_sys_resource_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cap_add:
      - SYS_RESOURCE
""")
        with pytest.raises(ComposeSecurityError, match="cap_add"):
            validate_user_compose(compose, paths)

    def test_default_cap_drop_member_in_cap_add_accepted(self, tmp_path: Path, paths) -> None:
        # NET_ADMIN appears in DEFAULT_CAP_DROP. Adding it back via cap_add
        # is the legitimate opt-back-in mechanism — same as NET_RAW for ping.
        # The validator must NOT reject it.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cap_add:
      - NET_ADMIN
""")
        validate_user_compose(compose, paths)


class TestRejectsHostileVolumes:
    def test_docker_socket_short_syntax_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_docker_socket_long_syntax_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /sock
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_proc_mount_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /proc:/host/proc
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_sys_mount_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /sys:/host/sys
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_root_mount_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /:/host
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_etc_mount_rejected_even_readonly(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /etc:/etc:ro
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_dev_mount_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /dev:/dev
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)


# ---------------------------------------------------------------------------
# off_services downgrade-to-warning path
# ---------------------------------------------------------------------------

class TestOffServiceWarnsInsteadOfRaising:
    def test_off_service_with_privileged_warns_only(
        self, tmp_path: Path, paths, capsys
    ) -> None:
        # The boxmunge logger has propagate=False and writes WARNING to stderr.
        # Capture stderr to confirm a warning was emitted.
        from boxmunge.log import _reset_logger
        _reset_logger()
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    privileged: true
""")
        validate_user_compose(compose, paths, off_services={"web"})
        captured = capsys.readouterr()
        assert "hostile compose key privileged" in captured.err
        assert "service web" in captured.err
        assert "profile: off" in captured.err

    def test_off_service_with_hostile_volume_warns_only(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /var/run/docker.sock:/sock
""")
        # No raise.
        validate_user_compose(compose, paths, off_services={"web"})

    def test_non_off_service_in_same_compose_still_raises(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    privileged: true
  api:
    image: api
    privileged: true
""")
        # `web` is opted out, but `api` is not — must still raise.
        with pytest.raises(ComposeSecurityError, match="api"):
            validate_user_compose(compose, paths, off_services={"web"})


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_multiple_hostile_services_first_error_is_fine(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  alpha:
    image: a
    privileged: true
  beta:
    image: b
    privileged: true
""")
        with pytest.raises(ComposeSecurityError):
            validate_user_compose(compose, paths)

    def test_unparseable_compose_raises_compose_security_error(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", "::: not yaml :::\n  - [ unbalanced")
        with pytest.raises(ComposeSecurityError, match="could not parse"):
            validate_user_compose(compose, paths)

    def test_missing_compose_raises(self, tmp_path: Path, paths) -> None:
        compose = tmp_path / "missing.yml"
        with pytest.raises(ComposeSecurityError):
            validate_user_compose(compose, paths)

    def test_empty_compose_passes(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", "")
        validate_user_compose(compose, paths)

    def test_no_services_block_passes(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", "version: '3'\n")
        validate_user_compose(compose, paths)

    def test_non_dict_service_skipped(self, tmp_path: Path, paths) -> None:
        # Compose with a service entry that's not a mapping — defensive.
        compose = _write(tmp_path / "compose.yml", """
services:
  web: null
""")
        validate_user_compose(compose, paths)

    def test_off_services_none_treated_as_empty(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    privileged: true
""")
        with pytest.raises(ComposeSecurityError):
            validate_user_compose(compose, paths, off_services=None)

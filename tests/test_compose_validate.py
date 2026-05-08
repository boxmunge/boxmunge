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

    def test_no_new_privileges_security_opt_on_off_profile_accepted(
        self, tmp_path: Path, paths,
    ) -> None:
        # Wave 3: redeclaring `no-new-privileges:true` is rejected on
        # default-profile services (overlay-merge dedupe), but permitted
        # when the service is explicitly opted out via profile: off.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - no-new-privileges:true
""")
        validate_user_compose(compose, paths, off_services={"web"})

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

    def test_run_docker_sock_short_syntax_rejected(self, tmp_path: Path, paths) -> None:
        # Audit B-1: on modern Debian /var/run is a symlink to /run, so the
        # canonical Docker socket path is /run/docker.sock. The validator
        # must reject the unsymlinked path explicitly.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /run/docker.sock:/var/run/docker.sock
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_run_docker_sock_long_syntax_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: /run/docker.sock
        target: /sock
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_run_subpath_still_allowed(self, tmp_path: Path, paths) -> None:
        # Audit B-1 boundary: /run by itself must NOT be rejected — many
        # legitimate apps mount /run/myapp tmpfs paths. Only /run/docker.sock
        # (and its descendants) and /var/run/docker.sock are hostile.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /run/myapp:/run/myapp
""")
        # Should not raise.
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


# ---------------------------------------------------------------------------
# A-NEW-3 — Hostile-volume Path-prefix matching (subpaths must be rejected)
# ---------------------------------------------------------------------------

class TestRejectsHostileVolumeSubpaths:
    def test_proc_self_subpath_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /proc/self:/host_self
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_etc_passwd_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /etc/passwd:/etc/passwd:ro
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_etc_shadow_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /etc/shadow:/x
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_dev_block_device_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /dev/sda:/dev/sda
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_sys_fs_cgroup_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /sys/fs/cgroup:/cg
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_docker_sock_lookalike_dir_rejected(self, tmp_path: Path, paths) -> None:
        # /var/run/docker.sock is a file; an attacker mounting a sibling
        # directory like /var/run/docker.sock.d/sock would be a lookalike.
        # We treat the docker.sock path as a strict prefix: subpaths under it
        # are rejected via the same prefix-match rule.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /var/run/docker.sock/anything:/sock
""")
        with pytest.raises(ComposeSecurityError, match="volumes"):
            validate_user_compose(compose, paths)

    def test_benign_home_path_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /home/deploy/foo:/foo
""")
        validate_user_compose(compose, paths)


# ---------------------------------------------------------------------------
# A-NEW-4 — Variable substitution in volume sources is rejected up front.
# ---------------------------------------------------------------------------

class TestRejectsVolumeEnvSubstitution:
    def test_brace_substitution_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - ${SOCK_PATH}:/var/run/docker.sock
""")
        with pytest.raises(ComposeSecurityError, match="substitution"):
            validate_user_compose(compose, paths)

    def test_bare_dollar_substitution_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - $HOME/foo:/etc
""")
        with pytest.raises(ComposeSecurityError, match="substitution"):
            validate_user_compose(compose, paths)

    def test_brace_substitution_in_long_syntax_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: ${PROC_PATH}
        target: /host_proc
""")
        with pytest.raises(ComposeSecurityError, match="substitution"):
            validate_user_compose(compose, paths)

    # Audit F-5: embedded `$` (not just leading) must trigger rejection.
    def test_embedded_bare_dollar_substitution_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /foo$BAR:/dst
""")
        with pytest.raises(ComposeSecurityError, match="substitution"):
            validate_user_compose(compose, paths)

    def test_embedded_brace_substitution_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /foo${BAR}/x:/dst
""")
        with pytest.raises(ComposeSecurityError, match="substitution"):
            validate_user_compose(compose, paths)

    def test_trailing_brace_substitution_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /abc/${BAR}:/dst
""")
        with pytest.raises(ComposeSecurityError, match="substitution"):
            validate_user_compose(compose, paths)

    def test_literal_path_no_dollars_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /literal/no/dollars:/dst
""")
        validate_user_compose(compose, paths)


# ---------------------------------------------------------------------------
# A-NEW-5 — `no-new-privileges:false` rejected as security_opt.
# ---------------------------------------------------------------------------

class TestRejectsNoNewPrivilegesFalse:
    def test_no_new_privileges_false_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - no-new-privileges:false
""")
        with pytest.raises(ComposeSecurityError, match="security_opt"):
            validate_user_compose(compose, paths)

    def test_no_new_privileges_false_mixed_case_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - No-New-Privileges:False
""")
        with pytest.raises(ComposeSecurityError, match="security_opt"):
            validate_user_compose(compose, paths)


# ---------------------------------------------------------------------------
# Wave 3 — Compose-merge dedupe defense-in-depth (Architecture audit Option C).
#
# User compose.yml + boxmunge overlay both declaring the same security_opt
# entry produces a duplicate at merge time, which Compose v2 rejects. The
# validator catches this up front with a targeted error rather than letting
# the operator see a confusing docker-compose stack trace.
# ---------------------------------------------------------------------------


class TestRejectsOverlayDedupe:
    def test_redeclared_no_new_privileges_true_default_profile_rejected(
        self, tmp_path: Path, paths,
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - no-new-privileges:true
""")
        with pytest.raises(ComposeSecurityError, match="redundant"):
            validate_user_compose(compose, paths)

    def test_redeclared_on_off_profile_permitted(
        self, tmp_path: Path, paths,
    ) -> None:
        # Off services are out of overlay coverage; the redundancy check
        # does not apply to them.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - no-new-privileges:true
""")
        validate_user_compose(compose, paths, off_services={"web"})

    def test_unrelated_security_opt_entry_permitted(
        self, tmp_path: Path, paths,
    ) -> None:
        # A custom seccomp profile is not in the overlay's emission set,
        # so it must pass the dedupe gate even on a default-profile
        # service. (The hostile-substring check still applies elsewhere
        # — `seccomp=runtime/default` is benign.)
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - seccomp=runtime/default
""")
        validate_user_compose(compose, paths)

    def test_redeclared_no_new_privileges_false_still_hostile(
        self, tmp_path: Path, paths,
    ) -> None:
        # Regression guard: the existing hostile-substring check (rejects
        # `no-new-privileges:false`) fires BEFORE the overlay-dedupe
        # check, so the operator-friendly hostile-key wording stays
        # primary. (Order of precedence matters for the error message
        # the operator sees first.)
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - no-new-privileges:false
""")
        with pytest.raises(ComposeSecurityError, match="security_opt"):
            validate_user_compose(compose, paths)

    def test_redeclared_message_mentions_overlay(
        self, tmp_path: Path, paths,
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - no-new-privileges:true
""")
        with pytest.raises(ComposeSecurityError) as excinfo:
            validate_user_compose(compose, paths)
        msg = str(excinfo.value)
        assert "boxmunge default-profile overlay" in msg
        assert "no-new-privileges:true" in msg


# ---------------------------------------------------------------------------
# A-NEW-6 — Additional escape-vector keys.
# ---------------------------------------------------------------------------

class TestRejectsIpcHost:
    def test_ipc_host_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    ipc: host
""")
        with pytest.raises(ComposeSecurityError, match="ipc"):
            validate_user_compose(compose, paths)


class TestRejectsCgroupnsHost:
    def test_cgroupns_mode_host_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cgroupns_mode: host
""")
        with pytest.raises(ComposeSecurityError, match="cgroupns_mode"):
            validate_user_compose(compose, paths)


class TestRejectsDevices:
    def test_non_empty_devices_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    devices:
      - /dev/kvm:/dev/kvm
""")
        with pytest.raises(ComposeSecurityError, match="devices"):
            validate_user_compose(compose, paths)

    def test_empty_devices_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    devices: []
""")
        validate_user_compose(compose, paths)


class TestRejectsDeviceCgroupRules:
    def test_non_empty_device_cgroup_rules_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    device_cgroup_rules:
      - "c *:* rwm"
""")
        with pytest.raises(ComposeSecurityError, match="device_cgroup_rules"):
            validate_user_compose(compose, paths)


class TestRejectsHostileCgroupParent:
    def test_absolute_path_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cgroup_parent: /system.slice
""")
        with pytest.raises(ComposeSecurityError, match="cgroup_parent"):
            validate_user_compose(compose, paths)

    def test_dotdot_traversal_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cgroup_parent: foo/../bar
""")
        with pytest.raises(ComposeSecurityError, match="cgroup_parent"):
            validate_user_compose(compose, paths)

    def test_flat_name_accepted(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cgroup_parent: my-cgroup
""")
        validate_user_compose(compose, paths)


# ---------------------------------------------------------------------------
# A-NEW-7 — Case-insensitive scalar checks.
# ---------------------------------------------------------------------------

class TestCaseInsensitiveScalarChecks:
    def test_pid_HOST_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    pid: HOST
""")
        with pytest.raises(ComposeSecurityError, match="pid"):
            validate_user_compose(compose, paths)

    def test_network_mode_Host_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    network_mode: Host
""")
        with pytest.raises(ComposeSecurityError, match="network_mode"):
            validate_user_compose(compose, paths)

    def test_userns_mode_HOST_rejected(self, tmp_path: Path, paths) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    userns_mode: HOST
""")
        with pytest.raises(ComposeSecurityError, match="userns"):
            validate_user_compose(compose, paths)


# ---------------------------------------------------------------------------
# I-NEW-3 — Off-service warnings now surface ALL hostile entries.
# ---------------------------------------------------------------------------

class TestOffServiceSurfacesAllHostileEntries:
    def test_multiple_hostile_caps_each_logged(
        self, tmp_path: Path, paths, capsys
    ) -> None:
        from boxmunge.log import _reset_logger
        _reset_logger()
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    cap_add:
      - SYS_ADMIN
      - BPF
""")
        validate_user_compose(compose, paths, off_services={"web"})
        captured = capsys.readouterr()
        assert "SYS_ADMIN" in captured.err
        assert "BPF" in captured.err

    def test_multiple_hostile_volumes_each_logged(
        self, tmp_path: Path, paths, capsys
    ) -> None:
        from boxmunge.log import _reset_logger
        _reset_logger()
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    volumes:
      - /proc:/host/proc
      - /etc:/host/etc
""")
        validate_user_compose(compose, paths, off_services={"web"})
        captured = capsys.readouterr()
        # Two warnings — one per hostile entry.
        assert captured.err.count("hostile compose key volumes") >= 2

    def test_multiple_hostile_security_opts_each_logged(
        self, tmp_path: Path, paths, capsys
    ) -> None:
        from boxmunge.log import _reset_logger
        _reset_logger()
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    security_opt:
      - seccomp=unconfined
      - apparmor=unconfined
""")
        validate_user_compose(compose, paths, off_services={"web"})
        captured = capsys.readouterr()
        assert captured.err.count("hostile compose key security_opt") >= 2


# ---------------------------------------------------------------------------
# E-NEW-2 — `validate_user_compose` accepts project_name and threads it.
# ---------------------------------------------------------------------------

class TestProjectNameThreaded:
    def test_project_name_passed_to_log_warning(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    privileged: true
""")
        from unittest.mock import patch
        with patch("boxmunge.compose_validate.log_warning") as mw:
            validate_user_compose(
                compose, paths, off_services={"web"},
                project_name="myapp",
            )
            assert mw.called
            # Every call must pass project="myapp" so `boxmunge log --project`
            # can filter compose-validate warnings.
            for call in mw.call_args_list:
                assert call.kwargs.get("project") == "myapp"

    def test_project_name_optional(self, tmp_path: Path, paths) -> None:
        # Existing call sites without project_name still work.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    privileged: true
""")
        from unittest.mock import patch
        with patch("boxmunge.compose_validate.log_warning") as mw:
            validate_user_compose(compose, paths, off_services={"web"})
            assert mw.called
            for call in mw.call_args_list:
                # project=None means structured logs simply don't carry the field.
                assert call.kwargs.get("project") is None


# ---------------------------------------------------------------------------
# v0.6.0 — CVE policy cross-validation. Project-level CVE-policy fields
# (`dangerously_disable_quarantine`, `posture: strict`) demand `read_only:
# true` on every non-off service as defense in depth. Off services log a
# warning instead of raising.
# ---------------------------------------------------------------------------

class TestCveCrossValidation:
    # --- Rule A: dangerously_disable_quarantine requires read_only -----------

    def test_disable_quarantine_with_readonly_passes(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    read_only: true
""")
        validate_user_compose(
            compose, paths,
            cve_policy={"dangerously_disable_quarantine": True},
        )

    def test_disable_quarantine_with_readonly_false_rejected(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    read_only: false
""")
        with pytest.raises(ComposeSecurityError) as exc:
            validate_user_compose(
                compose, paths,
                cve_policy={"dangerously_disable_quarantine": True},
            )
        msg = str(exc.value)
        assert "service web" in msg
        assert "dangerously_disable_quarantine: true requires" in msg
        assert "read_only: true" in msg
        assert "Read-only rootfs" in msg

    def test_disable_quarantine_without_readonly_key_rejected(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        with pytest.raises(ComposeSecurityError, match="dangerously_disable_quarantine"):
            validate_user_compose(
                compose, paths,
                cve_policy={"dangerously_disable_quarantine": True},
            )

    def test_disable_quarantine_offending_service_in_off_warns_only(
        self, tmp_path: Path, paths, capsys
    ) -> None:
        from boxmunge.log import _reset_logger
        _reset_logger()
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    read_only: false
""")
        # No raise — off service downgrades to warning.
        validate_user_compose(
            compose, paths,
            off_services={"web"},
            cve_policy={"dangerously_disable_quarantine": True},
        )
        captured = capsys.readouterr()
        assert "web" in captured.err
        assert "dangerously_disable_quarantine" in captured.err
        assert "read_only" in captured.err

    def test_disable_quarantine_false_does_not_apply_rule(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        validate_user_compose(
            compose, paths,
            cve_policy={"dangerously_disable_quarantine": False},
        )

    def test_disable_quarantine_absent_does_not_apply_rule(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        # Empty cve_policy dict — neither rule applies.
        validate_user_compose(compose, paths, cve_policy={})

    def test_cve_policy_none_does_not_apply_rules(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        validate_user_compose(compose, paths, cve_policy=None)

    def test_disable_quarantine_first_offender_named_in_error(
        self, tmp_path: Path, paths
    ) -> None:
        # Service ordering follows insertion order. `alpha` is missing
        # read_only first, so the error must name `alpha`, not `beta`.
        compose = _write(tmp_path / "compose.yml", """
services:
  alpha:
    image: a
    read_only: false
  beta:
    image: b
    read_only: true
  gamma:
    image: c
""")
        with pytest.raises(ComposeSecurityError) as exc:
            validate_user_compose(
                compose, paths,
                cve_policy={"dangerously_disable_quarantine": True},
            )
        msg = str(exc.value)
        assert "service alpha" in msg
        assert "service beta" not in msg
        assert "service gamma" not in msg

    # --- Rule B: posture: strict requires read_only --------------------------

    def test_posture_strict_with_readonly_passes(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
    read_only: true
  api:
    image: api
    read_only: true
""")
        validate_user_compose(
            compose, paths, cve_policy={"posture": "strict"},
        )

    def test_posture_strict_without_readonly_rejected(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        with pytest.raises(ComposeSecurityError) as exc:
            validate_user_compose(
                compose, paths, cve_policy={"posture": "strict"},
            )
        msg = str(exc.value)
        assert "service web" in msg
        assert "posture 'strict' requires read_only: true" in msg
        assert "balanced" in msg or "relaxed" in msg

    def test_posture_strict_offending_service_in_off_warns_only(
        self, tmp_path: Path, paths, capsys
    ) -> None:
        from boxmunge.log import _reset_logger
        _reset_logger()
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        validate_user_compose(
            compose, paths,
            off_services={"web"},
            cve_policy={"posture": "strict"},
        )
        captured = capsys.readouterr()
        assert "web" in captured.err
        assert "strict" in captured.err
        assert "read_only" in captured.err

    def test_posture_balanced_does_not_apply_rule(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        validate_user_compose(
            compose, paths, cve_policy={"posture": "balanced"},
        )

    def test_posture_relaxed_does_not_apply_rule(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        validate_user_compose(
            compose, paths, cve_policy={"posture": "relaxed"},
        )

    def test_posture_absent_does_not_apply_rule(
        self, tmp_path: Path, paths
    ) -> None:
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        # No `posture` key — Rule B inert.
        validate_user_compose(
            compose, paths,
            cve_policy={"dangerously_disable_quarantine": False},
        )

    # --- Combined: rule order ------------------------------------------------

    def test_both_rules_trigger_rule_a_wins(
        self, tmp_path: Path, paths
    ) -> None:
        # Service violates both rules. Rule A (dangerously_disable_quarantine)
        # runs first per spec, so its message must be the one raised.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        with pytest.raises(ComposeSecurityError) as exc:
            validate_user_compose(
                compose, paths,
                cve_policy={
                    "dangerously_disable_quarantine": True,
                    "posture": "strict",
                },
            )
        msg = str(exc.value)
        assert "dangerously_disable_quarantine: true requires" in msg
        # Rule B's distinctive phrasing must NOT appear.
        assert "posture 'strict' requires" not in msg

    # --- Backward-compat: signature stays optional ---------------------------

    def test_signature_remains_compatible_without_cve_policy(
        self, tmp_path: Path, paths
    ) -> None:
        # Existing callers don't pass cve_policy. Must keep working.
        compose = _write(tmp_path / "compose.yml", """
services:
  web:
    image: nginx
""")
        validate_user_compose(compose, paths)
        validate_user_compose(compose, paths, off_services={"web"})
        validate_user_compose(
            compose, paths, off_services=None, project_name="demo",
        )

"""Tests for boxmunge.docker — compose stop/start commands."""

import fcntl
import os
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


from boxmunge.docker import (
    compose_stop,
    compose_pull,
    tag_image,
    container_running,
    caddy_reload,
    DockerError,
)


class TestComposeStop:
    @patch("boxmunge.docker._run")
    def test_stop_default(self, mock_run: any, tmp_path: Path) -> None:
        compose_stop(tmp_path, project_name="myapp")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == [
            "docker", "compose", "-p", "myapp", "-f", "compose.yml", "stop", "-t", "15",
        ]

    @patch("boxmunge.docker._run")
    def test_stop_custom_timeout(self, mock_run: any, tmp_path: Path) -> None:
        compose_stop(tmp_path, project_name="myapp", timeout=30)
        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd
        assert cmd[cmd.index("-t") + 1] == "30"

    @patch("boxmunge.docker._run")
    def test_stop_with_project_name(self, mock_run: any, tmp_path: Path) -> None:
        compose_stop(tmp_path, project_name="myapp")
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        assert cmd[cmd.index("-p") + 1] == "myapp"


class TestComposePull:
    @patch("boxmunge.docker._run")
    def test_runs_compose_pull(self, mock_run):
        compose_pull(Path("/projects/myapp"), project_name="myapp", services=["db", "cache"])
        cmd = mock_run.call_args[0][0]
        assert cmd[:2] == ["docker", "compose"]
        assert cmd[cmd.index("pull"):] == ["pull", "--ignore-buildable", "db", "cache"]

    def test_refuses_an_empty_service_list(self):
        with pytest.raises(ValueError, match="at least one service"):
            compose_pull(Path("/projects/myapp"), project_name="myapp", services=[])

    @patch("boxmunge.docker._run")
    def test_includes_compose_files(self, mock_run):
        compose_pull(
            Path("/projects/myapp"), compose_files=["compose.yml", "compose.boxmunge.yml"],
            project_name="myapp", services=["db"],
        )
        cmd = mock_run.call_args[0][0]
        assert "compose.yml" in cmd
        assert "compose.boxmunge.yml" in cmd


class TestTagImage:
    @patch("boxmunge.docker._run")
    def test_tags_image(self, mock_run):
        tag_image("sha256:abc123", "caddy:2-alpine")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "tag", "sha256:abc123", "caddy:2-alpine"]


class TestContainerRunning:
    @patch("boxmunge.docker._run")
    def test_returns_true_when_running(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "true\n"
        mock_run.return_value = mock_result
        assert container_running("mycontainer") is True
        cmd = mock_run.call_args[0][0]
        assert cmd == ["docker", "inspect", "--format", "{{.State.Running}}", "mycontainer"]

    @patch("boxmunge.docker._run")
    def test_returns_false_when_not_running(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "false\n"
        mock_run.return_value = mock_result
        assert container_running("mycontainer") is False

    @patch("boxmunge.docker._run", side_effect=DockerError("no such container"))
    def test_returns_false_on_docker_error(self, mock_run):
        assert container_running("nonexistent") is False


class TestCaddyReloadLock:
    """caddy_reload must serialise validate+reload under a flock at lock_dir/.caddy.lock.

    Without the lock, two parallel deploys race: deploy-A passes validate,
    deploy-B writes a malformed site config, deploy-A's reload then fails
    on a config that was valid when checked. The lock turns that into a
    serialised sequence.
    """

    @patch("boxmunge.docker._run")
    def test_creates_lock_file_in_lock_dir(self, mock_run, tmp_path: Path) -> None:
        caddy_dir = tmp_path / "caddy"
        caddy_dir.mkdir()
        lock_dir = tmp_path / "state"

        caddy_reload(caddy_dir, lock_dir)

        assert (lock_dir / ".caddy.lock").exists()

    @patch("boxmunge.docker._run")
    def test_validate_and_reload_both_called(
        self, mock_run, tmp_path: Path
    ) -> None:
        caddy_dir = tmp_path / "caddy"
        caddy_dir.mkdir()
        lock_dir = tmp_path / "state"

        caddy_reload(caddy_dir, lock_dir)

        # First call is validate, second is reload.
        assert mock_run.call_count == 2
        validate_cmd = mock_run.call_args_list[0][0][0]
        reload_cmd = mock_run.call_args_list[1][0][0]
        assert "validate" in validate_cmd
        assert "reload" in reload_cmd

    def test_concurrent_reloads_serialize(self, tmp_path: Path) -> None:
        """When the lock is held externally, caddy_reload blocks until released.

        Holds the lock from a separate thread; starts caddy_reload (with
        _run mocked); confirms it hasn't completed while the lock is held;
        releases the lock; confirms it then completes promptly.
        """
        caddy_dir = tmp_path / "caddy"
        caddy_dir.mkdir()
        lock_dir = tmp_path / "state"
        lock_dir.mkdir()
        lock_path = lock_dir / ".caddy.lock"

        # Externally acquire the lock.
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)

        completed = threading.Event()

        def _do_reload() -> None:
            with patch("boxmunge.docker._run"):
                caddy_reload(caddy_dir, lock_dir)
            completed.set()

        t = threading.Thread(target=_do_reload, daemon=True)
        t.start()

        # While we hold the lock, the reload thread must be blocked.
        assert not completed.wait(timeout=0.3)

        # Release the external lock; reload should now complete.
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

        assert completed.wait(timeout=2.0), "caddy_reload did not unblock after lock release"
        t.join(timeout=1.0)


class TestCaddyValidateTimeout:
    """Audit D-NEW-2: caddy_validate must use a 30s timeout, not the 120s default."""

    def test_validate_constant_is_30s(self) -> None:
        from boxmunge.docker import _CADDY_VALIDATE_TIMEOUT
        assert _CADDY_VALIDATE_TIMEOUT == 30

    @patch("boxmunge.docker._run")
    def test_validate_passes_timeout_to_run(
        self, mock_run, tmp_path: Path,
    ) -> None:
        from boxmunge.docker import caddy_validate, _CADDY_VALIDATE_TIMEOUT
        caddy_validate(tmp_path)
        kwargs = mock_run.call_args.kwargs
        assert kwargs.get("timeout") == _CADDY_VALIDATE_TIMEOUT


class TestCaddyLockContentionLogging:
    """Audit E-NEW-3: caddy reload lock contention >threshold logs a warning.

    The boxmunge logger sets propagate=False once initialised by another
    test, so caplog can't see it via root. Attach a handler directly.
    """

    @staticmethod
    def _attach_capture():
        import logging as _l
        records: list = []

        class _ListHandler(_l.Handler):
            def emit(self, record):  # type: ignore[override]
                records.append(record)

        h = _ListHandler(level=_l.WARNING)
        _l.getLogger("boxmunge").addHandler(h)
        return h, records

    def test_long_wait_logs_warning(self, tmp_path: Path) -> None:
        import logging as _l
        caddy_dir = tmp_path / "caddy"
        caddy_dir.mkdir()
        lock_dir = tmp_path / "state"
        lock_dir.mkdir()
        lock_path = lock_dir / ".caddy.lock"

        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)

        completed = threading.Event()

        def _do_reload() -> None:
            with patch("boxmunge.docker._run"):
                caddy_reload(caddy_dir, lock_dir)
            completed.set()

        h, records = self._attach_capture()
        try:
            t = threading.Thread(target=_do_reload, daemon=True)
            t.start()
            # Hold lock for >0.1s then release.
            time.sleep(0.25)
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            assert completed.wait(timeout=2.0)
            t.join(timeout=1.0)
        finally:
            _l.getLogger("boxmunge").removeHandler(h)

        msgs = [r.getMessage() for r in records]
        assert any("waited" in m and "lock" in m for m in msgs), msgs

    def test_fast_path_no_warning(self, tmp_path: Path) -> None:
        """Happy path (no contention) must not emit lock-wait warnings."""
        import logging as _l
        caddy_dir = tmp_path / "caddy"
        caddy_dir.mkdir()
        lock_dir = tmp_path / "state"
        lock_dir.mkdir()
        h, records = self._attach_capture()
        try:
            with patch("boxmunge.docker._run"):
                caddy_reload(caddy_dir, lock_dir)
        finally:
            _l.getLogger("boxmunge").removeHandler(h)
        msgs = [r.getMessage() for r in records]
        assert not any("waited" in m for m in msgs), msgs


# Captured at import, before tests/conftest.py swaps in its no-Docker stub.
import boxmunge.built_images as _built_images  # noqa: E402
untag_old_built_names = _built_images.untag_old_built_names


class TestUntagOldBuiltNames:
    """Old names come off only images this compose project built (by image
    label, or as the image one of its containers runs), and never off an
    image another project's container, or a project-less one, uses. Nothing
    depends on RepoDigests, which the containerd store sets on local builds."""

    _LABELLED = ("sha256:aaa myapp-web:latest\n"
                 "sha256:aaa myapp-custom:1\n"
                 "sha256:bbb boxmunge.invalid/myapp/web:latest\n"
                 "sha256:ccc vendor/tool:2\n"
                 "sha256:ddd <none>:<none>\n"
                 "sha256:eee myapp-removed:latest\n"
                 "sha256:fff myapp-shared:latest\n")

    def _fake(self, labelled: str, containers: str, every: str = ""):
        import subprocess
        calls: list[list[str]] = []

        def run(cmd, **_kw):
            calls.append(cmd)
            if cmd[:3] == ["docker", "image", "ls"]:
                out = labelled if any(a.startswith("label=") for a in cmd) else every
            elif cmd[:2] == ["docker", "ps"]:
                out = "c1 c2 c3 c4\n" if containers else ""
            elif cmd[:3] == ["docker", "container", "inspect"]:
                out = containers
            else:
                out = ""
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")
        return run, calls

    def _untag(self, run):
        with patch("boxmunge.built_images._run", side_effect=run):
            return untag_old_built_names("myapp", {"web": "myapp-custom:1"}, {"cache", "worker"})

    def test_untags_labelled_builds_and_keeps_images_others_use(self):
        containers = ("sha256:ccc\tvendor/tool:2\tother\n"      # another project, by ID
                      "sha256:zzz\tmyapp-shared\tother\n"       # another project, by name
                      "sha256:eee\tmyapp-removed\t\n")          # no project at all
        run, calls = self._fake(self._LABELLED, containers)
        assert self._untag(run) == ["myapp-web:latest", "myapp-custom:1"]
        assert "label=com.docker.compose.project=myapp" in calls[0]
        assert not any("RepoDigests" in " ".join(c) for c in calls)
        assert calls[-1][:4] == ["docker", "image", "rm", "-f"]

    def test_unlabelled_build_owned_through_this_projects_container(self):
        """Compose 2.38 builds without image labels; containers are labelled."""
        every = ("sha256:aaa myapp-web:latest\n"
                 "sha256:aaa myapp-custom:1\n"
                 "sha256:qqq foo-bar-web:latest\n")      # someone else's, unlabelled
        containers = "sha256:aaa\tmyapp-custom\tmyapp\tweb\n"
        run, _ = self._fake("", containers, every)
        assert self._untag(run) == ["myapp-web:latest", "myapp-custom:1"]

    def test_unlabelled_build_loses_only_the_names_this_project_gave_it(self):
        """A Dockerfile that is just `FROM busybox:1.36`, built by unlabelled
        Compose 2.38, is busybox's own image: only myapp-web goes."""
        every = "sha256:bbx busybox:1.36\nsha256:bbx myapp-web:latest\n"
        containers = "sha256:bbx\tmyapp-web\tmyapp\tweb\n"
        run, _ = self._fake("", containers, every)
        assert self._untag(run) == ["myapp-web:latest"]

    def test_own_image_only_service_protects_an_image(self):
        """This project's `worker` runs the web build by its old name; the
        regenerated overlay has not recreated it yet."""
        labelled = "sha256:aaa myapp-web:latest\n"
        containers = "sha256:aaa\tmyapp-web\tmyapp\tworker\n"
        run, calls = self._fake(labelled, containers)
        assert self._untag(run) == []
        assert not any(c[:3] == ["docker", "image", "rm"] for c in calls)

    def test_leftover_container_of_a_removed_service_protects_nothing(self):
        labelled = "sha256:old myapp-old:latest\n"
        containers = "sha256:old\tmyapp-old\tmyapp\told\n"
        run, _ = self._fake(labelled, containers)
        assert self._untag(run) == ["myapp-old:latest"]

    def test_image_only_services_pulled_image_is_not_owned(self):
        """This project's `cache` service runs alpine:3.20; it was pulled,
        not built, so its name stays."""
        every = "sha256:ppp alpine:3.20\n"
        containers = "sha256:ppp\talpine:3.20\tmyapp\tcache\n"
        run, calls = self._fake("", containers, every)
        assert self._untag(run) == []
        assert not any(c[:3] == ["docker", "image", "rm"] for c in calls)

    def test_with_no_containers_every_labelled_name_goes(self):
        run, _ = self._fake(self._LABELLED, "")
        assert self._untag(run) == ["myapp-web:latest", "myapp-custom:1", "vendor/tool:2",
                                    "myapp-removed:latest", "myapp-shared:latest"]

    def test_nothing_owned_runs_no_removal(self):
        run, calls = self._fake("sha256:bbb boxmunge.invalid/myapp/web:latest\n", "")
        assert self._untag(run) == []
        assert not any(c[:3] == ["docker", "image", "rm"] for c in calls)

    def test_container_gone_since_listing_uses_nothing(self):
        import subprocess

        def run(cmd, **_kw):
            if cmd[:3] == ["docker", "image", "ls"]:
                return subprocess.CompletedProcess(cmd, 0, "sha256:aaa myapp-web:latest\n", "")
            if cmd[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(cmd, 0, "c1 c2\n", "")
            if cmd[:3] == ["docker", "container", "inspect"]:
                return subprocess.CompletedProcess(
                    cmd, 1, "sha256:aaa\tmyapp-web\tother\n", "Error: No such container: c2\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        assert self._untag(run) == []

    def test_other_inspect_errors_fail_loudly(self):
        import subprocess
        from boxmunge.docker_run import DockerError

        def run(cmd, **_kw):
            if cmd[:3] == ["docker", "image", "ls"]:
                return subprocess.CompletedProcess(cmd, 0, "sha256:aaa myapp-web:latest\n", "")
            if cmd[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(cmd, 0, "c1\n", "")
            return subprocess.CompletedProcess(cmd, 1, "", "permission denied\n")
        with pytest.raises(DockerError, match="permission denied"):
            self._untag(run)

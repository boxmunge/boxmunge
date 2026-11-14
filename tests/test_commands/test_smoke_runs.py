# SPDX-License-Identifier: Apache-2.0
"""A smoke run checks every container, tells a smoke it could not launch
from one that ran and failed by whether the script was started, and stops
what it started when it gives up (0.11.6 audit F02, F03, F04).

Each failure is followed to what the health monitor does next: only a
critical verdict takes the project down.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

import boxmunge
from boxmunge import service_exec
from boxmunge.commands.check import run_smoke_in_container
from boxmunge.commands.smoke_result import STARTED, interpret_smoke_result, smoke_command
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state, write_state
from tests.deploy_helpers import mark_deployed

NAME = "myapp"
IMG = "sha256:" + "7" * 64
OK, SLOW, CORRUPT = (0, ""), (1, "queue is slow"), (2, "cannot open database: corruption detected")
RAN = STARTED + "\n"  # stdout of a smoke whose script was started
NO_SH = (127, 'OCI runtime exec failed: exec: "sh": executable file not found in $PATH', "")


class Docker:
    """Stands in for subprocess.run: each container answers its smoke's
    `docker exec` with the (exit, stderr) of its script, with an
    (exit, stderr, stdout) when it is not the script that answers, or raises
    what it is given. The stop answers (exit, stdout, stderr), or with
    "hangs" outlasts its own timeout."""

    def __init__(self, answers: dict[str, object],
                 stop: tuple[int, str, str] | str = (0, "4242\n", "")):
        self.answers, self.stop = answers, stop
        self.smoked: list[str] = []
        self.smokes: list[list[str]] = []
        self.stops: list[list[str]] = []

    def __call__(self, cmd, **_kw):
        if cmd[:2] != ["docker", "exec"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")  # the writable hint's log read
        if service_exec._STOP_SCRIPT in cmd:
            self.stops.append(cmd)
            if self.stop == "hangs":
                raise subprocess.TimeoutExpired(cmd, _kw["timeout"])
            return subprocess.CompletedProcess(cmd, *self.stop)
        [container] = [arg for arg in cmd if arg in self.answers]
        self.smoked.append(container)
        self.smokes.append(cmd)
        answer = self.answers[container]
        if isinstance(answer, BaseException):
            raise answer
        return subprocess.CompletedProcess(cmd, answer[0], *answer[2:] or [RAN], answer[1])


def _manifest(*services: str) -> dict:
    return {"schema_version": 1, "id": "01TEST", "project": NAME, "source": "bundle",
            "hosts": [f"{NAME}.test"],
            "services": {s: {"port": 8080, "smoke": "smoke.sh", "routes": [{"path": f"/{s}"}]}
                         for s in services}}


def _smoke(tmp_path: Path, services: tuple[str, ...], docker: Docker):
    with patch.object(service_exec, "run_bounded", docker):
        return run_smoke_in_container(tmp_path, _manifest(*services), ["compose.yml"])


@pytest.fixture(autouse=True)
def containers(fake_containers):
    """Services `a` and `b` run one container each."""
    for service in ("a", "b"):
        fake_containers.run(NAME, service, IMG)
    return fake_containers


@pytest.fixture
def box(tmp_path: Path) -> BoxPaths:
    """The project deployed on a box, for the health timer's tick."""
    p = BoxPaths(root=tmp_path / "bm")
    for d in ["config", f"projects/{NAME}", "state/deploy", "state/health", "caddy/sites", "logs"]:
        (p.root / d).mkdir(parents=True, exist_ok=True)
    p.config_file.write_text("hostname: t\nadmin_email: a@b\n"
                             "pushover:\n  user_key: u\n  app_token: a\n")
    (p.project_dir(NAME) / "manifest.yml").write_text(yaml.dump(_manifest("a", "b")))
    (p.project_dir(NAME) / "compose.yml").write_text(
        "services:\n  a:\n    image: nginx\n  b:\n    image: nginx\n")
    mark_deployed(p, NAME)
    write_state(p.project_deploy_state(NAME), {
        "current_ref": "r1",
        "last_started_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()})
    return p


def _tick(box: BoxPaths, docker: Docker) -> tuple[int, MagicMock, MagicMock]:
    """One health-timer tick: its status, compose_down and the alert sender."""
    from boxmunge.commands.check_all import run_check_all
    down, push = MagicMock(), MagicMock(return_value=True)
    with patch.object(service_exec, "run_bounded", docker), \
         patch("boxmunge.commands.health_state.compose_down", down), \
         patch("boxmunge.notify.send_notification", push):
        return run_check_all(box, read_only=False), down, push


class TestEveryContainerIsChecked:
    """F02: a warning used to end the run, hiding a critical behind it."""

    def test_a_critical_after_a_warning_is_found(self, tmp_path):
        docker = Docker({f"{NAME}-a-1": SLOW, f"{NAME}-b-1": CORRUPT})
        result = _smoke(tmp_path, ("a", "b"), docker)
        assert docker.smoked == [f"{NAME}-a-1", f"{NAME}-b-1"]
        assert (result.status, result.message) == ("critical", CORRUPT[1])

    def test_a_critical_ends_the_run(self, tmp_path):
        """The other order: nothing after a critical can change the verdict."""
        docker = Docker({f"{NAME}-a-1": SLOW, f"{NAME}-b-1": CORRUPT})
        result = _smoke(tmp_path, ("b", "a"), docker)
        assert docker.smoked == [f"{NAME}-b-1"]
        assert (result.status, result.message) == ("critical", CORRUPT[1])

    def test_a_critical_replica_after_a_warning_one_is_found(self, tmp_path, containers):
        containers.run(NAME, "a", IMG, name=f"{NAME}-a-2")
        docker = Docker({f"{NAME}-a-1": SLOW, f"{NAME}-a-2": CORRUPT, f"{NAME}-b-1": OK})
        result = _smoke(tmp_path, ("a", "b"), docker)
        assert docker.smoked == [f"{NAME}-a-1", f"{NAME}-a-2"]
        assert (result.status, result.message) == ("critical", CORRUPT[1])

    def test_warnings_alone_report_the_first_after_checking_everything(self, tmp_path, containers):
        containers.run(NAME, "a", IMG, name=f"{NAME}-a-2")
        docker = Docker({f"{NAME}-a-1": OK, f"{NAME}-a-2": SLOW,
                         f"{NAME}-b-1": (1, "cache is cold")})
        result = _smoke(tmp_path, ("a", "b"), docker)
        assert docker.smoked == [f"{NAME}-a-1", f"{NAME}-a-2", f"{NAME}-b-1"]
        assert (result.status, result.message) == ("warning", SLOW[1])

    def test_a_service_with_no_container_does_not_hide_a_critical(self, tmp_path, containers):
        containers.remove(NAME)
        containers.run(NAME, "b", IMG)
        result = _smoke(tmp_path, ("a", "b"), Docker({f"{NAME}-b-1": CORRUPT}))
        assert (result.status, result.message) == ("critical", CORRUPT[1])

    def test_the_monitor_stops_a_project_whose_critical_follows_a_warning(self, box):
        status, down, push = _tick(box, Docker({f"{NAME}-a-1": SLOW, f"{NAME}-b-1": CORRUPT}))
        assert status == 2 and down.call_count == 1 and push.call_count == 1
        state = read_state(box.project_health_state(NAME))
        assert (state["status"], state["failure_reason"]) == ("critical_stopped", CORRUPT[1])


class TestLaunchFailureIsToldByWhetherTheScriptStarted:
    """F03: the words on stderr used to turn the app's exit 2 into a warning."""

    @pytest.mark.parametrize("stderr", [
        CORRUPT[1], "upstream is not running", "can't open /data/app.db", "exec failed: migrate",
        "worker is restarting", "no such container in the pool", "oci runtime mismatch",
        "executable file not found: ffmpeg",
    ])
    def test_the_apps_exit_2_is_critical_whatever_it_says(self, stderr):
        result = interpret_smoke_result(2, RAN, stderr)
        assert (result.status, result.message) == ("critical", stderr)

    @pytest.mark.parametrize("status,stderr", [
        NO_SH[:2],
        (126, "OCI runtime exec failed: exec failed: permission denied"),
        (1, "Error response from daemon: No such container: x"),
        (1, "Error response from daemon: container 5f2c is not running"),
        (2, "sh: 0: cannot open /boxmunge-scripts/smoke.sh: No such file"),
    ])
    def test_a_script_that_was_never_started_could_not_run_whatever_the_status(
            self, status, stderr):
        result = interpret_smoke_result(status, "", stderr)
        assert result.status == "warning"
        assert result.message == f"smoke could not run (infrastructure, not app): {stderr}"

    def _run(self, script: Path, service: str = "web") -> subprocess.CompletedProcess:
        return subprocess.run(["sh", "-c", smoke_command(str(script), service)],
                              capture_output=True, text=True, timeout=30)

    def _result(self, ran: subprocess.CompletedProcess):
        return interpret_smoke_result(ran.returncode, ran.stdout, ran.stderr)

    def test_a_script_that_is_not_there_is_never_run_and_never_critical(self, tmp_path):
        """A severed bind mount: `sh` itself exits 2 on a script it cannot open."""
        ran = self._run(tmp_path / "it's gone.sh")
        assert ran.returncode == 127 and "is not in the container" in ran.stderr
        assert self._result(ran).message.startswith("smoke could not run (infrastructure")

    @pytest.mark.parametrize("ends,status", [("no-such-command-here", 127), ("exit 126", 126)])
    def test_the_scripts_own_126_or_127_is_not_called_infrastructure(self, tmp_path, ends, status):
        """Its last command was not found, say: the script ran, and the
        status is its own, where docker's and the missing script's are not."""
        script = tmp_path / "smoke.sh"
        script.write_text(f"echo checking\n{ends}\n")
        ran = self._run(script)
        result = self._result(ran)
        assert ran.returncode == status and result.status == "warning"
        assert "infrastructure" not in result.message
        assert result.message.startswith(f"smoke script ran and exited {status}, as a shell does")

    @pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
    def test_a_script_the_user_cannot_read_is_never_critical(self, tmp_path):
        script = tmp_path / "smoke.sh"
        script.write_text("exit 2\n")
        script.chmod(0o000)
        ran = self._run(script)
        assert ran.returncode == 126 and "is not readable" in ran.stderr
        assert self._result(ran).message.startswith("smoke could not run (infrastructure")

    def test_the_script_gets_the_service_name_and_its_verdict_stands(self, tmp_path):
        script = tmp_path / "smoke script.sh"  # needs no execute bit: sh reads it
        script.write_text('echo "$1: cannot open database: corruption detected" >&2; exit 2\n')
        result = self._result(self._run(script, "web"))
        assert (result.status, result.message) == (
            "critical", "web: cannot open database: corruption detected")

    def test_the_monitor_stops_an_app_whose_critical_names_a_file_it_cannot_open(self, box):
        status, down, _ = _tick(box, Docker({f"{NAME}-a-1": CORRUPT, f"{NAME}-b-1": OK}))
        assert status == 2 and down.call_count == 1
        assert read_state(box.project_health_state(NAME))["status"] == "critical_stopped"

    def test_the_monitor_leaves_running_a_project_whose_smoke_could_not_launch(self, box):
        status, down, _ = _tick(box, Docker({f"{NAME}-a-1": NO_SH, f"{NAME}-b-1": OK}))
        assert status == 1 and down.call_count == 0
        state = read_state(box.project_health_state(NAME))
        assert state["status"] != "critical_stopped"
        assert state["failure_reason"].startswith("smoke could not run (infrastructure, not app)")


class TestAnAbandonedSmokeIsStopped:
    """F04: a timeout killed the docker client and left the smoke running."""

    HUNG = subprocess.TimeoutExpired(cmd="docker", timeout=60)

    @pytest.fixture(autouse=True)
    def _second_replica(self, containers):
        containers.run(NAME, "a", IMG, name=f"{NAME}-a-2")

    def _pid_name(self, cmd: list[str]) -> str:
        [name] = [arg for arg in cmd if arg.startswith("boxmunge-exec-")]
        return name

    def test_a_timed_out_smoke_is_killed_in_its_own_container(self, tmp_path):
        docker = Docker({f"{NAME}-a-1": OK, f"{NAME}-a-2": self.HUNG})
        result = _smoke(tmp_path, ("a",), docker)
        [stop] = docker.stops
        assert stop[:3] == ["docker", "exec", f"{NAME}-a-2"]
        assert self._pid_name(stop) == self._pid_name(docker.smokes[1])
        assert result.status == "warning"
        assert result.message == (f"Smoke test for a timed out (60s) in container {NAME}-a-2 "
                                  "and was stopped there")

    def test_a_timeout_does_not_end_the_run(self, tmp_path):
        docker = Docker({f"{NAME}-a-1": self.HUNG, f"{NAME}-a-2": CORRUPT})
        result = _smoke(tmp_path, ("a",), docker)
        assert docker.smoked == [f"{NAME}-a-1", f"{NAME}-a-2"] and len(docker.stops) == 1
        assert (result.status, result.message) == ("critical", CORRUPT[1])

    def test_a_stop_that_cannot_be_verified_is_said(self, tmp_path):
        docker = Docker({f"{NAME}-a-1": self.HUNG, f"{NAME}-a-2": OK},
                        stop=(1, "", "no record of the command's process group\n"))
        result = _smoke(tmp_path, ("a",), docker)
        assert result.status == "warning"
        assert "timed out (60s)" in result.message
        assert "no record of the command's process group" in result.message
        assert "may still be running" in result.message

    def test_a_stop_that_fails_is_reported_in_the_same_words_every_time(self, tmp_path):
        """The command of a stop that hangs holds its script and a pid file
        name made up for that run, and the monitor alerts again whenever
        the message changes."""
        messages = [
            _smoke(tmp_path, ("a",), Docker({f"{NAME}-a-1": self.HUNG, f"{NAME}-a-2": OK},
                                            stop="hangs")).message
            for _ in range(2)]
        assert messages[0] == messages[1]
        assert messages[0] == (
            f"Smoke test for a timed out (60s) in container {NAME}-a-1 and stopping it there "
            "FAILED (the stop did not finish in 60s), so it may still be running")

    def test_a_refused_pid_record_is_reported_in_the_same_words_every_time(self):
        """The stop script itself, on a record that is not a group id."""
        said = []
        for _ in range(2):
            record = Path("/tmp") / f"boxmunge-exec-{uuid.uuid4().hex}.pid"
            record.write_text("12abc\n")
            try:
                stop = subprocess.run(
                    ["sh", "-c", service_exec._STOP_SCRIPT, "boxmunge-stop", record.name],
                    capture_output=True, text=True, timeout=30)
            finally:
                record.unlink()
            assert stop.returncode == 1 and stop.stdout == ""
            said.append(stop.stderr)
        assert said[0] == said[1] == "the pid record does not hold a process group id\n"

    def test_killed_processes_nothing_reaps_are_said_to_remain(self, tmp_path):
        """A container without an init: the script is dead, its entries stay."""
        docker = Docker({f"{NAME}-a-1": self.HUNG, f"{NAME}-a-2": OK},
                        stop=(0, "4242 unreaped\n", ""))
        result = _smoke(tmp_path, ("a",), docker)
        assert (result.status, result.message) == ("warning", (
            f"Smoke test for a timed out (60s) in container {NAME}-a-1 and was killed there; "
            "its finished process entries remain until the container restarts, because the "
            "container runs without an init process"))

    def test_an_interrupted_smoke_is_killed_before_the_interruption_spreads(self, tmp_path):
        docker = Docker({f"{NAME}-a-1": KeyboardInterrupt(), f"{NAME}-a-2": OK})
        with pytest.raises(KeyboardInterrupt):
            _smoke(tmp_path, ("a",), docker)
        [stop] = docker.stops
        assert stop[:3] == ["docker", "exec", f"{NAME}-a-1"]
        assert docker.smoked == [f"{NAME}-a-1"]

    def test_an_interruption_whose_stop_cannot_be_verified_leaves_a_record(self, tmp_path, caplog):
        docker = Docker({f"{NAME}-a-1": KeyboardInterrupt(), f"{NAME}-a-2": OK},
                        stop=(1, "", "no record of the command's process group\n"))
        with caplog.at_level(logging.WARNING, logger="boxmunge"), \
                pytest.raises(KeyboardInterrupt):
            _smoke(tmp_path, ("a",), docker)
        assert [(r.levelname, r.getMessage()) for r in caplog.records] == [("WARNING", (
            f"A command interrupted in container {NAME}-a-1 may still be running there: "
            "stopping it failed (no record of the command's process group)"))]

    def test_an_interruption_whose_stop_is_verified_says_nothing(self, tmp_path, caplog):
        docker = Docker({f"{NAME}-a-1": KeyboardInterrupt(), f"{NAME}-a-2": OK})
        with caplog.at_level(logging.WARNING, logger="boxmunge"), \
                pytest.raises(KeyboardInterrupt):
            _smoke(tmp_path, ("a",), docker)
        assert caplog.records == []

    def test_every_tick_reports_a_stopped_timeout_in_the_same_words(self, box):
        """The monitor re-alerts when the message changes: a stopped smoke's
        does not carry its process group, which differs on every tick."""
        reasons = []
        for group in ("4242\n", "5151\n"):
            docker = Docker({f"{NAME}-a-1": self.HUNG, f"{NAME}-a-2": OK, f"{NAME}-b-1": OK},
                            stop=(0, group, ""))
            status, down, _ = _tick(box, docker)
            assert status == 1 and down.call_count == 0 and len(docker.stops) == 1
            reasons.append(read_state(box.project_health_state(NAME))["failure_reason"])
        assert reasons[0] == reasons[1] and "was stopped there" in reasons[0]


_SIGTERMED_CHECK = """
import sys
from unittest.mock import patch
import boxmunge.cli
from boxmunge import service_exec
from boxmunge.commands import check

started, stopped = sys.argv[1:]
_rb = service_exec.run_bounded
real_run = lambda cmd, **kw: _rb(cmd, **{"timeout": 30, "keep": 10**5, "budget": 10**7, **kw})
def docker(cmd, **kw):
    if "boxmunge-stop" in cmd:
        open(stopped, "w").write("stopped")
        return real_run(["echo", "42"], capture_output=True, text=True)
    return real_run(["sh", "-c", 'echo started > "$1"; exec sleep 60', "smoke", started], **kw)
def smoke(args):
    check._smoke_one("myapp-web-1", "/boxmunge-scripts/smoke.sh", "web")
with patch.object(service_exec, "run_bounded", side_effect=docker), \\
     patch.dict(boxmunge.cli.COMMANDS, {"check": smoke}), \\
     patch.object(sys, "argv", ["boxmunge-server", "check", "myapp"]):
    boxmunge.cli.main()
"""


def test_sigterm_during_check_stops_the_smoke_in_its_container(tmp_path: Path) -> None:
    """`boxmunge check <project>` stopped by SIGTERM must unwind, as the
    health timer's check-all does, not die with its smoke left running."""
    started, stopped = tmp_path / "started", tmp_path / "stopped"
    proc = subprocess.Popen(
        [sys.executable, "-c", _SIGTERMED_CHECK, str(started), str(stopped)],
        env={**os.environ, "PYTHONPATH": str(Path(boxmunge.__file__).parents[1])},
        stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while not started.exists():
            assert proc.poll() is None and time.monotonic() < deadline, "the smoke never started"
            time.sleep(0.05)
        proc.send_signal(signal.SIGTERM)
        _, err = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == 128 + signal.SIGTERM, err
    assert "stopped by signal 15" in err
    assert stopped.read_text() == "stopped"

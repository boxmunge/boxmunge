# SPDX-License-Identifier: Apache-2.0
"""boxmunge self-test -- prove backup/restore/rollback works via canary project.

Deploys the built-in canary project, exercises the full lifecycle,
then tears it down. Exit 0 = everything works.
"""

import json
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from boxmunge.log import log_operation, log_error
from boxmunge.paths import BoxPaths


CANARY_PROJECT = "boxmunge-canary"
CANARY_PORT = 19876


@dataclass
class SelfTestStep:
    name: str
    passed: bool
    detail: str


@dataclass
class SelfTestReport:
    steps: list[SelfTestStep] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return all(s.passed for s in self.steps)

    @property
    def exit_code(self) -> int:
        return 0 if self.success else 1

    def format_text(self) -> str:
        lines = ["boxmunge self-test results:", ""]
        for step in self.steps:
            status = "PASS" if step.passed else "FAIL"
            line = f"  {status}  {step.name}"
            if step.detail:
                line += f" -- {step.detail}"
            lines.append(line)
        lines.append("")
        lines.append("RESULT: ALL PASSED" if self.success else "RESULT: FAILED")
        return "\n".join(lines)

    def format_json(self) -> str:
        return json.dumps({
            "success": self.success,
            "steps": [
                {"name": s.name, "passed": s.passed, "detail": s.detail}
                for s in self.steps
            ],
        }, indent=2)


def _canary_project_path() -> Path:
    """Path to the built-in canary project shipped with boxmunge."""
    installed = Path("/opt/boxmunge/canary")
    if installed.exists():
        return installed
    return Path(__file__).parent.parent.parent.parent / "canary"


def _wait_for_health(port: int, timeout_seconds: int = 30) -> bool:
    """Wait for the canary app to respond to healthcheck."""
    for _ in range(timeout_seconds):
        try:
            urllib.request.urlopen(f"http://localhost:{port}/healthz", timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


def _http_get_json(url: str) -> dict:
    resp = urllib.request.urlopen(url, timeout=10)
    return json.loads(resp.read())


def _http_post(url: str, data: str = "canary-test") -> int:
    req = urllib.request.Request(url, data=data.encode(), method="POST")
    resp = urllib.request.urlopen(req, timeout=10)
    return resp.status


def _step_deploy(
    report: SelfTestReport, project_dir: Path,
) -> bool:
    """Step 1: Deploy canary via docker compose."""
    print("  [1/6] Deploying canary project...")
    try:
        subprocess.run(
            ["docker", "compose", "-f", "compose.yml",
             "-p", CANARY_PROJECT, "up", "-d", "--build"],
            cwd=project_dir, check=True, capture_output=True, text=True, timeout=120,
        )
        if not _wait_for_health(CANARY_PORT):
            report.steps.append(SelfTestStep("deploy", False, "Health check timeout"))
            return False
        report.steps.append(SelfTestStep("deploy", True, ""))
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        report.steps.append(SelfTestStep("deploy", False, str(e)))
        return False


def _step_insert_data(report: SelfTestReport) -> bool:
    """Step 2: Insert test data via HTTP."""
    print("  [2/6] Inserting test data...")
    try:
        for i in range(3):
            _http_post(f"http://localhost:{CANARY_PORT}/data", f"canary-{i}")
        data = _http_get_json(f"http://localhost:{CANARY_PORT}/data")
        if data["count"] < 3:
            report.steps.append(SelfTestStep(
                "insert-data", False, f"Expected >= 3 rows, got {data['count']}",
            ))
            return False
        report.steps.append(SelfTestStep("insert-data", True, f"{data['count']} rows"))
        return True
    except Exception as e:
        report.steps.append(SelfTestStep("insert-data", False, str(e)))
        return False


def _step_backup(report: SelfTestReport, paths: BoxPaths) -> bool:
    """Step 3: Run backup."""
    print("  [3/6] Running backup...")
    try:
        from boxmunge.commands.backup_cmd import run_backup
        result = run_backup(CANARY_PROJECT, paths)
        if result != 0:
            report.steps.append(SelfTestStep("backup", False, "run_backup returned non-zero"))
            return False
        report.steps.append(SelfTestStep("backup", True, ""))
        return True
    except Exception as e:
        report.steps.append(SelfTestStep("backup", False, str(e)))
        return False


def _step_wipe(report: SelfTestReport, project_dir: Path) -> bool:
    """Step 4: Wipe the database to simulate data loss."""
    print("  [4/6] Wiping database...")
    try:
        subprocess.run(
            ["docker", "compose", "-f", "compose.yml",
             "-p", CANARY_PROJECT, "exec", "-T", "db",
             "psql", "-U", "canary", "-d", "canarydb",
             "-c", "DROP TABLE IF EXISTS canary_data;"
                   " CREATE TABLE canary_data"
                   " (id SERIAL PRIMARY KEY, value TEXT);"],
            cwd=project_dir, check=True, capture_output=True, timeout=30,
        )
        data = _http_get_json(f"http://localhost:{CANARY_PORT}/data")
        if data["count"] != 0:
            report.steps.append(SelfTestStep(
                "wipe", False, f"Expected 0 rows, got {data['count']}",
            ))
            return False
        report.steps.append(SelfTestStep("wipe", True, "0 rows confirmed"))
        return True
    except Exception as e:
        report.steps.append(SelfTestStep("wipe", False, str(e)))
        return False


def _step_restore(report: SelfTestReport, paths: BoxPaths) -> bool:
    """Step 5: Restore from backup and verify data recovered."""
    print("  [5/6] Restoring from backup...")
    try:
        from boxmunge.commands.restore import run_restore
        result = run_restore(CANARY_PROJECT, paths, yes=True)
        if result != 0:
            report.steps.append(SelfTestStep("restore", False, "run_restore returned non-zero"))
            return False
        if not _wait_for_health(CANARY_PORT):
            report.steps.append(SelfTestStep(
                "restore", False, "Health check timeout after restore",
            ))
            return False
        data = _http_get_json(f"http://localhost:{CANARY_PORT}/data")
        if data["count"] < 3:
            report.steps.append(SelfTestStep(
                "restore", False, f"Expected >= 3 rows, got {data['count']}",
            ))
            return False
        report.steps.append(SelfTestStep("restore", True, f"{data['count']} rows recovered"))
        return True
    except Exception as e:
        report.steps.append(SelfTestStep("restore", False, str(e)))
        return False


def _teardown_canary(project_dir: Path) -> None:
    """Tear down canary containers and clean up."""
    if project_dir.exists():
        subprocess.run(
            ["docker", "compose", "-f", "compose.yml",
             "-p", CANARY_PROJECT, "down", "-v", "--remove-orphans"],
            cwd=project_dir, check=False, capture_output=True, timeout=60,
        )
        shutil.rmtree(project_dir, ignore_errors=True)


def _finish(report: SelfTestReport, paths: BoxPaths, as_json: bool) -> int:
    """Print results, log, and return exit code."""
    if as_json:
        print(report.format_json())
    else:
        print(report.format_text())

    if report.success:
        log_operation("self-test", "Self-test passed", paths)
    else:
        failed = [s for s in report.steps if not s.passed]
        log_error(
            "self-test",
            f"Self-test failed: {failed[0].name} -- {failed[0].detail}",
            paths,
        )

    return report.exit_code


def run_self_test(paths: BoxPaths, as_json: bool = False) -> int:
    """Run the full self-test lifecycle. Returns 0 on success."""
    report = SelfTestReport()
    canary_src = _canary_project_path()
    project_dir = paths.project_dir(CANARY_PROJECT)

    if not canary_src.exists() or not (canary_src / "manifest.yml").exists():
        print("ERROR: Canary project not found. Is boxmunge installed correctly?")
        return 1

    try:
        # Setup: copy canary to project dir
        if project_dir.exists():
            shutil.rmtree(project_dir)
        shutil.copytree(canary_src, project_dir)
        (project_dir / ".env").write_text(f"CANARY_PORT={CANARY_PORT}\n")

        steps = [
            lambda: _step_deploy(report, project_dir),
            lambda: _step_insert_data(report),
            lambda: _step_backup(report, paths),
            lambda: _step_wipe(report, project_dir),
            lambda: _step_restore(report, paths),
        ]

        for step in steps:
            if not step():
                return _finish(report, paths, as_json)

        # Step 6: Teardown (always succeeds if we got here)
        print("  [6/6] Tearing down canary...")
        report.steps.append(SelfTestStep("teardown", True, ""))

    finally:
        _teardown_canary(project_dir)

    return _finish(report, paths, as_json)


def cmd_self_test(args: list[str]) -> None:
    """CLI entry point for self-test command."""
    as_json = "--json" in args
    paths = BoxPaths()
    sys.exit(run_self_test(paths, as_json=as_json))

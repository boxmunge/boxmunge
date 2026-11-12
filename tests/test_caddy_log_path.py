# SPDX-License-Identifier: Apache-2.0
"""bootstrap/caddy-log-path.sh: install.sh refuses an existing box whose Caddy
configs write a log under /var/log/caddy, before it changes anything.

Caddy's container has no such path from 0.11.7 on (a read-only root, nothing
mounted there), so Caddy would stop at config load once recreated. Releases
0.11.0 to 0.11.6 mounted a tmpfs there, so a hand-written log block passed
their validation. The check goes when the upgrade floor reaches 0.11.7.

#105: it reads what Caddy imports (caddy/sites/*.conf), the pending journal
entries and the project overrides, not all of caddy/sites, where an
operator's TLS key that deploy cannot read made grep fail.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "caddy-log-path.sh"
LOG_BLOCK = "    log {\n        output file /var/log/caddy/other.log\n    }\n"
not_as_root = pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")


@pytest.fixture
def box(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "bm"
    (root / "caddy" / "sites").mkdir(parents=True)
    (root / "caddy" / ".site-journal").mkdir()
    (root / "projects" / "app").mkdir(parents=True)
    # runuser stand-in: run the command as this user.
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    runuser = fakebin / "runuser"
    runuser.write_text('#!/usr/bin/env bash\n[[ "$1 $2 $3" == "-u deploy --" ]] || exit 64\n'
                       'shift 3\nexec "$@"\n')
    runuser.chmod(0o755)
    return root, fakebin


def _check(box: tuple[Path, Path]) -> subprocess.CompletedProcess:
    root, fakebin = box
    env = {**os.environ, "BOXMUNGE_ROOT": str(root), "PATH": f"{fakebin}:{os.environ['PATH']}"}
    return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True,
                          timeout=60, stdin=subprocess.DEVNULL, check=False)


def _unreadable(path: Path, text: str = "key material") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0)
    return path


def test_a_box_with_no_caddy_config_passes_without_a_deploy_user(tmp_path: Path) -> None:
    result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, check=False,
                            env={"BOXMUNGE_ROOT": str(tmp_path), "PATH": "/usr/bin:/bin"})
    assert (result.returncode, result.stderr) == (0, "")


def test_configs_that_log_to_stdout_pass(box: tuple[Path, Path]) -> None:
    root, _ = box
    stdout_block = "app.example.com {\n    log {\n        output stdout\n    }\n}\n"
    (root / "caddy" / "sites" / "app.conf").write_text(stdout_block)
    (root / "caddy" / ".site-journal" / "app.conf.json").write_text(
        json.dumps({"path": "x", "previous": stdout_block, "written": stdout_block}))
    (root / "projects" / "app" / "caddy.override.conf").write_text("    encode gzip\n")
    result = _check(box)
    assert (result.returncode, result.stderr) == (0, "")


@pytest.mark.parametrize("where", [
    "caddy/sites/app.conf", "caddy/.site-journal/app.conf.json", "projects/app/caddy.override.conf",
])
def test_a_config_that_logs_under_var_log_caddy_is_refused(box: tuple[Path, Path], where: str) -> None:
    root, _ = box
    text = LOG_BLOCK
    if where.endswith(".json"):
        text = json.dumps({"path": "x", "previous": text, "written": text})
    (root / where).write_text(text)
    (root / "caddy" / "sites" / "fine.conf").write_text("fine.example.com {\n}\n")
    result = _check(box)
    assert result.returncode == 1
    assert f"         {root / where}\n" in result.stderr
    assert "fine.conf" not in result.stderr
    assert "Nothing was changed" in result.stderr
    assert "`output stdout`" in result.stderr
    # The way back for an upgrade this stopped: the shim blocklisted the release.
    assert f"sudo {root}/bin/boxmunge-upgrade clear-blocklist <that release>" in result.stderr


@not_as_root
def test_a_check_that_cannot_run_is_an_error_not_a_pass(box: tuple[Path, Path]) -> None:
    """Caddy imports the file, so the check cannot pass it unread."""
    root, _ = box
    _unreadable(root / "caddy" / "sites" / "app.conf", LOG_BLOCK)
    result = _check(box)
    assert result.returncode == 1
    assert "could not check the Caddy configs" in result.stderr
    assert "Nothing was changed" in result.stderr
    assert f"sudo {root}/bin/boxmunge-upgrade clear-blocklist <that release>" in result.stderr


def test_a_deploy_user_that_cannot_run_the_check_is_an_error(box: tuple[Path, Path]) -> None:
    root, fakebin = box
    (root / "caddy" / "sites" / "app.conf").write_text("app.example.com {\n}\n")
    (fakebin / "runuser").write_text("#!/usr/bin/env bash\necho 'runuser: user deploy does not exist' >&2\nexit 125\n")
    result = _check(box)
    assert result.returncode == 1
    assert "could not check the Caddy configs" in result.stderr and "125" in result.stderr


@not_as_root
def test_an_unreadable_file_beside_the_configs_is_not_read(box: tuple[Path, Path]) -> None:
    root, _ = box
    sites = root / "caddy" / "sites"
    (sites / "app.conf").write_text("app.example.com {\n    tls /etc/caddy/sites/tls/origin.pem\n}\n")
    _unreadable(sites / "tls" / "origin.key")
    _unreadable(sites / "notes.txt")
    result = _check(box)
    assert result.returncode == 0, result.stderr


@not_as_root
@pytest.mark.parametrize("where", [
    "caddy/sites/planted.conf", "caddy/.site-journal/planted.json", "projects/app/caddy.override.conf",
])
def test_a_link_is_not_followed(box: tuple[Path, Path], tmp_path: Path, where: str) -> None:
    root, _ = box
    (root / where).symlink_to(_unreadable(tmp_path / "victim", LOG_BLOCK))
    result = _check(box)
    assert result.returncode == 0, result.stderr


def test_install_sh_checks_an_existing_box_before_it_changes_anything() -> None:
    install = (REPO / "install.sh").read_text()
    call = '    BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" bash "${SCRIPT_DIR}/bootstrap/caddy-log-path.sh"\n'
    check = install.index(call)
    # Only on an existing box: a fresh install has no deploy user to read as.
    block = install.rindex('if [[ -f "${BOXMUNGE_ROOT}/config/boxmunge.yml" ]]; then\n', 0, check)
    assert "\nfi\n" not in install[block:check]
    assert install.index('bootstrap/upgrade-floor.sh"\n') < check
    for first_change in ("\nremove_dead_crowdsec_repo\n", "\nensure_install_prereqs\n",
                         "bootstrap/init-host.sh"):
        assert check < install.index(first_change)

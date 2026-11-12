# SPDX-License-Identifier: Apache-2.0
"""bootstrap/unresolved-stage.sh: install.sh run by hand refuses an existing
box where a project still holds a release that boxmunge 0.10.1 or earlier
staged, before it changes anything.

This release has no `legacy-stage` command, so once it is installed nothing
on the box resolves such a stage. An upgrade is refused in the shim's
pre-flight (tests/test_unresolved_stage.py); this is the same detector for
`sudo bash install.sh`. It runs from the bundle's src/ on the host's python3
with no site-packages, before the package is installed. The check goes when
the upgrade floor reaches 0.11.7.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from boxmunge import unresolved_stage_install
from boxmunge.commands import upgrade_steps
from boxmunge.paths import BoxPaths

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "bootstrap" / "unresolved-stage.sh"
BASH = shutil.which("bash") or "/bin/bash"
PYTHON3 = f'#!/bin/sh\nexec "{sys.executable}" "$@"\n'
# Stands in for a python3 that cannot run the check; a run that reaches it fails.
BROKEN_PYTHON3 = "#!/bin/sh\necho 'Traceback: boom' >&2\nexit 1\n"


@pytest.fixture
def box(tmp_path: Path) -> Path:
    root = tmp_path / "bm"
    for d in ("config", "projects", "state"):
        (root / d).mkdir(parents=True)
    _runs(root, "0.11.6+abc1234")
    return root


def _runs(root: Path, version: str) -> None:
    (root / "config" / "version").write_text(f"{version}\n")


def _project(root: Path, name: str, *, staged: str | None = None) -> Path:
    """A deployed project; `staged` is the kind of stage its directory holds."""
    pdir = root / "projects" / name
    (pdir / ".releases").mkdir(parents=True)
    (pdir / "manifest.yml").write_text(f"project: {name}\n")
    (pdir / ".releases" / "live.json").write_text("{}\n")
    if staged == "bundle":
        (pdir / ".releases" / "prestage").mkdir()
    elif staged == "leftover":
        (pdir / "compose.staging-base.yml").write_text("services: {}\n")
    elif staged == "pre0101":
        (pdir / "compose.staging-base.yml").write_text("services: {}\n")
        (pdir / ".releases" / "live.json").unlink()
    return pdir


def _install(root: Path, tmp_path: Path, *, shim: str | None = "0", python3: str | None = PYTHON3,
             script: Path = SCRIPT) -> subprocess.CompletedProcess:
    """Run the check as install.sh does, with `python3` the only python on PATH."""
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    (fakebin / "dirname").symlink_to(shutil.which("dirname"))
    if python3 is not None:
        (fakebin / "python3").write_text(python3)
        (fakebin / "python3").chmod(0o755)
    env = {"BOXMUNGE_ROOT": str(root), "PATH": str(fakebin)}
    if shim is not None:
        env["FROM_UPGRADE_SHIM"] = shim
    return subprocess.run([BASH, str(script)], env=env, capture_output=True, text=True,
                          timeout=60, stdin=subprocess.DEVNULL, check=False, cwd=tmp_path)


def _tree(root: Path) -> dict[str, bytes | None]:
    return {str(p.relative_to(root)): p.read_bytes() if p.is_file() else None
            for p in sorted(root.rglob("*"))}


def test_a_box_with_no_stage_passes(box: Path, tmp_path: Path) -> None:
    _project(box, "shop")
    result = _install(box, tmp_path)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


@pytest.mark.parametrize(("kind", "by"), [
    ("bundle", "boxmunge 0.10.1"), ("leftover", "boxmunge 0.10.1"),
    ("pre0101", "a boxmunge release before 0.10.1"),
])
def test_a_box_holding_a_stage_is_refused(box: Path, tmp_path: Path, kind: str, by: str) -> None:
    _project(box, "shop", staged=kind)
    _project(box, "blog")
    before = _tree(box)
    result = _install(box, tmp_path)
    assert result.returncode == 1
    assert result.stderr.startswith("ERROR: this install is refused. Nothing was changed.\n")
    assert "1 project (shop) holds a release that boxmunge 0.10.1 or earlier" in result.stderr
    assert "On this box, on the release it runs now (boxmunge 0.11.6):\n" in result.stderr
    # The stage kind, and the command the release the box runs accepts.
    assert (f"  - shop: a release staged by {by} is unresolved ({kind}); run `boxmunge-server "
            f"legacy-stage shop` and take one of the choices it shows\n") in result.stderr
    assert result.stderr.endswith("\nThen run the install again.\n")
    assert "blog" not in result.stderr and "retry the upgrade" not in result.stderr
    # Read-only, and no alert or log entry: whoever runs install.sh reads the terminal.
    assert _tree(box) == before


def test_every_project_that_holds_one_is_named(box: Path, tmp_path: Path) -> None:
    _project(box, "shop", staged="bundle")
    _project(box, "wiki", staged="pre0101")
    result = _install(box, tmp_path)
    assert result.returncode == 1
    assert "2 projects (shop, wiki) hold " in result.stderr
    assert "  - shop: " in result.stderr and "  - wiki: " in result.stderr


def test_a_box_below_0_11_6_is_sent_to_0_11_6_first(box: Path, tmp_path: Path) -> None:
    _runs(box, "0.11.1")
    _project(box, "shop", staged="pre0101")
    result = _install(box, tmp_path)
    assert result.returncode == 1
    assert "`sudo /opt/boxmunge/bin/boxmunge-upgrade target 0.11.6`" in result.stderr
    assert "Then, on 0.11.6:\n  - shop: " in result.stderr
    assert result.stderr.endswith("\nThen run the install again.\n")


def test_the_upgrade_shim_s_install_is_not_checked(box: Path, tmp_path: Path) -> None:
    """The shim's pre-flight (the upgrade's dry run) has already refused such a box."""
    _project(box, "shop", staged="bundle")
    result = _install(box, tmp_path, shim="1", python3=BROKEN_PYTHON3)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


@pytest.mark.parametrize("version", ["0.11.7", "0.11.7+abc1234", "0.12.0"])
def test_a_box_on_0_11_7_or_later_is_not_checked(box: Path, tmp_path: Path, version: str) -> None:
    """Such a box holds none; what looks like one is not this check's to read."""
    _runs(box, version)
    _project(box, "shop", staged="bundle")
    result = _install(box, tmp_path)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


def test_state_that_cannot_be_read_is_refused(box: Path, tmp_path: Path) -> None:
    _project(box, "shop")
    (box / "state" / "legacy-stages.json").write_text("not json")
    result = _install(box, tmp_path)
    assert result.returncode == 1
    assert "Nothing was changed" in result.stderr
    assert "Cannot tell which projects hold a release" in result.stderr
    assert result.stderr.endswith("then run the install again.\n")


def test_a_python3_that_fails_is_an_error_not_a_pass(box: Path, tmp_path: Path) -> None:
    result = _install(box, tmp_path, python3=BROKEN_PYTHON3)
    assert result.returncode == 1
    assert "Traceback: boom" in result.stderr
    assert "could not check this box" in result.stderr and "(python3 exit 1)" in result.stderr
    assert "Nothing was changed" in result.stderr and "run the install again" in result.stderr


def test_a_host_with_no_python3_is_an_error_not_a_pass(box: Path, tmp_path: Path) -> None:
    result = _install(box, tmp_path, python3=None)
    assert result.returncode == 1
    assert "python3" in result.stderr and "not found" in result.stderr
    assert "could not check this box" in result.stderr and "(python3 exit 127)" in result.stderr


def test_a_bundle_without_the_detector_is_an_error_not_a_pass(box: Path, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "bootstrap").mkdir(parents=True)
    (bundle / "src").mkdir()
    script = bundle / "bootstrap" / SCRIPT.name
    shutil.copy(SCRIPT, script)
    result = _install(box, tmp_path, script=script)
    assert result.returncode == 1
    assert "ModuleNotFoundError" in result.stderr and "could not check this box" in result.stderr


def test_a_projects_directory_that_cannot_be_listed_is_an_error(box: Path, tmp_path: Path) -> None:
    (box / "projects").rmdir()
    (box / "projects").write_text("not a directory")
    result = _install(box, tmp_path)
    assert result.returncode == 1
    assert "NotADirectoryError" in result.stderr and "could not check this box" in result.stderr


def test_install_sh_must_say_whether_the_shim_runs_it(box: Path, tmp_path: Path) -> None:
    result = _install(box, tmp_path, shim=None)
    assert result.returncode != 0 and "FROM_UPGRADE_SHIM" in result.stderr


def test_the_detector_loads_nothing_outside_the_standard_library_and_src() -> None:
    """It runs before the package is installed: no venv, no site-packages (-S)."""
    code = ("import sys\nsys.path.insert(0, sys.argv[1])\n"
            "import boxmunge.unresolved_stage_install\n"
            "print(*sorted(m for m in sys.modules if m.startswith('boxmunge')))\n"
            "print(*sorted(f for m in sys.modules.values()\n"
            "              if 'site-packages' in (f := getattr(m, '__file__', None) or '')))\n")
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code, str(REPO / "src")],
                            capture_output=True, text=True, timeout=60, check=True)
    loaded, outside = result.stdout.split("\n")[:2]
    assert loaded.split() == [
        "boxmunge", "boxmunge.fs_nofollow", "boxmunge.paths", "boxmunge.release_selection",
        "boxmunge.unresolved_stage", "boxmunge.unresolved_stage_install", "boxmunge.version"]
    assert outside == ""


def test_it_checks_the_projects_an_upgrade_checks(
        box: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(box, "shop")
    _project(box, "blog")
    (box / "projects" / "no-manifest").mkdir()
    (box / "projects" / "a-file").write_text("")
    _project(box, "shop-staging")  # a reserved name: the upgrade reports it and carries on
    (box / "projects" / "gitproj").mkdir()
    (box / "projects" / "gitproj" / "manifest.yml").symlink_to("repo/manifest.yml")  # dangling
    paths = BoxPaths(root=box)
    monkeypatch.setattr(upgrade_steps, "report_project_failure", lambda *a, **k: None)
    names = unresolved_stage_install.project_names(paths)
    assert names == [d.name for d in upgrade_steps._project_dirs(paths)]
    assert names == ["blog", "gitproj", "shop"]


def test_a_box_with_no_projects_directory_has_no_projects(tmp_path: Path) -> None:
    assert unresolved_stage_install.project_names(BoxPaths(root=tmp_path)) == []


def test_install_sh_checks_an_existing_box_before_it_changes_anything() -> None:
    install = (REPO / "install.sh").read_text()
    call = ('    FROM_UPGRADE_SHIM="${FROM_UPGRADE_SHIM}" BOXMUNGE_ROOT="${BOXMUNGE_ROOT}" \\\n'
            '        bash "${SCRIPT_DIR}/bootstrap/unresolved-stage.sh"\n')
    check = install.index(call)
    block = install.rindex('if [[ -f "${BOXMUNGE_ROOT}/config/boxmunge.yml" ]]; then\n', 0, check)
    assert "\nfi\n" not in install[block:check]
    # After the floors: the box runs 0.11.0 or later, and its python3 runs this release.
    floors = [install.index(f'bootstrap/{name}-floor.sh"\n') for name in ("upgrade", "python")]
    assert floors[0] < floors[1] < check
    for first_change in ("\nremove_dead_crowdsec_repo\n", "\nensure_install_prereqs\n",
                         "bootstrap/init-host.sh"):
        assert check < install.index(first_change)

# SPDX-License-Identifier: Apache-2.0
"""boxmunge-system must run an image built from the definition installed in
system/. A rebuild that failed under the upgrade shim leaves the previous
image (its Alpine, age and rclone) running: health and doctor warn, naming
the rebuild, instead of reporting it healthy. A warning, not an error: health
exit 2 rolls back a platform upgrade in probation, and backups still work."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

import boxmunge.system_container as sc
from boxmunge.commands.doctor import run_doctor
from boxmunge.commands.health_cmd import check_system_container
from boxmunge.paths import BoxPaths

REPO = Path(__file__).resolve().parents[1]


def test_the_definition_is_the_sha256_of_dockerfile_then_compose(paths: BoxPaths) -> None:
    paths.system.mkdir(parents=True, exist_ok=True)
    (paths.system / "Dockerfile").write_bytes(b"FROM x\n")
    (paths.system / "compose.yml").write_bytes(b"services: {}\n")
    assert sc.system_definition(paths) == hashlib.sha256(b"FROM x\nservices: {}\n").hexdigest()


def test_the_compose_file_labels_the_image_with_it() -> None:
    compose = yaml.safe_load((REPO / "system" / "compose.yml").read_text())
    labels = compose["services"]["system"]["build"]["labels"]
    assert labels == {sc.DEFINITION_LABEL: "${BOXMUNGE_SYSTEM_DEFINITION:-}"}


def test_an_image_built_from_the_installed_definition_is_current(paths, system_container) -> None:
    assert sc.stale_image(paths) is None
    assert check_system_container(paths).status == "ok"


def test_an_image_from_another_definition_warns_with_the_rebuild(paths, system_container) -> None:
    system_container.inspect["Config"]["Labels"][sc.DEFINITION_LABEL] = "0" * 64
    problem = sc.stale_image(paths)
    assert problem and f"sudo docker compose -f {paths.system_compose} up -d --build" in problem
    check = check_system_container(paths)
    assert (check.status, check.detail) == ("warn", problem)


def test_an_image_without_the_label_is_stale(paths, system_container) -> None:
    del system_container.inspect["Config"]["Labels"][sc.DEFINITION_LABEL]
    assert check_system_container(paths).status == "warn"


def test_a_missing_definition_names_the_installer(paths, system_container) -> None:
    (paths.system / "Dockerfile").unlink()
    problem = sc.stale_image(paths)
    assert problem and "installer" in problem
    assert check_system_container(paths).status == "warn"


@pytest.mark.usefixtures("docker_down")
def test_doctor_warns_on_a_stale_image(paths, system_container, capsys) -> None:
    system_container.inspect["Config"]["Labels"][sc.DEFINITION_LABEL] = "0" * 64
    run_doctor(paths, as_json=True)
    out = capsys.readouterr().out
    assert '"WARN"' in out and "up -d --build" in out


def test_the_fake_container_installs_the_repo_definition(paths, system_container) -> None:
    for name in ("Dockerfile", "compose.yml"):
        assert (paths.system / name).read_bytes() == (REPO / "system" / name).read_bytes()

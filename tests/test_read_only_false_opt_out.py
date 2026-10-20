"""The documented `read_only: false` opt-out reaches the overlay and the CVE penalty.

`docker compose config --format json` (Compose 5.1.3) drops `read_only: false`
and keeps only `read_only: true`, so the resolved model cannot show the
opt-out. The canned config below drops it the same way; the real command is
covered in tests/integration/test_compose_resolve.py.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from boxmunge import docker
from boxmunge.commands import security_scan_inputs
from boxmunge.commands.security_scan_inputs import ProjectMeta
from boxmunge.compose import generate_compose_override, load_user_compose
from boxmunge.compose_resolve import ComposeResolveError, declared_read_only
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.cve import hardening
from boxmunge.cve.hardening import calculate_hardening_penalty
from boxmunge.cve.policy import parse_posture
from boxmunge.paths import BoxPaths


def _compose_config_like_docker(monkeypatch) -> None:
    """Stand in for `docker compose config`: the literal file with its
    zero-value `read_only: false` left out, as Compose omits it."""
    def fake(project_dir, compose_files=None, *, project_name, **_kw):
        doc = yaml.safe_load((Path(project_dir) / compose_files[0]).read_text())
        for svc in doc["services"].values():
            if svc.get("read_only") is False:
                del svc["read_only"]
        return json.dumps(doc)
    monkeypatch.setattr(docker, "compose_config", fake)


@pytest.fixture
def paths(tmp_path: Path) -> BoxPaths:
    return BoxPaths(root=tmp_path / "bm")


def _compose(paths: BoxPaths, text: str) -> Path:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "compose.yml").write_text(text)
    return project_dir / "compose.yml"


MANIFEST = {"project": "myapp", "services": {
    "db": {"internal": True}, "web": {"port": 80, "routes": [{"path": "/"}]}}}


def _overlay_services(paths: BoxPaths, compose: Path) -> dict:
    user_compose = load_user_compose(compose, "myapp")
    return yaml.safe_load(generate_compose_override(
        MANIFEST, user_compose=user_compose))["services"]


def test_manifest_service_read_only_false_gets_no_overlay_read_only(monkeypatch, paths) -> None:
    _compose_config_like_docker(monkeypatch)
    compose = _compose(paths, "services:\n  db:\n    image: postgres:16\n    read_only: false\n"
                              "  web:\n    image: nginx\n")
    services = _overlay_services(paths, compose)
    assert "read_only" not in services["db"]
    assert services["web"]["read_only"] is True  # undeclared: baseline applies


def test_read_only_true_and_absent_behave_as_before(monkeypatch, paths) -> None:
    _compose_config_like_docker(monkeypatch)
    compose = _compose(paths, "services:\n  db:\n    image: postgres:16\n    read_only: true\n"
                              "  web:\n    image: nginx\n")
    services = _overlay_services(paths, compose)
    assert "read_only" not in services["db"]  # the user's true already says it
    assert services["web"]["read_only"] is True


def test_load_user_compose_restores_the_dropped_false(monkeypatch, paths) -> None:
    _compose_config_like_docker(monkeypatch)
    compose = _compose(paths, "services:\n  db:\n    image: postgres:16\n    read_only: false\n")
    assert load_user_compose(compose, "myapp")["services"]["db"]["read_only"] is False


@pytest.mark.parametrize("value", ["${RO}", "${RO:-false}", "'false'", "0", "no-such"])
def test_interpolated_or_non_boolean_read_only_is_refused(monkeypatch, paths, value) -> None:
    _compose_config_like_docker(monkeypatch)
    compose = _compose(paths, f"services:\n  db:\n    image: postgres:16\n    read_only: {value}\n")
    with pytest.raises(ComposeResolveError, match="not a boolean"):
        declared_read_only(compose)
    with pytest.raises(ComposeSecurityError, match="not a boolean"):
        validate_user_compose(compose, paths, project_name="myapp")


def test_unparseable_raw_file_fails_noisily(paths) -> None:
    compose = _compose(paths, "services: [\n")
    with pytest.raises(ComposeResolveError, match="as written"):
        declared_read_only(compose)


def test_service_without_the_key_is_not_declared(paths) -> None:
    # A service defined through extends/include has no key in this file.
    compose = _compose(paths, "services:\n  db:\n    extends: {file: base.yml, service: db}\n")
    assert declared_read_only(compose) == {}


# --- the CVE hardening calculator, fed through the real loader ---

def _meta() -> ProjectMeta:
    return ProjectMeta(manifest=MANIFEST, posture_str="balanced",
                       posture=parse_posture("balanced"), dangerously=False,
                       declared_runtimes=None, hosts=[], compose_files=["compose.yml"])


@pytest.mark.parametrize("enforced", [False, True], ids=["legacy", "strict"])
def test_explicit_read_only_false_is_a_penalty(monkeypatch, paths, enforced) -> None:
    _compose_config_like_docker(monkeypatch)
    monkeypatch.setattr(hardening, "STRICT_HARDENING_PENALTY_ENFORCED", enforced)
    _compose(paths, "services:\n  db:\n    image: postgres:16\n    read_only: false\n"
                    "  web:\n    image: nginx\n")
    model = security_scan_inputs.load_user_model(paths, "myapp")
    profile = security_scan_inputs.hardening_profile(_meta(), model).applied
    assert not profile.read_only
    assert calculate_hardening_penalty(profile) == 1


@pytest.mark.parametrize("enforced", [False, True], ids=["legacy", "strict"])
def test_absent_and_true_read_only_carry_no_penalty(monkeypatch, paths, enforced) -> None:
    _compose_config_like_docker(monkeypatch)
    monkeypatch.setattr(hardening, "STRICT_HARDENING_PENALTY_ENFORCED", enforced)
    _compose(paths, "services:\n  db:\n    image: postgres:16\n    read_only: true\n"
                    "  web:\n    image: nginx\n")
    model = security_scan_inputs.load_user_model(paths, "myapp")
    profile = security_scan_inputs.hardening_profile(_meta(), model).applied
    assert profile.read_only

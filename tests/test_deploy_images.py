"""Build/pull, inspect and the image-directory probe (no Docker)."""
from __future__ import annotations

import io
import tarfile

import pytest

from boxmunge.commands import deploy_images as di
from boxmunge.docker_containers import ImageFacts
from boxmunge.image_probe import ProbeError, first_header_owner
from boxmunge.release_target import (
    DeployRefused, ReleaseTarget, production_target, staging_release_target,
)
from boxmunge.staged_release import ComposeTarget

S = 1048576


def _tar(uid: int, gid: int, mode: int = 0o750) -> io.BytesIO:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("data")
        info.type, info.uid, info.gid, info.mode = tarfile.DIRTYPE, uid, gid, mode
        tar.addfile(info)
    buf.seek(0)
    return buf


def test_header_ids_are_translated_to_the_container_view() -> None:
    owner = first_header_owner(_tar(S + 1000, S + 1001), S)
    assert (owner.uid, owner.gid, owner.mode, owner.is_dir) == (1000, 1001, 0o750, True)


def test_unremapped_box_uses_ids_as_they_are() -> None:
    assert first_header_owner(_tar(70, 70), 0).uid == 70


def test_an_empty_stream_means_the_path_is_absent() -> None:
    assert first_header_owner(io.BytesIO(b""), S) is None


@pytest.mark.parametrize("uid", [5, S + 65536, 2 * S])
def test_an_id_outside_the_remap_range_is_refused(uid) -> None:
    with pytest.raises(ProbeError, match="outside the remap range"):
        first_header_owner(_tar(uid, S), S)


def _calls(monkeypatch) -> list:
    calls: list = []
    monkeypatch.setattr(di, "_run", lambda cmd, **kw: calls.append((cmd, kw)))
    return calls


def test_build_and_pull_names_services_and_pulls_only_missing(paths, monkeypatch) -> None:
    calls = _calls(monkeypatch)
    di.build_and_pull(production_target(paths, "app"), {
        "web": {"build": {"context": "."}, "image": "boxmunge.invalid/app/web"},
        "db": {"image": "postgres:16"},
        "side": {"image": "boxmunge.invalid/app/web"},
    })
    (build, kw), (pull, _) = calls
    assert build[-4:] == ["--profile", "*", "build", "web"]
    assert pull[-5:] == ["pull", "--ignore-buildable", "--policy", "missing", "db"]
    assert "--profile" in pull and kw["cwd"] == paths.project_dir("app")


def test_staging_target_passes_project_directory_and_env_file(tmp_path, monkeypatch) -> None:
    calls = _calls(monkeypatch)
    target = ReleaseTarget("app", ComposeTarget(
        cwd=tmp_path / "rel", project_name="app-staging", files=["/s/base.yml", "/s/over.yml"],
        project_directory=tmp_path / "rel", env_file=tmp_path / "rel" / ".env"), staging=True)
    di.build_and_pull(target, {"db": {"image": "postgres:16"}})
    cmd = calls[0][0]
    assert cmd[cmd.index("--project-directory") + 1] == str(tmp_path / "rel")
    assert cmd[cmd.index("--env-file") + 1] == str(tmp_path / "rel" / ".env")


def test_the_staging_target_is_the_slot(paths) -> None:
    target = staging_release_target(paths, "app")
    assert target.staging and target.compose_project == "app-staging"
    assert target.compose.project_directory.name == "release"


def test_every_service_needing_a_declaration_is_listed() -> None:
    facts = {n: ImageFacts("sha256:" + "a" * 64, "", ()) for n in ("db", "cache", "web")}
    services = {"db": {"image": "postgres:16"}, "cache": {"image": "redis:7"},
                "web": {"build": ".", "image": "boxmunge.invalid/shop/web"}}
    with pytest.raises(DeployRefused) as e:
        di.decide_users(services, facts, {"project": "shop", "services": {"web": {}}})
    assert len(e.value.problems) == 3 and "merge" in e.value.problems[2]
    assert "redis:7" in e.value.problems[0] and "postgres:16" in e.value.problems[1]

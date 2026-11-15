# SPDX-License-Identifier: Apache-2.0
"""The patch builder, against a fake Docker: what it builds, from what, and
when it refuses. The Docker tier (tests/integration/test_autofix_build_docker.py)
builds real Debian and Alpine images."""
from __future__ import annotations

import json
import subprocess

import pytest

from boxmunge import docker, docker_containers
from boxmunge.cve import autofix_build as ab
from boxmunge.cve.autofix_build import (
    NotPatchable, Patchable, PatchBuildError, build_patched, probe, render_dockerfile,
)
from boxmunge.docker_run import DockerError
from boxmunge.image_pins import ImagePin, pin_ref

_BASE_ID = "sha256:" + "a" * 64
_PATCHED_ID = "sha256:" + "b" * 64
_PULLED = "registry.example.test/shop/web@sha256:" + "c" * 64
_LAYERS = ["sha256:" + "1" * 64]


def _done(cmd: list[str], rc: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(cmd, rc, out, err)


class FakeDocker:
    """Answers the docker commands the builder makes, recording them."""

    def __init__(self, *, user: str = "app", labels: dict | None = None,
                 verdicts: str = "ok", tags: list[str] | None = None,
                 probe_rc: int = 0, probe_out: str = "apt\n") -> None:
        self.images: dict[str, dict] = {}
        base = {"Id": _BASE_ID, "RepoTags": tags or [], "RepoDigests": [_PULLED],
                "Config": {"User": user, "Labels": labels}, "RootFS": {"Layers": _LAYERS}}
        for ref in (_BASE_ID, _PULLED):
            self.images[ref] = base
        self.verdicts, self.probe_rc, self.probe_out = verdicts, probe_rc, probe_out
        self.calls: list[list[str]] = []
        self.dockerfile: str | None = None
        self.fail_rm: set[str] = set()

    def __call__(self, cmd, cwd=None, capture=False, check=True, timeout=120, input=None):
        self.calls.append(cmd)
        assert cmd[0] == "docker"
        verb = cmd[1:3]
        if verb == ["image", "inspect"]:
            doc = self.images.get(cmd[3])
            if doc is None:
                return self._fail(cmd, check, f"Error: No such image: {cmd[3]}")
            return _done(cmd, out=json.dumps([doc]))
        if cmd[1] == "build":
            assert cmd[-1] == "-" and capture and input is not None
            self.dockerfile = input
            return self._build(cmd)
        if verb == ["image", "ls"]:
            return _done(cmd, out="".join(f"{r}\n" for r in self.images
                                          if r.split(":", 1)[0] == cmd[-1]))
        if cmd[1] == "run":
            script = cmd[cmd.index("-c") + 1]
            if "command -v" in script:
                return _done(cmd, self.probe_rc, self.probe_out,
                             "exec: \"/bin/sh\": stat /bin/sh: no such file or directory")
            pkgs = cmd[cmd.index("-c") + 3::2]
            return _done(cmd, out="".join(f"{p}\t9.9-1\t{self.verdicts}\n" for p in pkgs))
        if cmd[1] == "tag":
            self.images[cmd[3]] = self.images[cmd[2]]
            return _done(cmd)
        if verb == ["image", "rm"]:
            if cmd[3] in self.fail_rm:
                raise DockerError(f"cannot remove {cmd[3]}")
            doc = self.images.pop(cmd[3])
            if not [r for r, d in self.images.items() if d is doc and not r.startswith("sha256:")]:
                self.images = {r: d for r, d in self.images.items() if d is not doc}
            return _done(cmd)
        raise AssertionError(f"unexpected docker command {cmd}")

    def _fail(self, cmd, check, err):
        if check:
            raise DockerError(err)
        return _done(cmd, 1, "", err)

    def _build(self, cmd):
        label = json.loads(self.dockerfile.split(f"LABEL {ab.BASE_LABEL}=", 1)[1].split("\n")[0])
        self.images[cmd[cmd.index("-t") + 1]] = self.images[_PATCHED_ID] = {
            "Id": _PATCHED_ID, "RepoTags": [], "RepoDigests": [],
            "Config": {"User": "app", "Labels": {ab.BASE_LABEL: label}},
            "RootFS": {"Layers": [*_LAYERS, "sha256:" + "2" * 64]}}
        return _done(cmd)


@pytest.fixture
def fake(monkeypatch) -> FakeDocker:
    def install(**kw) -> FakeDocker:
        f = FakeDocker(**kw)
        for module in (ab, docker, docker_containers):
            monkeypatch.setattr(module, "_run", f)
        return f
    return install


_APT = Patchable(manager="apt", user="app")
_APK = Patchable(manager="apk", user="app")


def test_dockerfile_upgrades_only_named_packages() -> None:
    apt = render_dockerfile(_PULLED, _APT, {"openssl": "3.0.15-1", "libssl3": "3.0.15-1"})
    runs = [line for line in apt.splitlines() if line.startswith("RUN")]
    assert len(runs) == 1
    (script,) = json.loads(runs[0][len("RUN "):])[2:]
    assert "--no-remove --only-upgrade libssl3 openssl &&" in script
    assert "apt-get upgrade" not in script and "dist-upgrade" not in script
    assert script.endswith("rm -rf /var/lib/apt/lists/*")
    assert apt.splitlines()[0] == f"FROM {_PULLED}"

    apk = render_dockerfile(_PULLED, _APK, {"busybox": "1.36.1-r20"})
    (run,) = [line for line in apk.splitlines() if line.startswith("RUN")]
    assert json.loads(run[len("RUN "):]) == ["/bin/sh", "-c",
                                                 "apk upgrade --no-cache --no-self-upgrade busybox"]


def test_original_user_restored() -> None:
    lines = render_dockerfile(_PULLED, Patchable("apt", "1000:1000"), {"curl": "8"}).splitlines()
    assert lines[1] == "USER 0:0" and lines[-1] == "USER 1000:1000"
    root = render_dockerfile(_PULLED, Patchable("apk", ""), {"curl": "8"}).splitlines()
    assert not [line for line in root if line.startswith("USER")]


@pytest.mark.parametrize("name", ["", "-oDebug::pkgProblemResolver=1", "a b", "x;rm", "A\n"])
def test_rejects_a_package_name_that_is_not_one(name: str) -> None:
    with pytest.raises(PatchBuildError, match="package name"):
        render_dockerfile(_PULLED, _APT, {name: "1"})


def test_rejects_no_packages() -> None:
    with pytest.raises(PatchBuildError, match="no packages"):
        render_dockerfile(_PULLED, _APT, {})


def test_refuses_a_patched_base(fake) -> None:
    f = fake()
    patched = f"{pin_ref('shop', 'web', _PATCHED_ID)}"
    with pytest.raises(PatchBuildError, match="already a patched image"):
        build_patched("shop", "web", patched, {"curl": "8"}, _APT)
    f = fake(labels={ab.BASE_LABEL: _PULLED})
    with pytest.raises(PatchBuildError, match="already a patched image"):
        build_patched("shop", "web", _BASE_ID, {"curl": "8"}, _APT)
    f = fake(tags=[pin_ref("shop", "web", _BASE_ID)])
    with pytest.raises(PatchBuildError, match="already a patched image"):
        build_patched("shop", "web", _BASE_ID, {"curl": "8"}, _APT)
    assert not [c for c in f.calls if c[1] == "build"]


@pytest.mark.parametrize("ref", ["registry.example.test/shop/web:1.2", "sha256:abc"])
def test_refuses_a_base_not_at_a_digest(fake, ref: str) -> None:
    fake()
    with pytest.raises(PatchBuildError, match="exact digest"):
        build_patched("shop", "web", ref, {"curl": "8"}, _APT)


def test_version_check_failure_names_package(fake) -> None:
    f = fake(verdicts="low")
    with pytest.raises(PatchBuildError, match=r"openssl 9\.9-1 is below the fixed 3\.0\.15"):
        build_patched("shop", "web", _PULLED, {"openssl": "3.0.15-1"}, _APT)
    assert not [ref for ref in f.images if ref.startswith("boxmunge.invalid/")]


def test_a_version_the_distro_cannot_compare_fails_the_build(fake) -> None:
    fake(verdicts="error")
    with pytest.raises(PatchBuildError, match="curl 9.9-1 cannot be compared with the fixed 8"):
        build_patched("shop", "web", _PULLED, {"curl": "8"}, _APT)


def test_crash_debris_names_do_not_make_a_base_patched(fake) -> None:
    fake(tags=["boxmunge.invalid/shop/web:autofix-base-0123456789abcdef"])
    assert build_patched("shop", "web", _BASE_ID, {"curl": "8"}, _APT).image_id == \
        _PATCHED_ID


def test_a_package_the_image_lacks_fails_the_build(fake, monkeypatch) -> None:
    f = fake()
    real = f.__call__

    def missing(cmd, **kw):
        if cmd[1] == "run" and "command -v" not in cmd[cmd.index("-c") + 1]:
            return _done(cmd, out="")
        return real(cmd, **kw)
    for module in (ab, docker, docker_containers):
        monkeypatch.setattr(module, "_run", missing)
    with pytest.raises(PatchBuildError, match="curl is not installed"):
        build_patched("shop", "web", _PULLED, {"curl": "8"}, _APT)


def test_builds_tags_by_image_id_and_cleans_up(fake, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    f = fake()
    patched = build_patched("shop", "web", _PULLED, {"curl": "8.5-1"}, _APT)
    assert patched.image_id == _PATCHED_ID
    assert patched.ref == pin_ref("shop", "web", _PATCHED_ID)
    assert patched.versions == {"curl": "9.9-1"}
    ImagePin("web", patched.ref, patched.image_id, "autofix")  # a valid pin
    assert [ref for ref in f.images if ref.startswith("boxmunge.invalid/")] == [patched.ref]
    build = next(c for c in f.calls if c[1] == "build")
    assert build == ["docker", "build", "--no-cache", "-t", build[4], "-"]
    assert list(tmp_path.iterdir()) == []   # nothing is written anywhere
    assert f"LABEL {ab.BASE_LABEL}=\"{_PULLED}\"" in (f.dockerfile or "")


def test_a_built_base_is_built_from_by_a_temporary_name(fake) -> None:
    f = fake()
    build_patched("shop", "web", _BASE_ID, {"curl": "8"}, _APT)
    first = (f.dockerfile or "").splitlines()[0]
    assert first.startswith("FROM boxmunge.invalid/shop/web:autofix-base-")
    assert first[len("FROM "):] not in f.images


def test_refuses_an_image_not_built_on_the_base(fake, monkeypatch) -> None:
    f = fake()
    real_build = f._build

    def other_layers(cmd):
        out = real_build(cmd)
        f.images[cmd[cmd.index("-t") + 1]]["RootFS"] = {"Layers": ["sha256:" + "9" * 64]}
        return out
    monkeypatch.setattr(f, "_build", other_layers)
    with pytest.raises(PatchBuildError, match="not built on"):
        build_patched("shop", "web", _PULLED, {"curl": "8"}, _APT)
    assert not [ref for ref in f.images if ref.startswith("boxmunge.invalid/")]


def test_a_cleanup_failure_does_not_mask_the_build_error(fake) -> None:
    f = fake(verdicts="low")
    real_build = f._build

    def build(cmd):
        f.fail_rm.add(cmd[cmd.index("-t") + 1])
        return real_build(cmd)
    f._build = build
    with pytest.raises(PatchBuildError, match="below the fixed") as raised:
        build_patched("shop", "web", _BASE_ID, {"curl": "8"}, _APT)
    assert any("cleanup could not remove" in n for n in raised.value.__notes__)
    assert not [r for r in f.images if ":autofix-base-" in r]   # still removed


def test_a_cleanup_failure_alone_is_raised(fake) -> None:
    f = fake()
    real_build = f._build

    def build(cmd):
        f.fail_rm.add(cmd[cmd.index("-t") + 1])
        return real_build(cmd)
    f._build = build
    with pytest.raises(PatchBuildError, match="cleanup could not remove"):
        build_patched("shop", "web", _PULLED, {"curl": "8"}, _APT)


def test_build_sweeps_only_its_own_leftover_names(fake) -> None:
    f = fake()
    keep = ["boxmunge.invalid/shop/web:autofix-build-0123456789abcde",   # 15 hex
            "boxmunge.invalid/shop/web:autofix-0123456789ab",
            "boxmunge.invalid/shop/web:latest",
            "boxmunge.invalid/shop/api:autofix-base-0123456789abcdef",
            "boxmunge.invalid/shop-staging/web:autofix-base-0123456789abcdef"]
    gone = ["boxmunge.invalid/shop/web:autofix-build-0123456789abcdef",
            "boxmunge.invalid/shop/web:autofix-base-fedcba9876543210"]
    for ref in keep + gone:
        f.images[ref] = {**f.images[_BASE_ID]}
    build_patched("shop", "web", _PULLED, {"curl": "8"}, _APT)
    assert all(ref in f.images for ref in keep)
    assert not [ref for ref in gone if ref in f.images]


def test_patchability_must_describe_the_base(fake) -> None:
    fake(user="")
    with pytest.raises(PatchBuildError, match="user"):
        build_patched("shop", "web", _PULLED, {"curl": "8"}, _APT)


def test_probe_finds_the_package_manager(fake) -> None:
    f = fake(probe_out="apk\n")
    assert probe(_PULLED) == Patchable(manager="apk", user="app")
    run = next(c for c in f.calls if c[1] == "run")
    for flag in (["--network", "none"], ["--entrypoint", "/bin/sh"], ["--user", "0:0"],
                 ["--pids-limit", "64"], ["--memory", "256m"]):
        i = run.index(flag[0])
        assert run[i:i + 2] == flag
    assert "--rm" in run and "--no-healthcheck" in run and run[run.index("--pull") + 1] == "never"


def test_probe_no_shell_is_not_patchable(fake) -> None:
    fake(probe_rc=127, probe_out="")
    assert probe(_PULLED) == NotPatchable("no shell or package manager in the image")


def test_probe_unsupported_package_manager(fake) -> None:
    fake(probe_out="none\n")
    result = probe(_PULLED)
    assert isinstance(result, NotPatchable) and "apk or apt" in result.reason


def test_probe_user_that_cannot_be_restored(fake) -> None:
    fake(user="$APP_USER")
    result = probe(_PULLED)
    assert isinstance(result, NotPatchable) and "$APP_USER" in result.reason


def test_probe_docker_failure_is_noisy(fake) -> None:
    fake(probe_rc=125, probe_out="")
    with pytest.raises(DockerError):
        probe(_PULLED)


def test_remove_patched_goes_by_the_stored_ref(fake) -> None:
    f = fake()
    ref = pin_ref("shop", "web", _PATCHED_ID)
    f.images[ref] = {**f.images[_BASE_ID], "Id": _PATCHED_ID}
    ab.remove_patched(ImagePin("web", ref, _PATCHED_ID, "autofix"))
    assert ref not in f.images
    f.images[ref] = f.images[_BASE_ID]
    with pytest.raises(PatchBuildError, match="names another image"):
        ab.remove_patched(ImagePin("web", ref, _PATCHED_ID, "autofix"))

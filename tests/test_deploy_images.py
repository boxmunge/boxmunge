"""Build/pull, inspect and the image-directory probe (no Docker)."""
from __future__ import annotations

import pytest

from boxmunge.commands import deploy_build, deploy_images as di
from boxmunge.docker_containers import ImageFacts
from boxmunge.docker_run import DockerError
from boxmunge.release_target import (
    DeployRefused, ReleaseTarget, production_target, staging_release_target,
)
from boxmunge.staged_release import ComposeTarget

S = 1048576


def _calls(monkeypatch) -> list:
    calls: list = []
    record = lambda cmd, **kw: calls.append((cmd, kw))  # noqa: E731
    monkeypatch.setattr(di, "_run", record)
    monkeypatch.setattr(deploy_build, "_run", record)
    return calls


def _compose(paths, text: str = "services:\n  web:\n    build: .\n") -> None:
    pdir = paths.project_dir("app")
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "compose.yml").write_text(text)


def test_build_and_pull_names_services_and_pulls_only_missing(paths, monkeypatch) -> None:
    calls = _calls(monkeypatch)
    di.build_and_pull(production_target(paths, "app"), {
        "web": {"build": {"context": "."}, "image": "boxmunge.invalid/app/web"},
        "db": {"image": "postgres:16"},
        "side": {"image": "boxmunge.invalid/app/web"},
    }, pull=False)
    (build, kw), (pull, _) = calls
    assert build[-4:] == ["--profile", "*", "build", "web"]
    assert pull[-5:] == ["pull", "--ignore-buildable", "--policy", "missing", "db"]
    assert "--profile" in pull and kw["cwd"] == paths.project_dir("app")


def test_a_pulling_build_asks_for_each_base_images_current_digest(paths, monkeypatch) -> None:
    calls = _calls(monkeypatch)
    _compose(paths)
    di.build_and_pull(production_target(paths, "app"),
                      {"web": {"build": ".", "image": "boxmunge.invalid/app/web"}}, pull=True)
    assert calls[0][0][-3:] == ["build", "--pull", "web"]


_UNREADABLE = ("Command failed: docker compose build --pull web\nfailed to solve: "
               "registry.example/base:1: failed to resolve source metadata for "
               "registry.example/base:1: failed to do request: dial tcp: i/o timeout")


def _failing_build(monkeypatch, message: str) -> None:
    def run(cmd, **kw):
        raise DockerError(message)
    monkeypatch.setattr(deploy_build, "_run", run)


def test_an_unreadable_base_registry_fails_naming_no_pull(paths, monkeypatch) -> None:
    _compose(paths)
    _failing_build(monkeypatch, _UNREADABLE)
    with pytest.raises(DockerError) as e:
        di.build_and_pull(production_target(paths, "app"),
                          {"web": {"build": ".", "image": "boxmunge.invalid/app/web"}},
                          pull=True)
    text = str(e.value)
    assert "--no-pull" in text and "i/o timeout" in text and "docker image ls" in text
    assert "build: {pull: false}" in text and "no such image" in text


def test_a_build_that_sets_pull_false_is_built_apart_without_pull(paths, monkeypatch) -> None:
    """Its FROM may name an image only this box has; compose's CLI --pull
    would override its own `pull: false`."""
    calls = _calls(monkeypatch)
    _compose(paths, "services:\n  web:\n    build: .\n"
                    "  tool:\n    build:\n      context: .\n      pull: false\n")
    services = {n: {"build": ".", "image": f"boxmunge.invalid/app/{n}"} for n in ("web", "tool")}
    di.build_and_pull(production_target(paths, "app"), services, pull=True)
    assert [c[0][-3:] for c in calls] == [["build", "--pull", "web"], ["*", "build", "tool"]]
    calls.clear()
    di.build_and_pull(production_target(paths, "app"), services, pull=False)
    assert [c[0][-3:] for c in calls] == [["build", "tool", "web"]]


@pytest.mark.parametrize("pull, message", [
    (True, "failed to solve: process \"/bin/sh -c make\" did not complete"),
    (False, _UNREADABLE),  # --no-pull cannot help a build that did not pull
])
def test_other_build_failures_are_not_blamed_on_the_pull(paths, monkeypatch, pull,
                                                         message) -> None:
    _compose(paths)
    _failing_build(monkeypatch, message)
    with pytest.raises(DockerError) as e:
        di.build_and_pull(production_target(paths, "app"),
                          {"web": {"build": ".", "image": "boxmunge.invalid/app/web"}},
                          pull=pull)
    assert str(e.value) == message


def test_staging_target_passes_project_directory_and_env_file(tmp_path, monkeypatch) -> None:
    calls = _calls(monkeypatch)
    target = ReleaseTarget("app", ComposeTarget(
        cwd=tmp_path / "rel", project_name="app-staging", files=["/s/base.yml", "/s/over.yml"],
        project_directory=tmp_path / "rel", env_file=tmp_path / "rel" / ".env"), staging=True)
    di.build_and_pull(target, {"db": {"image": "postgres:16"}}, pull=True)
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


def test_a_git_projects_compose_link_into_its_checkout_is_read(paths) -> None:
    pdir = paths.project_dir("app")
    (pdir / "repo").mkdir(parents=True)
    (pdir / "repo" / "compose.yml").write_text(
        "services:\n  tool:\n    build:\n      context: .\n      pull: false\n")
    (pdir / "compose.yml").symlink_to("repo/compose.yml")
    assert deploy_build.local_base_builds(production_target(paths, "app")) == {"tool"}


def test_pull_false_in_an_included_file_counts(paths) -> None:
    """Read as the reference walk follows include: (compose_references)."""
    _compose(paths, "include:\n  - parts/tools.yml\nservices:\n  web:\n    build: .\n")
    (paths.project_dir("app") / "parts").mkdir()
    (paths.project_dir("app") / "parts" / "tools.yml").write_text(
        "services:\n  tool:\n    build:\n      context: .\n      pull: false\n")
    assert deploy_build.local_base_builds(production_target(paths, "app")) == {"tool"}


def test_unreadable_compose_files_refuse_the_deploy(paths) -> None:
    _compose(paths, "include:\n  - parts/missing.yml\nservices: {}\n")
    with pytest.raises(DeployRefused, match="build.pull: false"):
        deploy_build.local_base_builds(production_target(paths, "app"))


@pytest.mark.parametrize("contexts", ["{tools: 'service:tool'}", "['tools=service:tool']"])
def test_a_build_on_a_pull_false_service_is_local_too(paths, contexts) -> None:
    """A pulling build would build its `service:` context again, with --pull."""
    _compose(paths, "services:\n  tool:\n    build:\n      context: .\n      pull: false\n"
                    f"  web:\n    build:\n      context: .\n      additional_contexts: {contexts}\n"
                    "  other:\n    build: .\n")
    assert deploy_build.local_base_builds(production_target(paths, "app")) == {"tool", "web"}


def test_a_pull_false_build_on_a_pulling_service_context_is_refused(paths, monkeypatch) -> None:
    """Building `web` without --pull would build its `service:` context
    `tool` again from the local image store, over the pulled build, on the
    stale base: refused before anything is built, naming both services."""
    calls = _calls(monkeypatch)
    _compose(paths, "services:\n  tool:\n    build: .\n"
                    "  web:\n    build:\n      context: .\n      pull: false\n"
                    "      additional_contexts: {tools: 'service:tool'}\n")
    services = {n: {"build": ".", "image": f"boxmunge.invalid/app/{n}"} for n in ("web", "tool")}
    with pytest.raises(DeployRefused) as e:
        di.build_and_pull(production_target(paths, "app"), services, pull=True)
    assert calls == []
    text = " ".join(e.value.problems)
    assert "'web'" in text and "'tool'" in text
    assert "pull: false" in text and "--no-pull" in text
    di.build_and_pull(production_target(paths, "app"), services, pull=False)
    assert [c[0][-3:] for c in calls] == [["build", "tool", "web"]]


def test_compose_yml_pull_true_beats_pull_false_in_the_file_it_extends(paths) -> None:
    """Compose merges an extended build key by key, the extending file
    winning, so an explicit pull: true in compose.yml stands."""
    _compose(paths, "services:\n  web:\n    extends: {file: base.yml, service: web}\n"
                    "    build:\n      pull: true\n"
                    "  api:\n    extends: {file: base.yml, service: common}\n"
                    "    build:\n      pull: false\n")
    (paths.project_dir("app") / "base.yml").write_text(
        "services:\n  web:\n    build:\n      context: .\n      pull: false\n"
        "  common:\n    build:\n      context: .\n      pull: true\n")
    assert deploy_build.local_base_builds(production_target(paths, "app")) == {"api"}


def test_pull_false_is_inherited_through_extends_under_another_name(paths) -> None:
    _compose(paths, "services:\n  api:\n    extends: base\n"
                    "  base:\n    build:\n      context: .\n      pull: false\n"
                    "  web:\n    extends: {file: parts/more.yml, service: tool}\n")
    (paths.project_dir("app") / "parts").mkdir()
    (paths.project_dir("app") / "parts" / "more.yml").write_text(
        "services:\n  tool:\n    build:\n      context: .\n      pull: false\n"
        "  unused:\n    build:\n      context: .\n      pull: false\n")
    assert deploy_build.local_base_builds(production_target(paths, "app")) == {
        "api", "base", "web"}


def test_each_compose_file_is_read_once(paths, monkeypatch) -> None:
    from pathlib import Path
    _compose(paths, "include:\n  - parts/tools.yml\nservices:\n  web:\n    build: .\n")
    (paths.project_dir("app") / "parts").mkdir()
    (paths.project_dir("app") / "parts" / "tools.yml").write_text(
        "services:\n  tool:\n    build:\n      context: .\n      pull: false\n")
    reads: list[str] = []
    real = Path.read_text
    monkeypatch.setattr(Path, "read_text",
                        lambda self, *a, **kw: reads.append(self.name) or real(self, *a, **kw))
    deploy_build.local_base_builds(production_target(paths, "app"))
    assert sorted(reads) == ["compose.yml", "tools.yml"]


def test_a_build_local_only_through_its_context_says_so(paths, monkeypatch) -> None:
    """`web` sets no pull: it builds locally because it builds on `tool`;
    naming build.pull: false for it would send the operator looking for
    a setting that is not there."""
    _calls(monkeypatch)
    _compose(paths, "services:\n  tool:\n    build:\n      context: .\n      pull: false\n"
                    "  base:\n    build: .\n"
                    "  web:\n    build:\n      context: .\n      additional_contexts:\n"
                    "        tools: 'service:tool'\n        base: 'service:base'\n")
    with pytest.raises(DeployRefused) as e:
        deploy_build.local_base_builds(production_target(paths, "app"))
    [problem] = e.value.problems
    assert "'web' builds from the local image store because it builds on 'tool'" in problem
    assert "build.pull: false" not in problem.split(" but ")[0]


@pytest.mark.parametrize("text, words", [
    ("services:\n  web: null\n", "service 'web' is not a mapping"),
    ("services:\n  web:\n    extends: base\n", "service 'base' is extended but not defined"),
])
def test_a_broken_service_definition_is_named_as_it_is(paths, text, words) -> None:
    _compose(paths, text)
    with pytest.raises(DeployRefused, match=words):
        deploy_build.local_base_builds(production_target(paths, "app"))

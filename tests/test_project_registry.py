"""Tests for project registry — allowlist of known project names."""

import fcntl
import os
import threading
import time

import pytest

from boxmunge.paths import BoxPaths


class TestProjectRegistry:
    def test_load_empty_returns_empty_set(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import load_registered_projects
        result = load_registered_projects(paths)
        assert result == set()

    def test_add_project(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, load_registered_projects
        add_project("myapp", paths)
        assert "myapp" in load_registered_projects(paths)

    def test_add_duplicate_is_idempotent(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, load_registered_projects
        add_project("myapp", paths)
        add_project("myapp", paths)
        projects = load_registered_projects(paths)
        assert "myapp" in projects

    def test_remove_project(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, remove_project, load_registered_projects
        add_project("myapp", paths)
        remove_project("myapp", paths)
        assert "myapp" not in load_registered_projects(paths)

    def test_remove_nonexistent_raises(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import remove_project
        with pytest.raises(ValueError, match="not registered"):
            remove_project("ghost", paths)

    def test_is_registered(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, is_registered
        assert not is_registered("myapp", paths)
        add_project("myapp", paths)
        assert is_registered("myapp", paths)

    def test_validates_project_name(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project
        with pytest.raises(ValueError, match="Invalid project name"):
            add_project("BAD NAME!", paths)

    def test_auto_migrate_from_existing_dirs(self, paths: BoxPaths) -> None:
        """If projects.txt doesn't exist but project dirs do, auto-populate."""
        from boxmunge.project_registry import load_registered_projects
        for name in ["alpha", "beta"]:
            proj = paths.projects / name
            proj.mkdir(parents=True)
            (proj / "manifest.yml").write_text(f"project: {name}\n")
        result = load_registered_projects(paths)
        assert result == {"alpha", "beta"}
        assert (paths.state / "projects.txt").exists()

    def test_auto_migrate_ignores_pre_registered_dirs(self, paths: BoxPaths) -> None:
        """Dirs without manifest.yml are pre-registered (secrets-only), skip them."""
        from boxmunge.project_registry import load_registered_projects
        proj = paths.projects / "secrets-only"
        proj.mkdir(parents=True)
        result = load_registered_projects(paths)
        assert result == set()


class TestProjectRegistryConcurrency:
    """4d (audit D-2b): add_project / remove_project must serialise.

    Without the flock, two concurrent add_project calls can each load the
    same set, mutate locally, and race to save — losing one of the additions.
    """

    def test_concurrent_adds_do_not_lose_writes(self, paths: BoxPaths) -> None:
        """An add_project call must block while the registry lock is held
        elsewhere, then complete and produce a consistent on-disk result."""
        from boxmunge.project_registry import add_project, load_registered_projects

        # Manually grab the registry flock to simulate another writer mid-flight.
        lock_path = paths.state / ".registry.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)

        completed = threading.Event()

        def add_in_thread() -> None:
            add_project("alpha", paths)
            completed.set()

        t = threading.Thread(target=add_in_thread, daemon=True)
        t.start()

        # Give the thread a window to attempt the add. Because the flock is
        # held externally, add_project must block — completed.set() must NOT
        # fire within this window.
        time.sleep(0.2)
        assert not completed.is_set(), (
            "add_project did not block while the registry lock was held"
        )

        # Release the lock; the thread should proceed and finish promptly.
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

        t.join(timeout=2.0)
        assert completed.is_set(), "add_project did not complete after lock release"
        assert "alpha" in load_registered_projects(paths)

    def test_parallel_adds_all_persisted(self, paths: BoxPaths) -> None:
        """Many threaded add_project calls must all land in the registry —
        no lost-update race."""
        from boxmunge.project_registry import add_project, load_registered_projects

        names = [f"proj{i:02d}" for i in range(20)]
        threads = [
            threading.Thread(target=add_project, args=(n, paths), daemon=True)
            for n in names
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        registered = load_registered_projects(paths)
        assert set(names) <= registered, (
            f"Lost adds: missing {set(names) - registered}"
        )


def test_deployed_projects_skip_registered_but_never_deployed(paths: BoxPaths) -> None:
    """The nightly scan and the cve-scan health check walk this list; a
    project registered ahead of its first deploy has nothing to scan and
    must not be reported as a failed scan every night."""
    from boxmunge.project_registry import add_project, deployed_among, read_registry
    for name in ("live", "pending"):
        add_project(name, paths)
    live = paths.project_dir("live")
    live.mkdir(parents=True)
    (live / "manifest.yml").write_text("project: live\n")
    paths.project_dir("pending").mkdir(parents=True)
    assert deployed_among(read_registry(paths).names, paths) == ["live"]


def test_nightly_scan_targets_only_deployed_projects(paths: BoxPaths) -> None:
    from boxmunge.commands.security_actions import _parse_scan_targets
    from boxmunge.project_registry import add_project
    add_project("pending", paths)
    add_project("live", paths)
    (paths.project_dir("live")).mkdir(parents=True)
    (paths.project_dir("live") / "manifest.yml").write_text("project: live\n")
    assert _parse_scan_targets([], paths) == (["live"], ())


class TestDamagedRegistry:
    """projects.txt is deploy-writable: any line can hold anything, and a line
    registered before its name was reserved (`x-staging`) is one too. A bad
    line never stops a valid project, and is never silently dropped."""

    @pytest.mark.parametrize("bad", ["../etc", "BAD NAME", "caddy", "foo-staging", "a/b"])
    def test_listing_names_the_file_and_line(self, paths: BoxPaths, bad) -> None:
        from boxmunge.project_registry import ProjectRegistryError, load_registered_projects
        registry = paths.state / "projects.txt"
        registry.write_text(f"alpha\n\n{bad}\nbeta\n")
        with pytest.raises(ProjectRegistryError) as exc:
            load_registered_projects(paths)
        assert f"{registry}:3: " in str(exc.value) and repr(bad) in str(exc.value)
        assert "Correct or delete each line" in str(exc.value)

    def test_read_registry_keeps_every_valid_name(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import read_registry
        registry = paths.state / "projects.txt"
        registry.write_text("alpha\n../x\nbeta\nBAD\n")
        read = read_registry(paths)
        assert read.names == {"alpha", "beta"} and read.unparsed == ("../x", "BAD")
        assert [p.split(": ")[0] for p in read.problems] == [f"{registry}:2", f"{registry}:4"]

    def test_membership_ignores_bad_lines(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import is_registered
        (paths.state / "projects.txt").write_text("alpha\nold-staging\n")
        assert is_registered("alpha", paths)
        assert not is_registered("beta", paths)

    def test_add_and_remove_keep_bad_lines_verbatim(self, paths: BoxPaths) -> None:
        from boxmunge.project_registry import add_project, read_registry, remove_project
        registry = paths.state / "projects.txt"
        registry.write_text("alpha\n  ../x \nold-staging\n")
        add_project("gamma", paths)
        remove_project("alpha", paths)
        assert registry.read_text() == "gamma\n  ../x \nold-staging\n"
        assert read_registry(paths).names == {"gamma"}

    def test_deploy_of_a_valid_project_is_unaffected(self, paths: BoxPaths) -> None:
        from unittest.mock import patch
        from boxmunge.commands.deploy import run_deploy
        from boxmunge.project_registry import add_project
        from tests.bundle_helpers import place_bundle
        add_project("myapp", paths)
        registry = paths.state / "projects.txt"
        registry.write_text(registry.read_text() + "old-staging\n")
        place_bundle(paths)
        with patch("boxmunge.compose_guard.compose_up"), \
                patch("boxmunge.commands.deploy.caddy_reload"):
            assert run_deploy("myapp", paths) == 0
        assert "old-staging\n" in registry.read_text()

    @pytest.mark.usefixtures("docker_down")  # doctor probes the docker CLI
    def test_doctor_fails_naming_the_line(self, paths: BoxPaths) -> None:
        import contextlib
        import io
        import json
        from boxmunge.commands.doctor import run_doctor
        registry = paths.state / "projects.txt"
        registry.write_text("alpha\n../x\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert run_doctor(paths, as_json=True) == 1
        [result] = [r for r in json.loads(out.getvalue()) if r["name"] == "Project registry"]
        assert result["status"] == "FAIL" and f"{registry}:2: " in result["detail"]

    def test_listings_report_rather_than_hide(self, paths: BoxPaths, monkeypatch) -> None:
        from boxmunge import mcp_tools
        (paths.state / "projects.txt").write_text("alpha\n../x\n")
        monkeypatch.setattr(mcp_tools, "_get_paths", lambda: paths)
        result = mcp_tools._tool_project_list_mcp()
        assert result["success"] is False and ":2: " in result["messages"][0]


class TestOverlappingNames:
    """`foo` and `foo-bar` can share container names (foo's service bar-web
    and foo-bar's web both become foo-bar-web-1), so new pairs are refused."""

    @pytest.mark.parametrize("existing,new", [("foo", "foo-bar"), ("foo-bar", "foo"),
                                              ("mongo", "mongo-express")])
    def test_new_overlapping_name_refused(self, paths: BoxPaths, existing, new) -> None:
        from boxmunge.project_registry import add_project, load_registered_projects
        add_project(existing, paths)
        with pytest.raises(ValueError, match="container names"):
            add_project(new, paths)
        assert new not in load_registered_projects(paths)

    @pytest.mark.parametrize("a,b", [("foo", "foobar"), ("foo-bar", "foo-baz"), ("bar", "foo-bar")])
    def test_names_that_do_not_extend_each_other_accepted(self, paths: BoxPaths, a, b) -> None:
        from boxmunge.project_registry import add_project
        add_project(a, paths)
        add_project(b, paths)

    @pytest.mark.usefixtures("docker_down")  # doctor probes the docker CLI
    def test_existing_pair_keeps_working_and_doctor_warns(self, paths: BoxPaths) -> None:
        from boxmunge.commands.doctor import run_doctor
        from boxmunge.project_registry import add_project, load_registered_projects
        (paths.state / "projects.txt").write_text("foo\nfoo-bar\n")
        add_project("foo-bar", paths)  # already registered: no error
        assert load_registered_projects(paths) == {"foo", "foo-bar"}
        import io, json, contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            run_doctor(paths, as_json=True)
        [warning] = [r for r in json.loads(out.getvalue()) if r["name"] == "Project names"]
        assert warning["status"] == "WARN" and "foo / foo-bar" in warning["detail"]


def test_auto_migrate_registers_on_disk_overlaps_with_a_warning(paths: BoxPaths) -> None:
    from boxmunge.project_registry import load_registered_projects
    paths.log_file.parent.mkdir(parents=True, exist_ok=True)
    for name in ("foo", "foo-bar"):
        (paths.project_dir(name)).mkdir(parents=True)
        (paths.project_dir(name) / "manifest.yml").write_text("project: x\n")
    assert load_registered_projects(paths) == {"foo", "foo-bar"}
    assert "foo / foo-bar" in paths.log_file.read_text()

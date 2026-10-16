from unittest.mock import MagicMock, patch
import pytest
import yaml
from boxmunge.paths import BoxPaths
from boxmunge.container_update_targets import (
    UpdateTarget, build_targets, resolve_strategy,
)


@pytest.fixture
def paths(tmp_path):
    p = BoxPaths(root=tmp_path / "bm")
    p.config.mkdir(parents=True)
    p.projects.mkdir(parents=True)
    p.caddy.mkdir(parents=True)
    (p.caddy / "compose.yml").write_text(
        "services:\n  caddy:\n    image: caddy:2-alpine\n    container_name: boxmunge-caddy\n"
    )
    p.config_file.write_text("hostname: t\nadmin_email: t@t\n")
    return p


def _write_project(paths, name, manifest_extra=None, with_backup=False):
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    manifest = {
        "schema_version": 1, "id": "01TEST", "project": name,
        "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }
    if with_backup:
        manifest["backup"] = {"type": "postgres", "service": "db", "dump_command": "pg_dump x"}
    if manifest_extra:
        manifest.update(manifest_extra)
    (pdir / "manifest.yml").write_text(yaml.dump(manifest))
    (pdir / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.25\n    container_name: " + name + "_web_1\n"
    )


class TestResolveStrategy:
    def test_box_default(self):
        box = {"strategy": "leave_broken"}
        assert resolve_strategy(box, project=None) == "leave_broken"

    def test_project_overrides_box(self):
        box = {"strategy": "leave_broken"}
        proj = {"strategy": "rollback_to_previous"}
        assert resolve_strategy(box, project=proj) == "rollback_to_previous"

    def test_project_no_override(self):
        box = {"strategy": "leave_broken"}
        proj = {"enabled": True}
        assert resolve_strategy(box, project=proj) == "leave_broken"


class TestBuildTargets:
    def test_caddy_always_first(self, paths):
        _write_project(paths, "myapp")
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        assert targets[0].name == "caddy"

    def test_includes_enabled_projects(self, paths):
        _write_project(paths, "myapp")
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        names = [t.name for t in targets]
        assert "myapp" in names

    def test_skips_opt_out_projects(self, paths):
        _write_project(paths, "myapp", manifest_extra={"container_updates": {"enabled": False}})
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        names = [t.name for t in targets]
        assert "myapp" not in names

    def test_per_project_strategy_override(self, paths):
        _write_project(paths, "myapp", manifest_extra={
            "container_updates": {"strategy": "rollback_to_previous"}
        })
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        myapp = next(t for t in targets if t.name == "myapp")
        assert myapp.strategy == "rollback_to_previous"

    def test_caddy_uses_box_strategy(self, paths):
        config = {"container_updates": {"enabled": True, "strategy": "rollback_to_previous"}}
        targets = build_targets(paths, config)
        caddy = targets[0]
        assert caddy.strategy == "rollback_to_previous"

    def test_has_backup_set_when_manifest_has_backup(self, paths):
        _write_project(paths, "stateful", with_backup=True)
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        stateful = next(t for t in targets if t.name == "stateful")
        assert stateful.has_backup is True

    def test_caddy_has_no_backup(self, paths):
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        caddy = targets[0]
        assert caddy.has_backup is False


class TestTargetState:
    def test_read_missing_returns_none(self, paths):
        from boxmunge.container_update_targets import read_target_state
        assert read_target_state(paths, "nope") is None

    def test_write_then_read(self, paths):
        from boxmunge.container_update_targets import write_target_state, read_target_state
        paths.container_update_state.mkdir(parents=True)
        state = {
            "last_check": "2026-05-04T03:00:00Z",
            "last_change": "2026-05-02T03:00:00Z",
            "last_status": "succeeded",
            "current_digests": {"caddy": "sha256:abc"},
            "previous_digests": {"caddy": "sha256:def"},
        }
        write_target_state(paths, "caddy", state)
        assert read_target_state(paths, "caddy") == state

    def test_write_creates_state_dir(self, paths):
        from boxmunge.container_update_targets import write_target_state
        # state dir does NOT exist yet
        assert not paths.container_update_state.exists()
        write_target_state(paths, "caddy", {"last_status": "succeeded"})
        assert paths.container_update_state.exists()


_OLD = "sha256:" + "0" * 64
_NEW = "sha256:" + "1" * 64


class FakeDocker:
    """Image tags and a compose project's containers, as Docker keeps them.

    ``pull`` moves tags to newer images; ``up`` recreates each image
    service's container from the image its tag names now; ``tag`` is
    `docker tag`, which accepts an image ID. ``health`` gives the
    healthcheck status each image reports once running.
    """

    def __init__(self, monkeypatch, fake_containers, project, services):
        self.containers, self.project, self.services = fake_containers, project, services
        self.tags = {ref: _OLD for ref in services.values()}
        self.pulled: dict[str, str] = {}
        self.health = {_OLD: "healthy", _NEW: "healthy"}
        self.ups = 0
        self.tagged: list[tuple[str, str]] = []
        import boxmunge.container_update as cu
        monkeypatch.setattr(cu, "compose_pull", self._pull)
        monkeypatch.setattr("boxmunge.docker.compose_pull", self._pull)  # the dry run's
        monkeypatch.setattr(cu, "compose_up", self._up)
        monkeypatch.setattr("boxmunge.docker_containers.local_image", self._local_image)
        monkeypatch.setattr(cu, "tag_image", self._tag)
        monkeypatch.setattr(cu, "_HEALTHCHECK_POLL_INTERVAL_SEC", 0)
        self._recreate()

    def _recreate(self):
        self.containers.remove(self.project)
        for svc, ref in self.services.items():
            image = self.tags[ref]
            self.containers.run(self.project, svc, image, health=self.health[image],
                                repo_digests=(f"{ref.split(':')[0]}@sha256:{'9' * 64}",)
                                if image == _OLD else ())

    def _local_image(self, ref):
        from boxmunge.docker_containers import LocalImage
        image = self.tags.get(ref)
        return None if image is None else LocalImage(image_id=image, repo_digests=())

    def _pull(self, *args, **kwargs):
        self.tags.update(self.pulled)

    def _up(self, *args, **kwargs):
        self.ups += 1
        self._recreate()

    def _tag(self, source, target):
        if source not in self.health:
            from boxmunge.docker import DockerError
            raise DockerError(f"No such image: {source}")
        self.tagged.append((source, target))
        self.tags[target] = source


def _caddy_target(paths, strategy="leave_broken"):
    return UpdateTarget(
        name="caddy", project_dir=paths.caddy, compose_files=["compose.yml"],
        strategy=strategy, has_backup=False, is_caddy=True,
    )


@pytest.fixture
def caddy(monkeypatch, fake_containers):
    return FakeDocker(monkeypatch, fake_containers, "caddy", {"caddy": "caddy:2-alpine"})


class TestUpdateTarget:
    def test_no_change_when_the_pull_brings_nothing_new(self, paths, caddy):
        from boxmunge.container_update import update_target
        result = update_target(paths, _caddy_target(paths))
        assert result["status"] == "no_change"
        assert caddy.ups == 0

    def test_succeeds_on_image_change_and_healthy(self, paths, caddy):
        from boxmunge.container_update import update_target
        caddy.pulled = {"caddy:2-alpine": _NEW}
        result = update_target(paths, _caddy_target(paths))
        assert result["status"] == "succeeded"
        assert caddy.ups == 1
        # Display references: the registry digest before, the image ID after.
        assert result["previous_digests"] == {"caddy": "caddy@sha256:" + "9" * 64}
        assert result["current_digests"] == {"caddy": _NEW}

    def test_failed_when_pull_fails(self, paths, caddy, monkeypatch):
        import boxmunge.container_update as cu
        from boxmunge.docker import DockerError

        def fail(*a, **k):
            raise DockerError("network")
        monkeypatch.setattr(cu, "compose_pull", fail)
        result = cu.update_target(paths, _caddy_target(paths))
        assert result["status"] == "failed"
        assert "pull" in result.get("reason", "").lower()

    def test_build_only_project_skips_pull_and_is_no_change(self, paths, monkeypatch):
        """A build-only project (no image: services) has nothing to pull.

        Regression: previously `docker compose pull` on a build-only project
        errored ("no image to pull") and the run was recorded as `failed`,
        surfacing a misleading container-updates health warning. It must be
        recorded `no_change` (fresh timestamp — neither failed nor stale) and
        must NOT attempt a pull.
        """
        import boxmunge.container_update as cu
        from boxmunge.container_update_targets import read_target_state
        pdir = paths.projects / "buildonly"
        pdir.mkdir()
        (pdir / "compose.yml").write_text("services:\n  web:\n    build: .\n")
        pull = MagicMock()
        monkeypatch.setattr(cu, "compose_pull", pull)
        target = UpdateTarget(
            name="buildonly", project_dir=pdir,
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False, is_caddy=False,
        )
        result = cu.update_target(paths, target)
        assert result["status"] == "no_change"
        pull.assert_not_called()
        # State persisted as no_change (self-heals a prior 'failed' state).
        assert read_target_state(paths, "buildonly")["last_status"] == "no_change"

    def test_service_without_container_fails_instead_of_no_change(
        self, paths, caddy, fake_containers,
    ):
        """Nothing shows which image it runs, so "no change" would be a guess."""
        from boxmunge.container_update import update_target
        fake_containers.remove("caddy")
        result = update_target(paths, _caddy_target(paths))
        assert result["status"] == "failed"
        assert "service 'caddy' has no container" in result["reason"]
        assert caddy.ups == 0

    def test_image_missing_after_pull_fails(self, paths, caddy, monkeypatch):
        import boxmunge.container_update as cu
        monkeypatch.setattr("boxmunge.docker_containers.local_image", lambda ref: None)
        result = cu.update_target(paths, _caddy_target(paths))
        assert result["status"] == "failed"
        assert "not in the local image store" in result["reason"]

    def test_replicas_on_different_images_fail(self, paths, caddy, fake_containers):
        from boxmunge.container_update import update_target
        fake_containers.run("caddy", "caddy", _NEW)
        result = update_target(paths, _caddy_target(paths))
        assert result["status"] == "failed"
        assert "run different images" in result["reason"]

    def test_leave_broken_strategy_does_not_rollback(self, paths, caddy):
        from boxmunge.container_update import update_target
        caddy.pulled = {"caddy:2-alpine": _NEW}
        caddy.health[_NEW] = "unhealthy"
        result = update_target(paths, _caddy_target(paths))
        assert result["status"] == "failed"
        assert result["reason"] == "unhealthy: caddy"
        assert result["rollback_attempted"] is False
        assert caddy.ups == 1

    def test_rollback_retags_the_previous_image_id_and_recreates(self, paths, caddy):
        """Review finding 08: the previous image is restored by its image ID.
        Its registry digest (shown in previous_digests) is not an ID Docker
        can tag from."""
        from boxmunge.container_update import update_target
        caddy.pulled = {"caddy:2-alpine": _NEW}
        caddy.health[_NEW] = "unhealthy"
        result = update_target(paths, _caddy_target(paths, "rollback_to_previous"))
        assert result["status"] == "failed"
        assert result["rollback_attempted"] is True
        assert result["rollback_succeeded"] is True
        assert caddy.tagged == [(_OLD, "caddy:2-alpine")]
        assert caddy.ups == 2
        assert [c.image_id for c in caddy.containers("caddy")] == [_OLD]

    def test_unhealthy_wait_reads_containers_by_label(self, paths, caddy, fake_containers):
        """A stopped container fails the health wait whatever its name."""
        from boxmunge.container_update import _wait_healthy
        fake_containers.remove("caddy")
        fake_containers.run("caddy", "caddy", _OLD, name="boxmunge-caddy", running=False)
        assert _wait_healthy(_caddy_target(paths), ["caddy"]) == (False, ["caddy"])

    def test_one_shot_that_finished_again_is_healthy(self, paths, caddy, fake_containers):
        from boxmunge.container_update import _wait_healthy
        fake_containers.run("caddy", "migrate", _OLD, running=False, exit_code=0,
                            restart_policy="no")
        assert _wait_healthy(_caddy_target(paths), ["caddy", "migrate"],
                             frozenset({"migrate"})) == (True, [])

    def test_one_shot_that_failed_is_unhealthy(self, paths, caddy, fake_containers):
        from boxmunge.container_update import _wait_healthy
        fake_containers.run("caddy", "migrate", _OLD, running=False, exit_code=3,
                            restart_policy="no")
        assert _wait_healthy(_caddy_target(paths), ["caddy", "migrate"],
                             frozenset({"migrate"})) == (False, ["migrate"])

    def test_long_running_service_that_now_exits_zero_is_unhealthy(
        self, paths, caddy, fake_containers,
    ):
        """Restart "no" is Compose's default: exit 0 is only fine for a
        service that was a finished one-shot before the update too."""
        from boxmunge.container_update import _wait_healthy
        fake_containers.remove("caddy")
        fake_containers.run("caddy", "caddy", _NEW, running=False, exit_code=0,
                            restart_policy="no")
        assert _wait_healthy(_caddy_target(paths), ["caddy"]) == (False, ["caddy"])

    def test_one_shots_are_judged_on_the_pre_update_containers(self, fake_containers):
        from boxmunge.container_update import one_shot_services
        from boxmunge.deployed_inventory import DeployedService
        done = fake_containers.run("p", "migrate", _OLD, running=False, exit_code=0,
                                   restart_policy="no")
        up = fake_containers.run("p", "web", _OLD)
        services = {
            "migrate": DeployedService("migrate", "m:1", False, True, (done,)),
            "web": DeployedService("web", "w:1", False, True, (up,)),
        }
        assert one_shot_services(services) == {"migrate"}

    @staticmethod
    def _stateful(paths, monkeypatch, fake_containers):
        _write_project(paths, "stateful", with_backup=True)
        FakeDocker(monkeypatch, fake_containers, "stateful", {"web": "nginx:1.25"})
        return UpdateTarget(
            name="stateful", project_dir=paths.project_dir("stateful"),
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=True, is_caddy=False,
        )

    @patch("boxmunge.container_update.run_backup")
    def test_no_backup_when_no_image_changed(
        self, mock_backup, paths, monkeypatch, fake_containers,
    ):
        """C-10: the pre-backup used to run every day before change detection,
        so a no-op sweep consumed a retention slot."""
        from boxmunge.container_update import update_target
        result = update_target(paths, self._stateful(paths, monkeypatch, fake_containers))
        assert result["status"] == "no_change"
        mock_backup.assert_not_called()

    @patch("boxmunge.container_update.run_backup", return_value=0)
    def test_preupdate_backup_runs_before_recreate(
        self, mock_backup, paths, monkeypatch, fake_containers,
    ):
        import boxmunge.container_update as cu
        from boxmunge.backup import BackupKind
        target = self._stateful(paths, monkeypatch, fake_containers)
        monkeypatch.setattr(cu, "detect_image_changes", lambda s, r: {"web": _NEW})
        order = []
        mock_backup.side_effect = lambda *a, **k: order.append("backup") or 0
        monkeypatch.setattr(cu, "compose_up", lambda *a, **k: order.append("up"))
        cu.update_target(paths, target)
        mock_backup.assert_called_once_with(
            "stateful", paths, kind=BackupKind.PREUPDATE, _lock_held=True,
        )
        assert order[:2] == ["backup", "up"]

    @patch("boxmunge.container_update.run_backup", return_value=1)
    def test_aborts_before_recreate_when_backup_fails(
        self, mock_backup, paths, monkeypatch, fake_containers,
    ):
        import boxmunge.container_update as cu
        target = self._stateful(paths, monkeypatch, fake_containers)
        monkeypatch.setattr(cu, "detect_image_changes", lambda s, r: {"web": _NEW})
        up = MagicMock()
        monkeypatch.setattr(cu, "compose_up", up)
        result = cu.update_target(paths, target)
        assert result["status"] == "failed"
        assert "backup" in result.get("reason", "").lower()
        up.assert_not_called()


class TestDryRun:
    def test_reports_what_would_change_without_recreating(self, paths, caddy):
        from boxmunge.commands.container_update_cmd import _dry_run_target
        caddy.pulled = {"caddy:2-alpine": _NEW}
        result = _dry_run_target(paths, _caddy_target(paths))
        assert result["status"] == "would_change"
        assert result["current_digests"] == {"caddy": _NEW}
        assert caddy.ups == 0

    def test_service_without_container_fails(self, paths, caddy, fake_containers):
        from boxmunge.commands.container_update_cmd import _dry_run_target
        fake_containers.remove("caddy")
        result = _dry_run_target(paths, _caddy_target(paths))
        assert result["status"] == "failed"
        assert "has no container" in result["reason"]


class TestImageServices:
    def test_build_inactive_and_scaled_to_zero_services_are_not_updated(self, paths):
        from boxmunge.container_update import image_services
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "compose.yml").write_text(
            "services:\n"
            "  web:\n    image: nginx:1.25\n    container_name: custom\n"
            "  app:\n    build: .\n    image: myapp-app\n"
            "  dev:\n    image: dev:1\n    profiles: [dev]\n"
            "  off:\n    image: off:1\n    deploy:\n      replicas: 0\n"
        )
        target = UpdateTarget(
            name="myapp", project_dir=pdir,
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False,
        )
        assert list(image_services(target)) == ["web"]


class TestTargetStateErrors:
    def test_read_target_state_raises_on_corrupt(self, paths):
        import json
        import pytest
        from boxmunge.container_update_targets import read_target_state
        paths.container_update_state.mkdir(parents=True)
        paths.container_update_target_state("caddy").write_text("not json {")
        with pytest.raises(json.JSONDecodeError):
            read_target_state(paths, "caddy")


class TestUpdateTargetSkipsQuarantined:
    """Wave 1 defense-in-depth: update_target itself refuses to pull/recreate
    a CVE-quarantined user project, even if a future caller forgets to
    pre-filter. Caddy is exempt — it has no quarantine state."""

    def test_monitor_stopped_project_is_refused_under_the_lock(self, paths, monkeypatch):
        import boxmunge.container_update as cu
        from boxmunge.state import write_state
        _write_project(paths, "stopped-app")
        write_state(paths.project_health_state("stopped-app"), {
            "status": "critical_stopped", "stopped_at": "2026-10-01T03:00:00+00:00",
        })
        pull = MagicMock()
        monkeypatch.setattr(cu, "compose_pull", pull)
        target = UpdateTarget(
            name="stopped-app", project_dir=paths.project_dir("stopped-app"),
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False, is_caddy=False,
        )
        assert cu.update_target(paths, target)["status"] == cu.SKIPPED_MONITOR_STOPPED
        pull.assert_not_called()

    @patch("boxmunge.container_update.compose_pull")
    @patch("boxmunge.container_update.compose_up")
    @patch("boxmunge.container_update.run_backup")
    def test_quarantined_project_returns_quarantined_status(
        self, mock_backup, mock_up, mock_pull, paths,
    ):
        from boxmunge.container_update import update_target
        _write_project(paths, "quar-app")
        # Mark CVE-quarantined.
        paths.project_quarantine_state("quar-app").parent.mkdir(
            parents=True, exist_ok=True,
        )
        paths.project_quarantine_state("quar-app").write_text("{}")

        target = UpdateTarget(
            name="quar-app", project_dir=paths.project_dir("quar-app"),
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False, is_caddy=False,
        )
        result = update_target(paths, target)
        assert result["status"] == "quarantined"
        # Mutating side effects MUST NOT have run.
        mock_pull.assert_not_called()
        mock_up.assert_not_called()
        mock_backup.assert_not_called()

    def test_caddy_is_not_blocked_by_quarantine_check(self, paths, caddy):
        """Caddy targets must continue updating regardless — quarantine state
        applies to user projects only."""
        from boxmunge.container_update import update_target
        # Even if a stray "caddy.quarantined.json" exists (it shouldn't),
        # Caddy targets short-circuit via the is_caddy flag.
        # "caddy" is a reserved project name, so build the path by hand.
        paths.deploy_state.mkdir(parents=True, exist_ok=True)
        (paths.deploy_state / "caddy.quarantined.json").write_text("{}")
        result = update_target(paths, _caddy_target(paths))
        # No-change path runs; status is no_change (not quarantined).
        assert result["status"] == "no_change"


class TestPersistResult:
    def test_persist_no_change_preserves_previous_digests(self, paths):
        from boxmunge.container_update_targets import persist_result, write_target_state, read_target_state
        paths.container_update_state.mkdir(parents=True)
        # Existing state has a genuine previous_digests from an earlier update
        write_target_state(paths, "caddy", {
            "last_check": "2026-05-01T00:00:00+00:00",
            "last_change": "2026-04-30T00:00:00+00:00",
            "last_status": "succeeded",
            "current_digests": {"caddy": "sha256:current"},
            "previous_digests": {"caddy": "sha256:original"},
        })
        target = UpdateTarget(
            name="caddy", project_dir=paths.caddy,
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False, is_caddy=True,
        )
        result = {
            "name": "caddy", "ts": "2026-05-04T03:00:00+00:00",
            "status": "no_change",
            "rollback_attempted": False, "rollback_succeeded": None,
            "current_digests": {"caddy": "sha256:current"},
        }
        persist_result(paths, target, result, before={"caddy": "sha256:current"})
        state = read_target_state(paths, "caddy")
        # previous_digests must NOT be overwritten with the no-change "before"
        assert state["previous_digests"] == {"caddy": "sha256:original"}

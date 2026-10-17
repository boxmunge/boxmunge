"""Tests for boxmunge.compose — compose overlay generation."""

import yaml

from boxmunge.compose import generate_compose_override, generate_staging_compose_override


# The overlay writes long-syntax mounts so a path is never read as options.
_PROD_SMOKE_MOUNT = {"type": "bind", "source": "./.releases/live-scripts",
                     "target": "/boxmunge-scripts", "read_only": True,
                     "bind": {"create_host_path": True}}
_STAGING_SMOKE_MOUNT = {**_PROD_SMOKE_MOUNT, "source": "./boxmunge-scripts"}


def _volume(source: str, target: str) -> dict[str, str]:
    return {"type": "volume", "source": source, "target": target}


FULL_MANIFEST = {
    "project": "myapp",
    "hosts": ["myapp.example.com"],
    "services": {
        "frontend": {
            "type": "frontend",
            "port": 3000,
            "routes": [{"path": "/"}],
        },
        "backend": {
            "type": "backend",
            "port": 8000,
            "internal": True,
            "routes": [{"path": "/api/*"}],
        },
        "db": {
            "type": "database",
            "port": 5432,
            "internal": True,
            "routes": [],
        },
    },
}


class TestGenerateComposeOverride:
    def test_routable_services_get_proxy_network(self) -> None:
        override = generate_compose_override(FULL_MANIFEST, user_compose={})
        parsed = yaml.safe_load(override)
        assert "frontend" in parsed["services"]
        networks = parsed["services"]["frontend"]["networks"]
        assert "boxmunge-proxy" in networks

    def test_internal_services_excluded_from_proxy(self) -> None:
        """Non-routable services don't get proxy-network aliases.

        They may still appear in the overlay for other reasons (env_files,
        limits, hardening), but never with a boxmunge-proxy network entry.
        """
        override = generate_compose_override(FULL_MANIFEST, user_compose={})
        parsed = yaml.safe_load(override)
        db = parsed["services"].get("db", {})
        assert "networks" not in db

    def test_backend_with_routes_gets_proxy_network(self) -> None:
        override = generate_compose_override(FULL_MANIFEST, user_compose={})
        parsed = yaml.safe_load(override)
        assert "backend" in parsed["services"]
        aliases = parsed["services"]["backend"]["networks"]["boxmunge-proxy"]["aliases"]
        assert "myapp-backend" in aliases

    def test_routable_services_keep_default_network(self) -> None:
        """Routable services must stay on default network for inter-service DNS."""
        override = generate_compose_override(FULL_MANIFEST, user_compose={})
        parsed = yaml.safe_load(override)
        networks = parsed["services"]["frontend"]["networks"]
        assert "default" in networks
        assert "boxmunge-proxy" in networks

    def test_aliases_are_project_scoped(self) -> None:
        override = generate_compose_override(FULL_MANIFEST, user_compose={})
        parsed = yaml.safe_load(override)
        aliases = parsed["services"]["frontend"]["networks"]["boxmunge-proxy"]["aliases"]
        assert aliases == ["myapp-frontend"]

    def test_declares_external_network(self) -> None:
        override = generate_compose_override(FULL_MANIFEST, user_compose={})
        parsed = yaml.safe_load(override)
        assert parsed["networks"]["boxmunge-proxy"]["external"] is True


class TestComposeEnvFiles:
    def test_includes_env_files_in_order(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest, env_files={
            "host_secrets": "/opt/boxmunge/config/secrets.env",
            "project_env": "./project.env",
            "project_secrets": "./secrets.env",
        }, user_compose={})
        parsed = yaml.safe_load(content)
        env_list = parsed["services"]["web"]["env_file"]
        assert env_list[0] == "/opt/boxmunge/config/secrets.env"
        assert env_list[1] == "./project.env"
        assert env_list[2] == "./secrets.env"

    def test_omits_missing_env_files(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest, env_files={
            "host_secrets": "/opt/boxmunge/config/secrets.env",
        }, user_compose={})
        parsed = yaml.safe_load(content)
        assert len(parsed["services"]["web"]["env_file"]) == 1

    def test_no_env_files_by_default(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert "env_file" not in parsed["services"]["web"]


class TestComposeResourceLimits:
    def test_includes_limits(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "limits": {"memory": "512m", "cpus": "0.5"},
            }},
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        limits = parsed["services"]["web"]["deploy"]["resources"]["limits"]
        assert limits["memory"] == "512m"
        assert limits["cpus"] == "0.5"

    def test_no_limits_by_default(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert "deploy" not in parsed["services"]["web"]

    def test_limits_on_some_services(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}], "limits": {"memory": "256m"}},
                "api": {"port": 9000, "routes": [{"path": "/api/*"}]},
            },
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert "deploy" in parsed["services"]["web"]
        assert "deploy" not in parsed["services"]["api"]


class TestNonRoutableServices:
    def test_worker_gets_env_files(self) -> None:
        """Non-routable services (workers, databases) still need secrets."""
        manifest = {
            "project": "myapp",
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}]},
                "worker": {"port": 9000, "internal": True, "routes": []},
            },
        }
        content = generate_compose_override(manifest, env_files={
            "host_secrets": "/opt/boxmunge/config/secrets.env",
        }, user_compose={})
        parsed = yaml.safe_load(content)
        # Worker should get env_files even without routes
        assert "worker" in parsed["services"]
        assert parsed["services"]["worker"]["env_file"] == [
            "/opt/boxmunge/config/secrets.env"
        ]
        # Worker should NOT have network aliases
        assert "networks" not in parsed["services"]["worker"]

    def test_worker_gets_limits(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}]},
                "worker": {"port": 9000, "routes": [], "limits": {"memory": "256m"}},
            },
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert "worker" in parsed["services"]
        assert parsed["services"]["worker"]["deploy"]["resources"]["limits"]["memory"] == "256m"


class TestSmokeScriptMount:
    def test_smoke_service_gets_volume_mount(self) -> None:
        """Production mounts its own copy of the release's scripts."""
        manifest = {
            "project": "myapp",
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "smoke": "boxmunge-scripts/smoke.sh",
            }},
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert parsed["services"]["web"]["volumes"] == [
            _PROD_SMOKE_MOUNT]

    def test_staging_mounts_the_staged_scripts(self) -> None:
        """Staging runs the staged release's scripts from the project dir."""
        manifest = {
            "project": "myapp",
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "smoke": "boxmunge-scripts/smoke.sh",
            }},
        }
        content = generate_staging_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert parsed["services"]["web"]["volumes"] == [
            _STAGING_SMOKE_MOUNT]

    def test_only_smoke_services_get_mount(self) -> None:
        """Only services with smoke get the volume mount."""
        manifest = {
            "project": "myapp",
            "services": {
                "web": {
                    "port": 8080, "routes": [{"path": "/"}],
                    "smoke": "boxmunge-scripts/smoke.sh",
                },
                "worker": {"port": 9000, "routes": [{"path": "/work"}]},
            },
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert "volumes" in parsed["services"]["web"]
        assert "volumes" not in parsed["services"]["worker"]

    def test_multiple_smoke_services(self) -> None:
        """Multiple services can each have their own smoke test."""
        manifest = {
            "project": "myapp",
            "services": {
                "web": {
                    "port": 8080, "routes": [{"path": "/"}],
                    "smoke": "boxmunge-scripts/smoke-web.sh",
                },
                "api": {
                    "port": 9000, "routes": [{"path": "/api/*"}],
                    "smoke": "boxmunge-scripts/smoke-api.sh",
                },
            },
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert "volumes" in parsed["services"]["web"]
        assert "volumes" in parsed["services"]["api"]

    def test_no_smoke_no_mount(self) -> None:
        """Services without smoke get no volume mount."""
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert "volumes" not in parsed["services"]["web"]


class TestStagingOverrideEnvAndLimits:
    def test_staging_includes_env_files(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }
        content = generate_staging_compose_override(manifest, env_files={
            "project_secrets": "./secrets.env",
        }, user_compose={})
        parsed = yaml.safe_load(content)
        assert parsed["services"]["web"]["env_file"] == ["./secrets.env"]

    def test_staging_includes_limits(self) -> None:
        manifest = {
            "project": "myapp",
            "services": {"web": {
                "port": 8080, "routes": [{"path": "/"}],
                "limits": {"memory": "512m"},
            }},
        }
        content = generate_staging_compose_override(manifest, user_compose={})
        parsed = yaml.safe_load(content)
        assert parsed["services"]["web"]["deploy"]["resources"]["limits"]["memory"] == "512m"


class TestComposeSecurityHardening:
    def _manifest(self, security=None, service_security=None):
        m = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {
                "web": {
                    "type": "frontend",
                    "port": 3000,
                    "routes": [{"path": "/"}],
                },
            },
        }
        if security is not None:
            m["security"] = security
        if service_security is not None:
            m["services"]["web"]["security"] = service_security
        return m

    def test_default_injects_no_new_privileges_init_pids_capdrop(self) -> None:
        override = generate_compose_override(self._manifest(), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert "no-new-privileges:true" in web["security_opt"]
        assert web["init"] is True
        assert web["pids_limit"] == 512
        assert "NET_ADMIN" in web["cap_drop"]
        assert "NET_RAW" in web["cap_drop"]

    def test_default_injects_read_only_and_tmpfs_v08(self) -> None:
        """v0.8: default profile makes read_only:true and tmpfs:['/tmp']
        defaults of the silent-floor overlay."""
        override = generate_compose_override(self._manifest(), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert web["read_only"] is True
        assert web["tmpfs"] == ["/tmp"]

    def test_off_omits_hardening_fields(self) -> None:
        override = generate_compose_override(
            self._manifest(security={"profile": "off", "reason": "test"}), user_compose={}
        )
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert "security_opt" not in web
        assert "init" not in web
        assert "pids_limit" not in web
        assert "cap_drop" not in web
        # v0.8: off profile also omits read_only and tmpfs.
        assert "read_only" not in web
        assert "tmpfs" not in web

    def test_service_cap_add_subtracts_from_drop(self) -> None:
        override = generate_compose_override(
            self._manifest(service_security={"cap_add": ["NET_RAW"]}), user_compose={}
        )
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert "NET_RAW" not in web["cap_drop"]
        assert "NET_RAW" in web["cap_add"]

    def test_per_service_pids_override(self) -> None:
        override = generate_compose_override(
            self._manifest(service_security={"pids_limit": 4096}), user_compose={}
        )
        parsed = yaml.safe_load(override)
        assert parsed["services"]["web"]["pids_limit"] == 4096

    def test_pids_nested_under_deploy_when_manifest_has_limits(self) -> None:
        """Regression: when manifest declares limits (e.g. memory/cpus), the
        rendered overlay creates `deploy.resources.limits`. Adding
        top-level `pids_limit` AND `deploy.resources.limits` together makes
        Docker Compose fail with "can't set distinct values on 'pids_limit'
        and 'deploy.resources.limits.pids'". Workaround: when the deploy
        block exists, nest pids under it.
        """
        m = self._manifest()
        m["services"]["web"]["limits"] = {"memory": "256m", "cpus": "0.5"}

        override = generate_compose_override(m, user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]

        # Top-level pids_limit MUST NOT be present (would conflict).
        assert "pids_limit" not in web, (
            "pids_limit at top level conflicts with deploy.resources.limits. "
            "It must be nested under deploy.resources.limits.pids instead."
        )
        # Memory and cpus from manifest still present.
        assert web["deploy"]["resources"]["limits"]["memory"] == "256m"
        assert web["deploy"]["resources"]["limits"]["cpus"] == "0.5"
        # pids nested.
        assert web["deploy"]["resources"]["limits"]["pids"] == 512
        # Other hardening still at top level.
        assert "no-new-privileges:true" in web["security_opt"]
        assert web["init"] is True
        assert "NET_ADMIN" in web["cap_drop"]

    def test_pids_at_top_level_when_manifest_has_no_limits(self) -> None:
        """When the manifest doesn't declare limits, no deploy block is
        created — pids_limit stays at the top level (the default)."""
        override = generate_compose_override(self._manifest(), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert web["pids_limit"] == 512
        # No deploy block should have been created.
        assert "deploy" not in web

    def test_pids_nested_respects_per_service_override(self) -> None:
        """A service-level pids_limit override (e.g. 4096) on a service with
        manifest limits must end up nested under deploy.resources.limits.pids."""
        m = self._manifest(service_security={"pids_limit": 4096})
        m["services"]["web"]["limits"] = {"memory": "256m"}
        override = generate_compose_override(m, user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert "pids_limit" not in web
        assert web["deploy"]["resources"]["limits"]["pids"] == 4096
        assert web["deploy"]["resources"]["limits"]["memory"] == "256m"


class TestV08UserWinsOnExplicitDeclarations:
    """v0.8: when the user has declared read_only or claimed /tmp on a
    service, the overlay generator omits its own contribution for that
    field. Compose merge then leaves the user value alone — no merge
    conflict, no dedupe rejection rule needed.

    Rationale: Compose merge of scalars (read_only) keeps the LATER
    file's value (overlay would overwrite user); merge of lists (tmpfs)
    concatenates (would clash). Both are wrong outcomes when the user
    has expressed intent.
    """

    def _manifest(self) -> dict:
        return {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {
                "web": {
                    "type": "frontend",
                    "port": 3000,
                    "routes": [{"path": "/"}],
                },
            },
        }

    def test_no_user_compose_emits_v08_defaults(self) -> None:
        override = generate_compose_override(self._manifest(), user_compose={})
        web = yaml.safe_load(override)["services"]["web"]
        assert web["read_only"] is True
        assert web["tmpfs"] == ["/tmp"]

    def test_user_declared_read_only_true_omits_overlay_read_only(self) -> None:
        """User redeclares read_only:true — overlay omits its addition.
        Operationally identical to the v0.8 default; no error.
        """
        user_compose = {
            "services": {"web": {"image": "nginx", "read_only": True}},
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        web = yaml.safe_load(override)["services"]["web"]
        assert "read_only" not in web

    def test_user_declared_read_only_false_omits_overlay_read_only(self) -> None:
        """User opts out of read-only rootfs — overlay omits its addition,
        so compose merge respects the user's literal value.
        """
        user_compose = {
            "services": {"web": {"image": "nginx", "read_only": False}},
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        web = yaml.safe_load(override)["services"]["web"]
        assert "read_only" not in web

    def test_user_tmpfs_tmp_omits_overlay_tmpfs(self) -> None:
        user_compose = {
            "services": {
                "web": {"image": "nginx", "tmpfs": ["/tmp:size=128m"]},
            },
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        web = yaml.safe_load(override)["services"]["web"]
        assert "tmpfs" not in web

    def test_user_tmpfs_other_path_does_not_omit_overlay_tmpfs(self) -> None:
        """User has tmpfs but for a different path — overlay still emits
        its /tmp tmpfs. Compose list-merge concatenates, both apply.
        """
        user_compose = {
            "services": {
                "web": {"image": "nginx", "tmpfs": ["/var/cache"]},
            },
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        web = yaml.safe_load(override)["services"]["web"]
        assert web["tmpfs"] == ["/tmp"]

    def test_user_volume_targets_tmp_omits_overlay_tmpfs(self) -> None:
        """User has a volume mount whose target is /tmp — overlay omits
        its tmpfs. Avoids overriding the user's explicit /tmp choice.
        """
        user_compose = {
            "services": {
                "web": {"image": "nginx", "volumes": ["./tmpdata:/tmp"]},
            },
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        web = yaml.safe_load(override)["services"]["web"]
        assert "tmpfs" not in web

    def test_user_long_syntax_volume_targets_tmp_omits_overlay_tmpfs(self) -> None:
        user_compose = {
            "services": {
                "web": {
                    "image": "nginx",
                    "volumes": [
                        {"type": "tmpfs", "target": "/tmp"},
                    ],
                },
            },
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        web = yaml.safe_load(override)["services"]["web"]
        assert "tmpfs" not in web

    def test_user_long_syntax_bind_volume_targets_tmp_omits_overlay_tmpfs(self) -> None:
        user_compose = {
            "services": {
                "web": {
                    "image": "nginx",
                    "volumes": [
                        {"type": "bind", "source": "./d", "target": "/tmp"},
                    ],
                },
            },
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        web = yaml.safe_load(override)["services"]["web"]
        assert "tmpfs" not in web

    def test_user_volume_with_options_targets_tmp_omits_overlay_tmpfs(self) -> None:
        """`/tmp:/tmp:ro` — short syntax, target is /tmp."""
        user_compose = {
            "services": {
                "web": {
                    "image": "nginx",
                    "volumes": ["/host/tmp:/tmp:ro"],
                },
            },
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        web = yaml.safe_load(override)["services"]["web"]
        assert "tmpfs" not in web

    def test_per_service_omission_does_not_leak(self) -> None:
        """Two services, only one declares read_only. Overlay omits on
        that service only — the other still gets the v0.8 default."""
        manifest = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {
                "web": {"type": "frontend", "port": 3000, "routes": [{"path": "/"}]},
                "worker": {"type": "backend", "port": 4000, "routes": []},
            },
        }
        user_compose = {
            "services": {
                "web": {"image": "nginx", "read_only": False},
                "worker": {"image": "alpine"},
            },
        }
        override = generate_compose_override(
            manifest, user_compose=user_compose,
        )
        parsed = yaml.safe_load(override)
        assert "read_only" not in parsed["services"]["web"]
        assert parsed["services"]["worker"]["read_only"] is True

    def test_off_profile_service_does_not_get_v08_defaults(self) -> None:
        """A service on profile: off gets nothing from the overlay,
        regardless of user_compose declarations. The off path skips
        the security fragment entirely so omission logic doesn't run.
        """
        manifest = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {
                "web": {
                    "type": "frontend", "port": 3000,
                    "routes": [{"path": "/"}],
                    "security": {"profile": "off", "reason": "test"},
                },
            },
        }
        override = generate_compose_override(manifest, user_compose={})
        web = yaml.safe_load(override)["services"]["web"]
        assert "read_only" not in web
        assert "tmpfs" not in web


class TestWritableOverlay:
    """v0.9: writable: block translates to overlay tmpfs/volumes.

    Three states tested:
      DEFAULT: no writable block — service emits v0.8 baseline only
      MANAGED: writable.ephemeral / .persistent — overlay generates tmpfs/volumes
      EXTERNAL: writable.external: true — overlay emits no tmpfs/volume entries
    """

    def _manifest(self, writable=None, with_limits=False):
        m = {
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {
                "web": {
                    "type": "frontend",
                    "port": 3000,
                    "routes": [{"path": "/"}],
                },
            },
        }
        if writable is not None:
            m["services"]["web"]["writable"] = writable
        if with_limits:
            m["services"]["web"]["limits"] = {"memory": "256m"}
        return m

    # --- State DEFAULT ----------------------------------------------------

    def test_default_state_baseline_unchanged(self) -> None:
        """Regression: service with no writable: block stays on v0.8 baseline."""
        override = generate_compose_override(self._manifest(), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert web["read_only"] is True
        assert web["tmpfs"] == ["/tmp"]
        # Volumes are NOT introduced into State 1 services.
        assert "volumes" not in web or web.get("volumes") == [
            _PROD_SMOKE_MOUNT
        ]

    # --- State MANAGED ----------------------------------------------------

    def test_ephemeral_appended_to_baseline_tmpfs(self) -> None:
        override = generate_compose_override(self._manifest(writable={
            "ephemeral": ["/var/cache/nginx", "/var/run"],
        }), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        # /tmp baseline is preserved; ephemeral entries appear after.
        assert web["tmpfs"] == ["/tmp", "/var/cache/nginx", "/var/run"]
        assert web["read_only"] is True

    def test_ephemeral_with_explicit_tmp_dedupes(self) -> None:
        override = generate_compose_override(self._manifest(writable={
            "ephemeral": ["/tmp", "/var/run"],
        }), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        # /tmp appears exactly once.
        assert web["tmpfs"].count("/tmp") == 1
        assert "/var/run" in web["tmpfs"]

    def test_persistent_emits_volume_reference(self) -> None:
        override = generate_compose_override(self._manifest(writable={
            "persistent": [{"name": "dbdata", "mount": "/app/data"}],
        }), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        vols = web["volumes"]
        assert _volume("demo_dbdata", "/app/data") in vols

    def test_persistent_emits_top_level_volumes_block(self) -> None:
        override = generate_compose_override(self._manifest(writable={
            "persistent": [{"name": "dbdata", "mount": "/app/data"}],
        }), user_compose={})
        parsed = yaml.safe_load(override)
        # Top-level volumes: block declares the named volume.
        assert "volumes" in parsed
        assert "demo_dbdata" in parsed["volumes"]
        # Value should be {} or None (Docker auto-creates).
        assert parsed["volumes"]["demo_dbdata"] in (None, {})

    def test_persistent_multiple_volumes(self) -> None:
        override = generate_compose_override(self._manifest(writable={
            "persistent": [
                {"name": "dbdata", "mount": "/app/data"},
                {"name": "uploads", "mount": "/app/uploads"},
            ],
        }), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert _volume("demo_dbdata", "/app/data") in web["volumes"]
        assert _volume("demo_uploads", "/app/uploads") in web["volumes"]
        assert "demo_dbdata" in parsed["volumes"]
        assert "demo_uploads" in parsed["volumes"]

    def test_persistent_plus_smoke_volumes_coexist(self) -> None:
        m = self._manifest(writable={
            "persistent": [{"name": "dbdata", "mount": "/app/data"}],
        })
        m["services"]["web"]["smoke"] = "smoke.sh"
        override = generate_compose_override(m, user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        # Smoke mount must still be present.
        assert _PROD_SMOKE_MOUNT in web["volumes"]
        # And the persistent volume too.
        assert _volume("demo_dbdata", "/app/data") in web["volumes"]

    def test_managed_both_ephemeral_and_persistent(self) -> None:
        override = generate_compose_override(self._manifest(writable={
            "ephemeral": ["/var/run"],
            "persistent": [{"name": "dbdata", "mount": "/app/data"}],
        }), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert "/var/run" in web["tmpfs"]
        assert _volume("demo_dbdata", "/app/data") in web["volumes"]

    # --- State EXTERNAL ---------------------------------------------------

    def test_external_suppresses_tmpfs_baseline(self) -> None:
        override = generate_compose_override(self._manifest(writable={
            "external": True,
        }), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        # Boxmunge emits NO tmpfs — not even /tmp.
        assert "tmpfs" not in web

    def test_external_suppresses_volumes(self) -> None:
        # External services with smoke would still need the smoke mount.
        # But without smoke, no volumes entry should appear.
        override = generate_compose_override(self._manifest(writable={
            "external": True,
        }), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        # No "volumes" key on the service — the operator owns this surface.
        assert "volumes" not in web

    def test_external_keeps_read_only(self) -> None:
        """External writability is orthogonal to read_only. The default
        baseline of read_only:true still applies — operator opts out
        separately via compose."""
        override = generate_compose_override(self._manifest(writable={
            "external": True,
        }), user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert web["read_only"] is True

    def test_external_with_smoke_still_mounts_scripts(self) -> None:
        """An external service still needs the smoke-scripts mount for
        its smoke test. That's a boxmunge concern, not the operator's."""
        m = self._manifest(writable={"external": True})
        m["services"]["web"]["smoke"] = "smoke.sh"
        override = generate_compose_override(m, user_compose={})
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        assert _PROD_SMOKE_MOUNT in web.get(
            "volumes", []
        )

    # --- regression: existing user-wins-on-tmpfs still works in DEFAULT ---

    def test_default_state_user_wins_on_tmpfs_unchanged(self) -> None:
        """v0.8 rule: user compose tmpfs overrides overlay baseline.
        This still applies in State DEFAULT (no writable block).
        """
        user_compose = {
            "services": {"web": {"tmpfs": ["/tmp:size=128m"]}},
        }
        override = generate_compose_override(
            self._manifest(), user_compose=user_compose,
        )
        parsed = yaml.safe_load(override)
        web = parsed["services"]["web"]
        # Overlay omits its /tmp baseline so user value wins via compose merge.
        assert "tmpfs" not in web


class TestBuiltImageNames:
    """The overlay names every built image (see compose_images)."""

    _MANIFEST = {"project": "myapp", "services": {"web": {"port": 80}}}
    _USER = {"services": {"web": {"build": ".", "image": "postgres:16"},
                          "worker": {"build": "./worker"},
                          "db": {"image": "postgres:16"}}}

    def test_production_names_every_build_service(self) -> None:
        services = yaml.safe_load(
            generate_compose_override(self._MANIFEST, user_compose=self._USER))["services"]
        assert services["web"]["image"] == "boxmunge.invalid/myapp/web"
        assert services["worker"]["image"] == "boxmunge.invalid/myapp/worker"
        assert "image" not in services["db"]

    def test_staging_builds_under_its_own_compose_project(self) -> None:
        services = yaml.safe_load(generate_staging_compose_override(
            self._MANIFEST, user_compose=self._USER))["services"]
        assert services["web"]["image"] == "boxmunge.invalid/myapp-staging/web"


def test_production_env_files_names_only_files_that_exist(paths) -> None:
    from boxmunge.compose import production_env_files
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    assert production_env_files(paths, "myapp") == {}
    paths.host_secrets.write_text("")
    (project_dir / "project.env").write_text("")
    paths.project_secrets("myapp").write_text("")
    assert production_env_files(paths, "myapp") == {
        "host_secrets": str(paths.host_secrets), "project_env": "./project.env",
        "project_secrets": "./secrets.env"}

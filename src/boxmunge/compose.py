"""Generate Docker Compose override files for boxmunge proxy networking."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from boxmunge import compose_resolve, docker
from boxmunge.compose_images import built_image_name
from boxmunge.compose_mounts import PROD_SMOKE_SOURCE, STAGING_SMOKE_SOURCE
from boxmunge.fileutil import atomic_write_text
from boxmunge.live_mounts import LiveMounts, plan_live_mounts, sync_live_mounts
from boxmunge.manifest import load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.published_ports import overlay_ports
from boxmunge.release import project_data_dirs, sync_live_scripts
from boxmunge.release_staging import production_release_root
from boxmunge.compose_hardening import hardening_fragment
from boxmunge.security_warn import (
    warn_off_services, warn_published_ports, warn_writable_state,
)
from boxmunge.writable import WritableState, classify_state


class ComposeError(ValueError):
    """Raised when a compose document is structurally invalid for boxmunge use."""


def _build_env_file_list(env_files: dict[str, str] | None) -> list[str]:
    """Build ordered env_file list from an env_files dict."""
    if not env_files:
        return []
    result = []
    for key in ("host_secrets", "project_env", "project_secrets"):
        if key in env_files:
            result.append(env_files[key])
    return result


def _user_services(user_compose: dict[str, Any]) -> dict[str, Any]:
    """Return the `services` mapping of a parsed user compose document."""
    if not isinstance(user_compose, dict):
        raise ComposeError(
            f"user compose must be a mapping (got {type(user_compose).__name__})"
        )
    services = user_compose.get("services") or {}
    if not isinstance(services, dict):
        raise ComposeError(
            f"compose.yml 'services' must be a mapping "
            f"(got {type(services).__name__})"
        )
    return services


def _build_service_override(
    manifest: dict[str, Any],
    env_file_list: list[str],
    *,
    user_compose: dict[str, Any],
    alias_prefix: str | None = None,
) -> dict[str, Any]:
    """Build per-service overrides for every service.

    Every service, whether the manifest declares it or it exists only in
    compose.yml (a database, cache, or sidecar), gets the container
    hardening fragment for its effective profile. Compose-only services
    resolve against the project-level `security:` block and, for now, do
    not get the read-only rootfs or its /tmp tmpfs. Manifest services add
    routing on top: network aliases for routable services, env_files,
    resource limits, the smoke-script mount, and the writable: translation.

    `user_compose` (the resolved compose model) supplies the compose-only
    services and the user's own read_only / tmpfs declarations.
    """
    project = manifest["project"]
    prefix = alias_prefix or project
    project_security = manifest.get("security")
    services: dict[str, Any] = {}

    manifest_services = manifest.get("services", {})
    if not isinstance(manifest_services, dict):
        raise ComposeError(
            f"manifest 'services' must be a mapping "
            f"(got {type(manifest_services).__name__})"
        )

    user_services = _user_services(user_compose)

    for svc_name, svc in manifest_services.items():
        svc_override: dict[str, Any] = {}
        routes = svc.get("routes", [])

        if routes:
            alias = f"{prefix}-{svc_name}"
            svc_override["networks"] = {
                "default": {},
                "boxmunge-proxy": {"aliases": [alias]},
            }

        if env_file_list:
            svc_override["env_file"] = list(env_file_list)

        limits = svc.get("limits")
        if limits:
            svc_override["deploy"] = {"resources": {"limits": dict(limits)}}

        # Collect service-level volumes here so smoke + persistent
        # writable entries can coexist on one list (Compose merge with
        # the user's compose.yml extends lists, never replaces).
        # Long syntax throughout: a path is never re-read as `src:dst:opts`.
        # create_host_path keeps the short syntax's behaviour for the smoke
        # mount (an absent scripts dir surfaces as a smoke failure).
        svc_volumes: list[dict[str, Any]] = []
        if svc.get("smoke"):
            # Production mounts its own copy: `stage` overwrites the project
            # dir's scripts while production keeps running.
            source = PROD_SMOKE_SOURCE if alias_prefix is None else STAGING_SMOKE_SOURCE
            svc_volumes.append({"type": "bind", "source": source,
                                "target": "/boxmunge-scripts", "read_only": True,
                                "bind": {"create_host_path": True}})

        # Security hardening — silent defaults injected here.
        sec_fragment = hardening_fragment(
            project_security, svc.get("security"), user_services.get(svc_name),
        )

        # v0.9: writable: block translation. Three states.
        # See docs/superpowers/specs/2026-05-08-v0.9-writable-abstraction-design.md
        state = classify_state(svc)
        if state is WritableState.EXTERNAL:
            # Operator owns writability entirely. Overlay emits no tmpfs
            # (not even /tmp) and no volumes. read_only baseline is left
            # alone — operator can still opt out separately via compose.
            sec_fragment.pop("tmpfs", None)
        elif state is WritableState.MANAGED:
            writable_block = svc.get("writable") or {}
            ephemeral = writable_block.get("ephemeral") or []
            persistent = writable_block.get("persistent") or []
            # Append ephemeral entries to the baseline tmpfs list, deduping
            # the /tmp baseline if the operator declared /tmp explicitly.
            baseline_tmpfs = list(sec_fragment.get("tmpfs", []))
            for path in ephemeral:
                if path not in baseline_tmpfs:
                    baseline_tmpfs.append(path)
            if baseline_tmpfs:
                sec_fragment["tmpfs"] = baseline_tmpfs
            # Translate persistent entries into named-volume references
            # keyed <project>_<name>. Compose prefixes the key with the
            # compose project name, so the Docker volume is
            # <compose-project>_<project>_<name> (staging gets its own).
            # Cross-service uniqueness of `name` is enforced at manifest
            # validation time.
            for entry in persistent:
                if not isinstance(entry, dict):
                    continue
                vol_name = f"{project}_{entry['name']}"
                svc_volumes.append({"type": "volume", "source": vol_name,
                                    "target": entry["mount"]})

        if svc_volumes:
            svc_override["volumes"] = svc_volumes

        # Avoid Docker Compose's "can't set distinct values on 'pids_limit'
        # and 'deploy.resources.limits.pids'" error: when manifest limits
        # already created a deploy.resources.limits block, nest pids_limit
        # under it as `pids` rather than emitting at the top level.
        if "deploy" in svc_override and "pids_limit" in sec_fragment:
            pids_value = sec_fragment.pop("pids_limit")
            svc_override["deploy"]["resources"]["limits"]["pids"] = pids_value

        svc_override.update(sec_fragment)

        if svc_override:
            services[svc_name] = svc_override

    # Opt-in published ports, production only: staging would collide with
    # production's host ports.
    if alias_prefix is None:
        for svc_name, ports in overlay_ports(project_security).items():
            services.setdefault(svc_name, {})["ports"] = ports

    # Compose-only services get every flag but read_only/tmpfs, which would break
    # existing databases on the next regen (see security_warn.undeclared_services).
    for svc_name, user_svc in user_services.items():
        if svc_name in manifest_services:
            continue
        fragment = hardening_fragment(project_security, None, user_svc)
        fragment.pop("read_only", None)
        fragment.pop("tmpfs", None)
        if fragment:
            services[svc_name] = {**services.get(svc_name, {}), **fragment}

    # The platform names every built image (see compose_images); `prefix` is
    # the compose project, so staging builds never replace production's.
    for svc_name, user_svc in user_services.items():
        if isinstance(user_svc, dict) and user_svc.get("build") is not None:
            services.setdefault(svc_name, {})["image"] = built_image_name(prefix, svc_name)

    return services


def managed_volume_keys(manifest: dict[str, Any]) -> list[str]:
    """Compose keys (`<project>_<name>`) of the named volumes the overlay
    emits for State MANAGED services' `writable.persistent` entries.

    See the note in `_build_service_override` for the resulting Docker
    volume name.
    """
    project = manifest.get("project", "")
    keys: list[str] = []
    services_block = manifest.get("services", {})
    if not isinstance(services_block, dict):
        return keys
    for svc in services_block.values():
        if not isinstance(svc, dict):
            continue
        if classify_state(svc) is not WritableState.MANAGED:
            continue
        writable_block = svc.get("writable") or {}
        persistent = writable_block.get("persistent") or []
        for entry in persistent:
            if not isinstance(entry, dict):
                continue
            keys.append(f"{project}_{entry['name']}")
    return keys


def _build_top_level_volumes(manifest: dict[str, Any]) -> dict[str, dict]:
    """Build the top-level `volumes:` block declaring the managed named
    volumes. Each gets an empty mapping — Docker auto-creates on first deploy.
    """
    return {key: {} for key in managed_volume_keys(manifest)}


def generate_compose_override(
    manifest: dict[str, Any],
    env_files: dict[str, str] | None = None,
    *,
    user_compose: dict[str, Any],
    live_mounts: LiveMounts | None = None,
) -> str:
    """Generate compose.boxmunge.yml content.

    Hardens every service in `user_compose` and the manifest, adds
    boxmunge-proxy network aliases to routable services, env_file
    directives to manifest services, and resource limits where declared.

    `user_compose`: the parsed user compose.yml dict, the same document
    `validate_user_compose` checked. Required: without it the overlay
    could not see compose-only services, and they would run unhardened.
    `live_mounts`: production's mounts of release code re-pointed at its
    own copies (see live_mounts).
    """
    return _render_override(manifest, env_files, user_compose, alias_prefix=None,
                            live_mounts=live_mounts or LiveMounts())


def _render_override(
    manifest: dict[str, Any],
    env_files: dict[str, str] | None,
    user_compose: dict[str, Any],
    alias_prefix: str | None,
    live_mounts: LiveMounts = LiveMounts(),
) -> str:
    env_file_list = _build_env_file_list(env_files)
    services = _build_service_override(
        manifest, env_file_list, user_compose=user_compose, alias_prefix=alias_prefix,
    )
    for svc_name, entries in live_mounts.volumes.items():
        svc = services.setdefault(svc_name, {})
        svc["volumes"] = [*svc.get("volumes", []), *entries]
    override: dict[str, Any] = {"networks": {"boxmunge-proxy": {"external": True}}}
    if services:
        override["services"] = services
    top_level_volumes = _build_top_level_volumes(manifest)
    if top_level_volumes:
        override["volumes"] = top_level_volumes
    override.update(live_mounts.files)
    return yaml.dump(override, default_flow_style=False, sort_keys=False)


def load_user_compose(compose_path: Path, project_name: str) -> dict[str, Any]:
    """Return the resolved user compose model for overlay generation.

    Validation has already been done upstream by `validate_user_compose`;
    the overlay needs every service Compose will run, including ones that
    arrive through `include:` or `extends:`, and the user's own
    read_only / tmpfs declarations, so it reads the same resolved model
    (`docker compose config`). Raises ComposeError if the file cannot be
    resolved: generating an overlay without it would leave services
    unhardened.
    """
    try:
        return compose_resolve.resolve_compose_config(compose_path, project_name)
    except compose_resolve.ComposeResolveError as e:
        raise ComposeError(f"cannot resolve {compose_path}: {e}") from e


def prepare_compose_override(
    paths: BoxPaths,
    manifest: dict[str, Any],
    component: str = "deploy",
    release_root: Path | None = None,
) -> None:
    """Generate compose.boxmunge.yml for a project, and refresh the copy of
    the smoke scripts it mounts.

    `component` labels the SECURITY OFF log entry so callers from upgrade /
    resume don't misattribute the warning as "deploy". Lives here, not in
    commands/, to avoid `commands/`-to-`commands/` imports (audit A-2).

    `release_root` holds the release production will run. Deploy passes the
    project dir (a promote deploys the staged release there); everyone else
    regenerates for the release production already runs, which during a
    stage is the kept one, not the staged one in the project dir. Its
    compose.yml is the one production runs, and its mounted release code is
    copied for production (see live_mounts).
    """
    project_name = manifest["project"]
    project_dir = paths.project_dir(project_name)
    if release_root is None:
        release_root = production_release_root(paths, project_name)
        if release_root != project_dir:
            # The caller read the staged release's manifest from the project dir.
            manifest = load_manifest(release_root / "manifest.yml")
    sync_live_scripts(paths, project_name, release_root)
    override_path = paths.project_compose_override(project_name)
    override_path.parent.mkdir(parents=True, exist_ok=True)

    # Build env_files based on which files exist
    env_files: dict[str, str] = {}
    if paths.host_secrets.exists():
        env_files["host_secrets"] = str(paths.host_secrets)
    project_env = paths.project_dir(project_name) / "project.env"
    if project_env.exists():
        env_files["project_env"] = "./project.env"
    project_secrets = paths.project_secrets(project_name)
    if project_secrets.exists():
        env_files["project_secrets"] = "./secrets.env"

    user_compose = load_user_compose(release_root / "compose.yml", project_name)
    live_mounts = plan_live_mounts(user_compose, release_root, project_data_dirs(project_dir).box_state())
    sync_live_mounts(project_dir, release_root, live_mounts)

    content = generate_compose_override(
        manifest, env_files=env_files or None, user_compose=user_compose,
        live_mounts=live_mounts,
    )
    atomic_write_text(override_path, content)
    # Before the overlay named built images under boxmunge.invalid/, Compose
    # tagged them `<project>-<service>` or the service's own `image:`, names
    # any other project could run. Drop those names from images whose
    # Compose labels prove this project built them; a running container keeps
    # its image, and the next up rebuilds under the new name.
    services = _user_services(user_compose)
    build_services = {name: svc.get("image") for name, svc in services.items()
                      if isinstance(svc, dict) and svc.get("build") is not None}
    for compose_project in (project_name, f"{project_name}-staging"):
        docker.untag_old_built_names(
            compose_project, build_services, set(services) - set(build_services))

    # Deploy-time warning for any service resolving to profile: off.
    # Repeated by design — see spec §"Deploy-time warning".
    warn_off_services(paths, manifest, component=component)
    # v0.9: deploy-time visibility for writable surface choices —
    # [WARNING] for read_only:false in user compose, [INFO] for
    # writable.external in manifest. Both repeated every deploy.
    warn_writable_state(paths, manifest, user_compose, component=component)
    warn_published_ports(paths, manifest, component=component)


def generate_staging_compose_override(
    manifest: dict[str, Any],
    env_files: dict[str, str] | None = None,
    *,
    user_compose: dict[str, Any],
) -> str:
    """Generate compose.boxmunge-staging.yml content.

    Like the standard override, but with '-staging' suffixed network aliases.
    Includes env_files and resource limits so staging matches production.

    `user_compose`: parsed user compose.yml. Same threading as the
    production override — see `generate_compose_override`.
    """
    return _render_override(
        manifest, env_files, user_compose,
        alias_prefix=f"{manifest['project']}-staging",
    )

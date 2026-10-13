"""Generate Docker Compose override files for boxmunge proxy networking."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from boxmunge import compose_resolve
from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths
from boxmunge.published_ports import overlay_ports
from boxmunge.security_overlay import (
    resolve_security,
    render_compose_security_fragment,
)
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


# ---------------------------------------------------------------------------
# v0.8: user-wins-on-explicit-declarations for read_only / tmpfs.
#
# Compose's merge keeps the later file's scalar (the overlay would overwrite
# a deliberate `read_only: false`) and concatenates lists (a user
# `tmpfs: ['/tmp:size=128m']` would clash with the overlay's `/tmp`). So the
# overlay omits either field when the user already declared it for that
# service, rather than rejecting the declaration.
# ---------------------------------------------------------------------------


def _user_declared_read_only(svc: dict[str, Any]) -> bool:
    """True iff the user compose declares `read_only` on this service.

    Any value counts (True or False) — the point is "the user has
    expressed intent", not "the user agrees with the overlay".
    """
    return "read_only" in svc


def _volume_target(entry: Any) -> str | None:
    """Extract the container target path from a compose volume entry.

    Short syntax: 'src:target[:opts]' — if it has a colon, the second
    field is the target. Anonymous volume short syntax ('/path' with
    no colon) is itself the target.
    Long syntax: {target: '/path', ...}.
    """
    if isinstance(entry, str):
        if ":" not in entry:
            # Anonymous volume — the whole string is the target.
            return entry
        parts = entry.split(":")
        if len(parts) >= 2:
            return parts[1]
        return None
    if isinstance(entry, dict):
        target = entry.get("target")
        return target if isinstance(target, str) else None
    return None


def _tmpfs_target(entry: Any) -> str | None:
    """Extract the target path from a compose tmpfs entry.

    Short syntax: '/tmp' or '/tmp:size=64m' — target is everything before
    the first colon.
    """
    if not isinstance(entry, str):
        return None
    if ":" in entry:
        return entry.split(":", 1)[0]
    return entry


def _user_claims_tmp(svc: dict[str, Any]) -> bool:
    """True iff the user compose has any /tmp claim on this service.

    Conservative detection over both `tmpfs` (string list) and `volumes`
    (short or long syntax). A weird combo that slips through would
    surface as a Compose-up time error, which is acceptable.
    """
    tmpfs = svc.get("tmpfs")
    if isinstance(tmpfs, list):
        for entry in tmpfs:
            if _tmpfs_target(entry) == "/tmp":
                return True
    volumes = svc.get("volumes")
    if isinstance(volumes, list):
        for entry in volumes:
            if _volume_target(entry) == "/tmp":
                return True
    return False


def _hardening_fragment(
    project_security: dict[str, Any] | None,
    service_security: dict[str, Any] | None,
    user_svc: Any,
) -> dict[str, Any]:
    """Render one service's hardening fragment for its effective profile.

    v0.8 user-wins rule: when compose.yml already declares `read_only` or
    claims `/tmp` for this service, the overlay omits its own value. See
    the module-level comment above `_user_declared_read_only` for why we
    omit instead of reject for these two fields.
    """
    resolved = resolve_security(project_security, service_security)
    fragment = render_compose_security_fragment(resolved)
    if isinstance(user_svc, dict):
        if "read_only" in fragment and _user_declared_read_only(user_svc):
            fragment.pop("read_only")
        if "tmpfs" in fragment and _user_claims_tmp(user_svc):
            fragment.pop("tmpfs")
    return fragment


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
        svc_volumes: list[str] = []
        if svc.get("smoke"):
            svc_volumes.append("./boxmunge-scripts:/boxmunge-scripts:ro")

        # Security hardening — silent defaults injected here.
        sec_fragment = _hardening_fragment(
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
                svc_volumes.append(f"{vol_name}:{entry['mount']}")

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
        fragment = _hardening_fragment(project_security, None, user_svc)
        fragment.pop("read_only", None)
        fragment.pop("tmpfs", None)
        if fragment:
            services[svc_name] = {**services.get(svc_name, {}), **fragment}

    return services


def _build_top_level_volumes(manifest: dict[str, Any]) -> dict[str, dict]:
    """Build the top-level `volumes:` block declaring named volumes the
    overlay emitted for State MANAGED services.

    Each named volume gets an empty mapping — Docker auto-creates on
    first deploy. Keys are `<project>_<name>`; see the note in
    `_build_service_override` for the resulting Docker volume name.
    """
    project = manifest.get("project", "")
    out: dict[str, dict] = {}
    services_block = manifest.get("services", {})
    if not isinstance(services_block, dict):
        return out
    for svc_name, svc in services_block.items():
        if not isinstance(svc, dict):
            continue
        if classify_state(svc) is not WritableState.MANAGED:
            continue
        writable_block = svc.get("writable") or {}
        persistent = writable_block.get("persistent") or []
        for entry in persistent:
            if not isinstance(entry, dict):
                continue
            vol_name = f"{project}_{entry['name']}"
            out[vol_name] = {}
    return out


def generate_compose_override(
    manifest: dict[str, Any],
    env_files: dict[str, str] | None = None,
    *,
    user_compose: dict[str, Any],
) -> str:
    """Generate compose.boxmunge.yml content.

    Hardens every service in `user_compose` and the manifest, adds
    boxmunge-proxy network aliases to routable services, env_file
    directives to manifest services, and resource limits where declared.

    `user_compose`: the parsed user compose.yml dict, the same document
    `validate_user_compose` checked. Required: without it the overlay
    could not see compose-only services, and they would run unhardened.
    """
    return _render_override(manifest, env_files, user_compose, alias_prefix=None)


def _render_override(
    manifest: dict[str, Any],
    env_files: dict[str, str] | None,
    user_compose: dict[str, Any],
    alias_prefix: str | None,
) -> str:
    env_file_list = _build_env_file_list(env_files)
    services = _build_service_override(
        manifest, env_file_list, user_compose=user_compose, alias_prefix=alias_prefix,
    )
    override: dict[str, Any] = {"networks": {"boxmunge-proxy": {"external": True}}}
    if services:
        override["services"] = services
    top_level_volumes = _build_top_level_volumes(manifest)
    if top_level_volumes:
        override["volumes"] = top_level_volumes
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
) -> None:
    """Generate compose.boxmunge.yml for a project.

    `component` labels the SECURITY OFF log entry so callers from upgrade /
    resume don't misattribute the warning as "deploy". Lives here, not in
    commands/, to avoid `commands/`-to-`commands/` imports (audit A-2).
    """
    project_name = manifest["project"]
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

    user_compose = load_user_compose(paths.project_compose(project_name), project_name)

    content = generate_compose_override(
        manifest, env_files=env_files or None, user_compose=user_compose,
    )
    atomic_write_text(override_path, content)

    # Deploy-time warning for any service resolving to profile: off.
    # Repeated by design — see spec §"Deploy-time warning".
    warn_off_services(paths, manifest, component=component)
    # v0.9: deploy-time visibility for writable surface choices —
    # [WARNING] for read_only:false in user compose, [INFO] for
    # writable.external in manifest. Both repeated every deploy.
    warn_writable_state(paths, manifest, user_compose, component=component)
    warn_published_ports(paths, manifest, component=component)


def is_bind_mount(volume_str: str) -> bool:
    """Check if a short-syntax volume string is a bind mount (starts with . / or ~)."""
    host_part = volume_str.split(":")[0]
    return host_part.startswith((".", "/", "~"))


def _staging_volume(entry: Any) -> Any:
    """Point a bind mount (short or long syntax) at its -staging sibling."""
    if isinstance(entry, dict) and entry.get("type") == "bind":
        return {**entry, "source": f"{entry['source']}-staging"}
    if isinstance(entry, str) and is_bind_mount(entry):
        return _rewrite_bind_mount(entry)
    return entry


def _rewrite_bind_mount(volume_str: str) -> str:
    """Rewrite a bind-mount host path to add -staging suffix.

    ./data:/app/data       -> ./data-staging:/app/data
    ./data:/app/data:ro    -> ./data-staging:/app/data:ro
    /abs/path:/container   -> /abs/path-staging:/container
    """
    parts = volume_str.split(":")
    host_path = parts[0]
    parts[0] = host_path + "-staging"
    return ":".join(parts)


def generate_staging_compose_base(compose_path: str | Path) -> str:
    """Read compose.yml and return a copy with ports stripped and bind mounts rewritten.

    Staging runs alongside production with a different project name.
    Docker Compose list-merging means an override file cannot remove ports
    declared in the base, so we generate a staging-specific base instead.
    Bind-mount host paths get a -staging suffix to prevent data sharing.
    Named volumes are left unchanged — Docker Compose's project naming
    already isolates them. Services pulled in by `include:` or
    `extends: {file: ...}` live in other files this rewrite cannot reach,
    so those are refused rather than staged with production's mounts.
    """
    raw = Path(compose_path).read_text()
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict):
        raise ComposeError(
            f"compose.yml must be a YAML mapping at the top level "
            f"(got {type(doc).__name__})"
        )
    services = doc.get("services")
    if services is not None and not isinstance(services, dict):
        raise ComposeError(
            f"compose.yml 'services' must be a mapping "
            f"(got {type(services).__name__})"
        )
    other_files = "include" in doc or any(
        isinstance(svc, dict) and isinstance(svc.get("extends"), dict)
        and "file" in svc["extends"] for svc in (services or {}).values()
    )
    if other_files:
        raise ComposeError(
            "stage cannot separate staging from production for services that "
            "come from include: or extends: file: (their bind mounts would be "
            "shared with production). Move those services into compose.yml to "
            "use stage."
        )
    for svc in (services or {}).values():
        if not isinstance(svc, dict):
            # Malformed entry: leave it for Compose to reject.
            continue
        svc.pop("ports", None)
        volumes = svc.get("volumes")
        if volumes:
            svc["volumes"] = [_staging_volume(v) for v in volumes]
    return yaml.dump(doc, default_flow_style=False, sort_keys=False)


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

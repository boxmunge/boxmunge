# SPDX-License-Identifier: Apache-2.0
"""Which user each service runs as.

`security.user` (project level, overridden per service) is `root`, `image`
or "<uid>:<gid>" with both ids in 1..65535; `root` and `image` need the
block's `reason`, as other opt-outs do. A compose `user:` is the operator's
explicit choice and wins; its numeric parts must be mappable (0..65535).

Deploy, stage and promote decide who each service runs as from its images
(`effective_user`) and record it in `state/deploy/<p>[-staging].users.json`;
every later start replays the record, so an upgrade or a restart never
changes a service's user.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow
from boxmunge.security_overlay import PROFILE_OFF, SecurityValidationError, effective_profile

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

USER_ROOT = "root"
USER_IMAGE = "image"
MAX_ID = 65535
_NUMERIC = re.compile(r"([0-9]+):([0-9]+)")  # [0-9], not \d: ASCII digits only
_DIGITS = re.compile(r"[0-9]+")
_SIGNED = re.compile(r"[+-][0-9]+")


def validate_user_field(block: dict[str, Any], context: str) -> None:
    """Check a security block's `user`. Raises SecurityValidationError."""
    if "user" not in block:
        return
    value = block["user"]
    if isinstance(value, bool) or not isinstance(value, str):
        raise SecurityValidationError(
            f"{context}: security.user must be a string: root, image, or a quoted "
            f"\"<uid>:<gid>\" (unquoted, YAML may read it as a number), got {value!r}")
    if value in (USER_ROOT, USER_IMAGE):
        reason = block.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            who = "root" if value == USER_ROOT else "the image's own user, which may be root"
            raise SecurityValidationError(
                f"{context}: security.user: {value} runs the service as {who}, so it "
                f"needs a non-empty reason in the same security block")
        return
    match = _NUMERIC.fullmatch(value)
    if match is None or not all(1 <= int(g) <= MAX_ID for g in match.groups()):
        raise SecurityValidationError(
            f"{context}: security.user {value!r} must be root, image, or \"<uid>:<gid>\" "
            f"with each id between 1 and {MAX_ID} (a gid of 0 only through root or image)")


def declared_user(project_security: dict[str, Any] | None,
                  manifest_service: dict[str, Any] | None) -> tuple[str | None, str | None]:
    """(security.user, its block's reason): the service's own, else the project's."""
    svc_sec = (manifest_service or {}).get("security") if isinstance(manifest_service, dict) else None
    for block in (svc_sec, project_security):
        if isinstance(block, dict) and "user" in block:
            return block["user"], block.get("reason")
    return None, None


def compose_user_text(raw: Any) -> str | None:
    """A compose `user:` as Docker reads it (YAML may give an int), or None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return str(raw)
    return raw if isinstance(raw, str) and raw.strip() else None


def _id_parts(text: str) -> list[str]:
    return text.split(":", 1)


def compose_user_problems(services: dict[str, Any],
                          manifest_services: dict[str, Any] | None) -> list[str]:
    """Compose `user:` values boxmunge refuses on every box: not a uid, name
    or uid:gid; a signed id (Docker parses ids with Atoi, which takes a
    sign, so "+70000" is uid 70000, not a name); a compose `user:` on a
    service whose own manifest security block also sets `user`."""
    problems = []
    for name, svc in services.items():
        if not isinstance(svc, dict) or "user" not in svc:
            continue
        text = compose_user_text(svc["user"])
        if text is None:
            problems.append(f"service {name}: user = {svc['user']!r} must be a uid, a "
                            f"name, or uid:gid")
            continue
        for part in _id_parts(text):
            if _SIGNED.fullmatch(part):
                problems.append(f"service {name}: user = {text!r}: write the id {part} "
                                f"without a sign (Docker reads it as a number)")
        own = (manifest_services or {}).get(name)
        own_sec = own.get("security") if isinstance(own, dict) else None
        if isinstance(own_sec, dict) and "user" in own_sec:
            problems.append(f"service {name}: compose.yml sets user: {text!r} and the "
                            f"manifest sets security.user: {own_sec['user']!r}; keep one")
    return problems


def unmappable_users(services: dict[str, Any]) -> list[str]:
    """Compose `user:` ids above 65535, which a remapped daemon cannot map.
    Refused on a remapped box; a warning before the migration, whose
    preflight refuses the project."""
    problems = []
    for name, svc in services.items():
        text = compose_user_text(svc.get("user")) if isinstance(svc, dict) else None
        for part in _id_parts(text) if text else []:
            if _DIGITS.fullmatch(part) and int(part) > MAX_ID:
                problems.append(f"service {name}: user = {text!r}: id {part} is above "
                                f"{MAX_ID}, which a remapped daemon cannot map. Use an id "
                                f"between 0 and {MAX_ID}")
    return problems


DEFAULT_USER = "10001:10001"
SOURCE_COMPOSE = "compose"
SOURCE_MANIFEST = "manifest"
SOURCE_IMAGE = "image"
SOURCE_DEFAULT = "default"
SOURCE_OFF = "profile-off"
SOURCE_CHOWN = "data-chown"
SOURCES = frozenset({SOURCE_COMPOSE, SOURCE_MANIFEST, SOURCE_IMAGE, SOURCE_DEFAULT,
                     SOURCE_OFF, SOURCE_CHOWN})
# The sources whose user the overlay emits; the others run what the image
# or compose.yml says.
_EMITTED = frozenset({SOURCE_MANIFEST, SOURCE_DEFAULT, SOURCE_CHOWN})
_REDECIDE = ("boxmunge cannot replay it: remove it and deploy the project again, "
             "which decides every service's user afresh")
IMAGE_REASON = "runs as the image's own default user, root; its entrypoint drops privileges"


class RunAsError(Exception):
    """A service cannot be given a user, or the users record is unreadable;
    the message says what to do."""


def identity(value: str | None) -> str:
    """The user part of a user spec; 'root' for every spelling of root
    (Docker runs '', '0', 'root', '0:<gid>' and 'root:<group>' as uid 0)."""
    part = (value or "").strip().split(":", 1)[0]
    return "root" if part in ("", "0", "root") else part


def numeric_ids(value: str | None) -> tuple[int, int] | None:
    match = _NUMERIC.fullmatch((value or "").strip())
    return (int(match[1]), int(match[2])) if match else None


@dataclass(frozen=True)
class ServiceUser:
    """Who one service runs as, and why. `user` is the value the decision
    produced (None: the image's own user); `image_user` is the image's
    Config.User when it was decided ('' when the image sets none)."""
    user: str | None
    source: str
    image_user: str = ""

    def emitted(self) -> str | None:
        """The overlay's `user:` (None: emit nothing)."""
        return self.user if self.source in _EMITTED else None

    def runs_as(self) -> str:
        return identity(self.user if self.user is not None else self.image_user)

    def owner_ids(self) -> tuple[int, int] | None:
        """The numeric uid:gid the service writes its data as, where it is
        known: nonroot_ids, or the image's own numeric non-root USER."""
        ids = self.nonroot_ids()
        if ids is None and self.user is None:
            ids = numeric_ids(self.image_user)
        return ids if ids and ids[0] != 0 else None

    def nonroot_ids(self) -> tuple[int, int] | None:
        """The numeric uid:gid of a non-root user boxmunge or compose.yml
        set; None for root, names, a bare uid and the image's own user."""
        ids = numeric_ids(self.user) if self.source in _EMITTED | {SOURCE_COMPOSE} else None
        return ids if ids and ids[0] != 0 else None


def _profile_off(manifest: dict[str, Any], service: str) -> bool:
    svc = (manifest.get("services") or {}).get(service)
    svc_sec = svc.get("security") if isinstance(svc, dict) else None
    return effective_profile(manifest.get("security"), svc_sec) == PROFILE_OFF


def declaration_text(service: str, manifest: dict[str, Any]) -> str:
    """Where to put, and the manifest.yml lines that declare, `service`
    running as its image's own user, for the manifest as it stands."""
    services = manifest.get("services") or {}
    own = services.get(service) if isinstance(services, dict) else None
    sec = own.get("security") if isinstance(own, dict) else None
    lines = ["services:", f"  {service}:"]
    if not isinstance(own, dict):
        where = (f"add to manifest.yml's services (compose.yml alone defines {service}, "
                 f"so `internal: true` declares it to carry the setting; a declared "
                 f"service also gets a read-only root filesystem and the project's env "
                 f"files, so list any path it writes outside its volumes as a compose.yml "
                 f"`tmpfs:` entry, as PostgreSQL needs /var/run/postgresql)")
        lines.append("    internal: true")
    elif isinstance(sec, dict):
        where = f"merge into services.{service}.security in manifest.yml"
    else:
        where = f"merge into services.{service} in manifest.yml"
    lines += ["    security:", "      user: image"]
    if not (isinstance(sec, dict) and sec.get("reason")):
        lines.append(f'      reason: "{IMAGE_REASON}"')
    return where + ":\n\n" + "\n".join(lines) + "\n\n"


def root_refusal(service: str, image: Any, manifest: dict[str, Any]) -> str:
    return (
        f"service {service} runs the registry image {image}, which sets no non-root "
        f"USER, so it would run as root; say so in the manifest. If its entrypoint "
        f"starts as root and drops privileges (postgres, mysql, mariadb, nginx), "
        f"{declaration_text(service, manifest)}"
        f"(A security block needs `schema_version: 2` or later in manifest.yml.) "
        f"If instead it runs as a fixed non-root user from the start (redis:*-alpine "
        f"is 999:1000), write `user: \"<uid>:<gid>\"` in place of the user and reason "
        f"lines. See PROJECT_CONVENTIONS.md, \"Who a service runs as\".")


def effective_user(service: str, svc: dict[str, Any], manifest: dict[str, Any],
                   image_user: str) -> ServiceUser:
    """The spec's rules 1-5, in order: compose `user:`, `security.user`, the
    image's non-root USER, profile off, the build: default. Raises
    RunAsError (rule 5) with the lines to add."""
    compose_user = compose_user_text(svc.get("user"))
    if compose_user is not None:
        return ServiceUser(compose_user, SOURCE_COMPOSE, image_user)
    declared, _reason = declared_user(manifest.get("security"),
                                      (manifest.get("services") or {}).get(service))
    if declared is not None:
        value = {USER_ROOT: "0:0", USER_IMAGE: None}.get(declared, declared)
        return ServiceUser(value, SOURCE_MANIFEST, image_user)
    if identity(image_user) != "root":
        return ServiceUser(None, SOURCE_IMAGE, image_user)
    if _profile_off(manifest, service):
        return ServiceUser(None, SOURCE_OFF, image_user)
    if svc.get("build") is not None:
        return ServiceUser(DEFAULT_USER, SOURCE_DEFAULT, image_user)
    raise RunAsError(root_refusal(service, svc.get("image"), manifest))


def describe(user: ServiceUser) -> str:
    image = user.image_user or "root"
    if user.source == SOURCE_COMPOSE:
        return f"{user.user} (compose.yml user:)"
    if user.source == SOURCE_MANIFEST:
        if user.user is None:
            return f"the image's user, {image} (security.user: image)"
        return "root (security.user: root)" if user.user == "0:0" else f"{user.user} (security.user)"
    if user.source == SOURCE_IMAGE:
        return f"{user.image_user} (the image's USER)"
    if user.source == SOURCE_DEFAULT:
        return f"{DEFAULT_USER} (the default for a build: service with no USER)"
    if user.source == SOURCE_CHOWN:
        return f"{user.user} (set by data chown)"
    return f"the image's user, {image} (profile: off)"


def read_users(paths: BoxPaths, project: str, *, staging: bool = False) -> dict[str, ServiceUser]:
    """The users record; {} when the project has none (deployed before users
    were decided). Raises RunAsError for a record that cannot be read."""
    path = paths.project_users_record(project, staging=staging)
    try:
        doc = json.loads(read_text_nofollow(path))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise RunAsError(f"cannot read the users record {path}: {e}. {_REDECIDE}") from e
    if not isinstance(doc, dict):
        raise RunAsError(f"{path} is not a users record. {_REDECIDE}")
    out = {}
    for svc, entry in doc.items():
        if (not isinstance(entry, dict) or entry.get("source") not in SOURCES
                or not (entry.get("user") is None or isinstance(entry.get("user"), str))
                or not isinstance(entry.get("image_user"), str)):
            raise RunAsError(f"{path}: entry {svc!r} is not {{user, source, image_user}}: "
                             f"{entry!r}. {_REDECIDE}")
        user = ServiceUser(entry["user"], entry["source"], entry["image_user"])
        if user.source in _EMITTED and user.user is not None and (
                numeric_ids(user.user) is None or not all(
                    i <= MAX_ID for i in numeric_ids(user.user))):
            raise RunAsError(f"{path}: entry {svc!r} would emit user {user.user!r}, which is "
                             f"not <uid>:<gid> with ids up to {MAX_ID}. {_REDECIDE}")
        out[svc] = user
    return out


def write_users(paths: BoxPaths, project: str, users: dict[str, ServiceUser], *,
                staging: bool = False) -> None:
    doc = {svc: {"user": u.user, "source": u.source, "image_user": u.image_user}
           for svc, u in sorted(users.items())}
    atomic_write_text(paths.project_users_record(project, staging=staging),
                      json.dumps(doc, indent=2) + "\n")


def image_user_drift(paths: BoxPaths, project: str, changed: dict[str, str]) -> list[str]:
    """"<svc>: image user <old> -> <new>" for each service that runs as its
    image's own user and whose newly pulled image (`changed`: service ->
    image ref) declares another USER. Other sources pin the user in the
    overlay or compose.yml, so a new image cannot change it."""
    from boxmunge.docker_containers import image_facts  # run_as stays free of Docker
    record = read_users(paths, project)
    drift = []
    for svc, ref in sorted(changed.items()):
        rec = record.get(svc)
        if rec is None or rec.emitted() is not None or rec.source == SOURCE_COMPOSE:
            continue
        new = image_facts(ref).user
        if identity(new) != identity(rec.image_user):
            drift.append(f"{svc}: image user {rec.image_user or 'root'} -> {new or 'root'}")
    return drift


def default_user_hint(paths: BoxPaths, project: str, service: str, *,
                      staging: bool = False) -> str | None:
    """A line for a failing service that took the 10001:10001 default."""
    try:
        user = read_users(paths, project, staging=staging).get(service)
    except RunAsError as e:
        return f"  HINT: {e}"
    if user is None or user.source != SOURCE_DEFAULT:
        return None
    return (f"  HINT: {service} runs as {DEFAULT_USER}, the default for a build: service "
            f"whose image sets no USER, and that uid has no passwd entry in the image. If "
            f"the app needs one, or must write where 10001 cannot, add USER to its "
            f"Dockerfile or declare security.user in manifest.yml.")

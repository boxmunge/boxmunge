# SPDX-License-Identifier: Apache-2.0
"""Per-project image pins: a service fixed to one image autofix built.

Image tags are global to the Docker daemon (container_update_tags), so a
patched image is named under the project's own platform prefix,
`boxmunge.invalid/<project>/<service>:autofix-<first 12 hex of its image
ID>` (pin_ref): image isolation keeps every other project off it, no pull
ever asks a registry for it (compose_images.is_platform_image), the
overlay's regeneration leaves it named (built_images), and project delete
removes it. `state/image_pins/<project>.json` holds {service, ref,
image_id, reason} for each pinned service, and production's overlay
(compose.boxmunge.yml, compose.render_compose_override) runs `image:
<ref>` for it. Every production start runs the overlay
(tests/test_image_pin_start_paths.py), and before Compose runs, the start
checks that each tag it runs still names the recorded image ID
(pinned_image_problem), so a pin holds, noisily, across a restart,
resume, recover, restore, the health monitor's restart, a quarantine
lift, an upgrade and container update.

A pin belongs to the release it was written for. Whenever the release
production runs changes, the pins go: a deploy, promote or rollback
renders its release without them and drops the record when it records the
switch (forget_pins), including a deploy whose `up` ran and then failed
its checks, and a rollback to the very release that was pinned. Its
images are the release's own; autofix patches again on the next scan, and
the deploy guard refuses a rollback that brings a patched CVE back.

The user-namespace migration loads images under new IDs; it rewrites the
pins through its map (remap_image_pins).

`reason` is "autofix". Supply Chain's `manual` stance will add its own.
The record is deploy-writable state that root reads: through fs_nofollow,
and one it cannot use raises StateError.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Literal

import yaml

from boxmunge import docker_containers
from boxmunge.compose_images import built_image_name, parse_built_ref
from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow, read_text_nofollow_or_none
from boxmunge.manifest import load_manifest
from boxmunge.redeploy_hint import redeploy_command
from boxmunge.release_txn import open_install_reason
from boxmunge.state import StateError

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable, Mapping
    from pathlib import Path

    from boxmunge.paths import BoxPaths

RECORD_VERSION = 1
REASONS = ("autofix",)
_FIELDS = ("service", "ref", "image_id", "reason")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
_TAG_RE = re.compile(r"autofix-[0-9a-f]{12}")
# The component the overlay's render logs under when a pin write renders it.
_COMPONENT = "image-pins"


def pin_ref(project: str, service: str, image_id: str) -> str:
    """The name autofix gives the patched image of `service`."""
    return f"{built_image_name(project, service)}:autofix-{image_id.removeprefix('sha256:')[:12]}"


@dataclass(frozen=True)
class ImagePin:
    """`service` runs `ref`, which must name the image `image_id`. `ref`
    is `boxmunge.invalid/<project>/<service>:autofix-<12 hex>`; the 12 hex
    are the ID's when autofix named it (a migration that loads it under a
    new ID keeps the name)."""

    service: str
    ref: str
    image_id: str
    reason: Literal["autofix"]

    def __post_init__(self) -> None:
        for field in _FIELDS:
            if not isinstance(getattr(self, field), str):
                raise ValueError(f"image pin {field} must be a string, "
                                 f"got {getattr(self, field)!r}")
        parsed = parse_built_ref(self.ref)
        if parsed is None or parsed[1] != self.service or parsed[3] is not None \
                or parsed[2] is None or not _TAG_RE.fullmatch(parsed[2]):
            raise ValueError(f"image pin ref {self.ref!r} is not "
                             f"boxmunge.invalid/<project>/{self.service}:autofix-<12 hex>")
        if not _IMAGE_ID_RE.fullmatch(self.image_id):
            raise ValueError(f"image pin image_id {self.image_id!r} is not sha256:<64 hex>")
        if self.reason not in REASONS:
            raise ValueError(f"image pin reason {self.reason!r} is not one of {REASONS}")

    @property
    def project(self) -> str:
        """The compose project whose prefix `ref` is under."""
        parsed = parse_built_ref(self.ref)
        assert parsed is not None  # __post_init__ checked it
        return parsed[0]


def read_pins(paths: BoxPaths, project: str) -> tuple[ImagePin, ...]:
    """The project's pins, by service; () when it has no record. Raises
    StateError, naming the file, for a record that cannot be read or used:
    a link or other non-regular file (refused, not followed), text that is
    not UTF-8 JSON, or a record not in the shape write_pins writes."""
    path = paths.project_image_pins(project)
    try:
        text = read_text_nofollow_or_none(path)
    except (OSError, UnicodeDecodeError) as e:
        raise StateError(f"cannot read {path}: {e}") from e
    if text is None:
        return ()
    try:
        return _parse(json.loads(text), project)
    except (ValueError, TypeError) as e:
        raise StateError(f"{path} is not an image pins record: {e}") from e


def _parse(doc: object, project: str) -> tuple[ImagePin, ...]:
    if not isinstance(doc, dict) or set(doc) != {"version", "pins"}:
        raise ValueError('expected {"version", "pins"}')
    if doc["version"] != RECORD_VERSION:
        raise ValueError(f"version {doc['version']!r}, expected {RECORD_VERSION}")
    entries = doc["pins"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("pins must be a non-empty list")
    pins = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != set(_FIELDS):
            raise ValueError(f"each pin is exactly {{{', '.join(_FIELDS)}}}, got {entry!r}")
        pins.append(ImagePin(**entry))
    return _checked(pins, project)


def _checked(pins: Iterable[ImagePin], project: str) -> tuple[ImagePin, ...]:
    """The pins by service. Raises ValueError for two pins of one service,
    or one named under another project's prefix."""
    by_service: dict[str, ImagePin] = {}
    for pin in pins:
        if pin.project != project:
            raise ValueError(f"the pin of {pin.service} names {pin.ref}, not an image of "
                             f"{project}")
        if pin.service in by_service:
            raise ValueError(f"two pins for service {pin.service!r}")
        by_service[pin.service] = pin
    return tuple(by_service[svc] for svc in sorted(by_service))


def _write(path: Path, pins: tuple[ImagePin, ...]) -> None:
    # atomic_write_text makes the directory deploy-owned (mkdir_p_deploy).
    atomic_write_text(path, json.dumps({"version": RECORD_VERSION,
                                        "pins": [asdict(p) for p in pins]}, indent=2) + "\n")


def write_pins(paths: BoxPaths, project: str, pins: Iterable[ImagePin]) -> None:
    """Pin the project's services to `pins` (replacing every pin it had),
    then render production's overlay with them, which records the overlay's
    new hash in the bind record (compose.prepare_compose_override), so a
    start that renders nothing is not refused for it. Caller holds the
    project lock; nothing is started. Raises ValueError for no pins (use
    clear_pins), two for one service, one of another project, or an open
    install (the project dir holds the release it installs, which the pins
    are not for), and what the render raises (a pin for a service the
    release lacks: ComposeError), the record written."""
    checked = _checked(pins, project)
    if not checked:
        raise ValueError("no pins to write; clear_pins removes a project's pins")
    install = open_install_reason(paths, project)
    if install is not None:
        raise ValueError(f"{project}'s image pins are not written while an install is "
                         f"open: {install}")
    _write(paths.project_image_pins(project), checked)
    _render(paths, project)


def clear_pins(paths: BoxPaths, project: str) -> None:
    """Remove the project's pins and render production's overlay without
    them, as write_pins does (switching back to upstream). No record:
    nothing is touched. Caller holds the project lock. Raises what the
    render raises, the record removed."""
    if forget_pins(paths, project):
        _render(paths, project)


def forget_pins(paths: BoxPaths, project: str) -> bool:
    """Drop the pins record, rendering nothing: for a release switch, which
    rendered its release without them already. Returns whether there was
    one. Raises OSError only."""
    path = paths.project_image_pins(project)
    if not os.path.lexists(path):
        return False
    path.unlink()
    return True


def _render(paths: BoxPaths, project: str) -> None:
    # compose renders the overlay from read_pins, so it is imported here.
    from boxmunge.compose import prepare_compose_override
    prepare_compose_override(paths, load_manifest(paths.project_manifest(project)),
                             component=_COMPONENT)


def remap_image_pins(paths: BoxPaths, projects: Iterable[str],
                     image_map: Mapping[str, str]) -> None:
    """After the user-namespace migration (or its rollback) loaded images
    under new IDs (`image_map`: old ID to new), point each project's pins at
    the new IDs; their names came across with them. A pin whose image was
    not loaded keeps its ID, and its next start is refused for it. Safe to
    run again. Raises StateError for a record that cannot be read."""
    for project in projects:
        pins = read_pins(paths, project)
        moved = tuple(ImagePin(p.service, p.ref, image_map.get(p.image_id, p.image_id),
                               p.reason) for p in pins)
        if moved != pins:
            _write(paths.project_image_pins(project), moved)


def _overlay_images(overlay: Path) -> dict[str, object]:
    doc = yaml.safe_load(read_text_nofollow(overlay))
    services = doc.get("services") if isinstance(doc, dict) else None
    return {svc: spec.get("image") for svc, spec in (services or {}).items()
            if isinstance(spec, dict)}


def pinned_image_problem(paths: BoxPaths, project: str, overlay: Path | None,
                         starting: Collection[str], *, switching: bool) -> str | None:
    """Why a production start of the services `starting`, from `overlay`
    (None: the start runs none), would not run each one's pinned image, or
    None. Each pinned tag the overlay runs must still name the image the pin
    records. A `switching` start (a deploy, promote or rollback, or a core
    resuming its install) may run a release rendered without the pins; any
    other start must run every pin. Raises DockerError when the image store
    cannot be asked."""
    try:
        pins = [p for p in read_pins(paths, project) if p.service in starting]
    except StateError as e:
        return str(e)
    if not pins or (overlay is None and switching):
        return None
    redo = redeploy_command(paths, project)
    if overlay is None:
        return (f"{', '.join(p.service for p in pins)} run pinned patched images, but the "
                f"overlay compose.boxmunge.yml that runs them is missing, so the start "
                f"would run the images they replace. Run `{redo}`, which generates it with "
                f"the release's own images (autofix patches again on the next scan)")
    try:
        runs = _overlay_images(overlay)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        return f"cannot read {overlay} to check its image pins: {e}"
    for pin in pins:
        if runs.get(pin.service) != pin.ref:
            if switching:
                continue
            return (f"the overlay runs {runs.get(pin.service) or 'no image'} for "
                    f"{pin.service}, not its pinned image {pin.ref}: it was generated "
                    f"without the pin. Run `{redo}`")
        image = docker_containers.local_image(pin.ref)
        if image is None or image.image_id != pin.image_id:
            found = "no image" if image is None else image.image_id[:19]
            return (f"the pinned image for {pin.service} ({pin.ref}) is not the one autofix "
                    f"built: the tag names {found}, the pin {pin.image_id[:19]}. Nothing "
                    f"but autofix should name it; run `{redo}`, which starts the release's "
                    f"own images (autofix patches again on the next scan)")
    return None

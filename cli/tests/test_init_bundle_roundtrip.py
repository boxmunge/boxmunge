# SPDX-License-Identifier: Apache-2.0
"""init -> bundle round trip on a real temp directory, inspecting the tarball."""

import re
import tarfile
from pathlib import Path

import yaml

from boxmunge_cli.bundle_cmd import run_bundle
from boxmunge_cli.init_cmd import run_init

_ULID = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")


def _bundle_manifest(tarball: Path, project: str) -> dict:
    with tarfile.open(tarball) as tar:
        member = tar.extractfile(f"{project}/manifest.yml")
        assert member is not None
        return yaml.safe_load(member.read())


def test_init_writes_a_real_ulid(tmp_path: Path) -> None:
    project = tmp_path / "myapp"
    assert run_init(project, server="box.example.com") == 0
    manifest = yaml.safe_load((project / "manifest.yml").read_text())
    assert isinstance(manifest["id"], str)
    assert _ULID.fullmatch(manifest["id"])


def test_init_then_bundle_ships_the_init_id(tmp_path: Path) -> None:
    project = tmp_path / "myapp"
    assert run_init(project, server="box.example.com") == 0
    before = (project / "manifest.yml").read_text()
    out = tmp_path / "out"
    out.mkdir()

    assert run_bundle(str(project), output=str(out)) == 0

    # Identity is fixed at init; bundling must not rewrite the manifest.
    assert (project / "manifest.yml").read_text() == before
    tarball = next(out.glob("myapp-*.tar.gz"))
    shipped = _bundle_manifest(tarball, "myapp")
    assert shipped["id"] == yaml.safe_load(before)["id"]


def _write_project(root: Path, manifest_text: str) -> Path:
    project = root / "myapp"
    project.mkdir()
    (project / "manifest.yml").write_text(manifest_text)
    (project / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    return project


_BODY = """\
project: myapp   # keep this comment
source: bundle
hosts:
  - myapp.example.com
services:
  web:
    port: 8080
    routes: [{path: /}]
"""


def test_null_id_is_replaced_in_place_keeping_comments(tmp_path: Path) -> None:
    project = _write_project(tmp_path, "# header comment\nid: null\n" + _BODY)
    out = tmp_path / "out"
    out.mkdir()

    assert run_bundle(str(project), output=str(out)) == 0

    text = (project / "manifest.yml").read_text()
    lines = text.splitlines()
    assert lines[0] == "# header comment"
    assert re.fullmatch(r"id: [0-9A-HJKMNP-TV-Z]{26}", lines[1])
    assert text.endswith(_BODY)  # everything else byte-identical
    new_id = lines[1].split(": ", 1)[1]
    assert _bundle_manifest(next(out.glob("*.tar.gz")), "myapp")["id"] == new_id


def test_missing_id_is_inserted_as_first_line(tmp_path: Path) -> None:
    project = _write_project(tmp_path, _BODY)
    project.joinpath("manifest.yml").chmod(0o640)
    out = tmp_path / "out"
    out.mkdir()

    assert run_bundle(str(project), output=str(out)) == 0

    text = (project / "manifest.yml").read_text()
    first, rest = text.split("\n", 1)
    assert re.fullmatch(r"id: [0-9A-HJKMNP-TV-Z]{26}", first)
    assert rest == _BODY
    assert (project / "manifest.yml").stat().st_mode & 0o777 == 0o640


def test_validate_only_never_writes_the_manifest(tmp_path: Path) -> None:
    project = _write_project(tmp_path, _BODY)
    assert run_bundle(str(project), validate_only=True) == 1
    assert (project / "manifest.yml").read_text() == _BODY

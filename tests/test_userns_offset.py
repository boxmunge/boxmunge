"""remap_offset(): the one source of the box's remap state."""
from __future__ import annotations

import json

import pytest

from boxmunge.userns import offset
from boxmunge.userns.offset import (
    RemapError, allocate_offset, recorded_offset, remap_offset, remove_offset_record,
    write_offset_record,
)
from tests.userns_helpers import S, remap_box, remapped_info

REAL_DOCKER_INFO = offset.docker_info  # bound at import, before any fixture runs


def test_never_remapped_box_is_offset_zero(paths) -> None:
    assert remap_offset(paths) == 0


def test_remapped_box_returns_the_recorded_offset(paths, monkeypatch) -> None:
    remap_box(paths, monkeypatch)
    assert remap_offset(paths) == S


@pytest.mark.parametrize("breakage, named", [
    ("record", "has no userns record"),
    ("daemon_json", "daemon.json userns-remap"),
    ("daemon", "running daemon is not remapped"),
    ("driver", "storage driver is 'vfs'"),
    ("root", "root dir is"),
    ("subuid", "subuid gives boxmunge-remap"),
    ("subgid_two_ranges", "subgid gives boxmunge-remap"),
])
def test_any_disagreement_raises_naming_the_source(paths, monkeypatch, breakage, named) -> None:
    remap_box(paths, monkeypatch)
    info = remapped_info()
    if breakage == "record":
        text = paths.config_file.read_text()
        paths.config_file.write_text(text[:text.index("userns:")])
    elif breakage == "daemon_json":
        (offset.ETC / "docker" / "daemon.json").write_text("{}")
    elif breakage == "daemon":
        info["SecurityOptions"] = ["name=seccomp,profile=builtin"]
    elif breakage == "driver":
        info["Driver"] = "vfs"
    elif breakage == "root":
        info["DockerRootDir"] = "/var/lib/docker"
    elif breakage == "subuid":
        (offset.ETC / "subuid").write_text("boxmunge-remap:2097152:65536\n")
    elif breakage == "subgid_two_ranges":
        (offset.ETC / "subgid").write_text(f"boxmunge-remap:{S}:65536\nboxmunge-remap:3000000:10\n")
    monkeypatch.setattr(offset, "docker_info", lambda: info)
    with pytest.raises(RemapError, match=named):
        remap_offset(paths)


def test_daemon_remapped_without_any_record_is_inconsistent(paths, monkeypatch) -> None:
    monkeypatch.setattr(offset, "docker_info", lambda: remapped_info())
    with pytest.raises(RemapError, match="has no userns record"):
        remap_offset(paths)


@pytest.mark.parametrize("block", [
    "userns: yes\n", "userns:\n  name: other\n  offset: 1048576\n",
    "userns:\n  name: boxmunge-remap\n  offset: 1048577\n",
    "userns:\n  name: boxmunge-remap\n  offset: true\n",
])
def test_malformed_record_is_refused(paths, block) -> None:
    paths.config_file.write_text("hostname: h\nadmin_email: a@b.c\n" + block)
    with pytest.raises(RemapError, match="userns must be"):
        recorded_offset(paths)


def test_unparseable_daemon_json_is_refused(paths) -> None:
    (offset.ETC / "docker").mkdir()
    (offset.ETC / "docker" / "daemon.json").write_text("{not json")
    with pytest.raises(RemapError, match="not valid JSON"):
        remap_offset(paths)


def test_allocation_skips_taken_blocks_in_either_file(tmp_path) -> None:
    (tmp_path / "subuid").write_text("dockremap:165536:65536\nalice:1048576:65536\n")
    (tmp_path / "subgid").write_text("bob:1114112:100\n")
    assert allocate_offset(tmp_path, host_ids=set()) == 1179648


def test_allocation_skips_a_block_holding_a_host_id(tmp_path) -> None:
    assert allocate_offset(tmp_path, host_ids={1048576 + 5}) == 1114112


def test_allocation_reuses_the_identitys_own_range(tmp_path) -> None:
    for name in ("subuid", "subgid"):
        (tmp_path / name).write_text(f"boxmunge-remap:{S}:65536\n")
    assert allocate_offset(tmp_path, host_ids=set()) == S


def test_allocation_refuses_a_misshapen_existing_range(tmp_path) -> None:
    (tmp_path / "subuid").write_text("boxmunge-remap:1048576:65536\n")
    (tmp_path / "subgid").write_text("boxmunge-remap:2097152:65536\n")
    with pytest.raises(RemapError, match="already has subordinate ids"):
        allocate_offset(tmp_path, host_ids=set())


def test_record_is_appended_keeping_comments_mode_and_owner(paths) -> None:
    paths.config_file.write_text("# keep me\nhostname: h\nadmin_email: a@b.c\n")
    paths.config_file.chmod(0o640)
    write_offset_record(paths, S)
    text = paths.config_file.read_text()
    assert text.startswith("# keep me\n") and f"offset: {S}" in text
    assert paths.config_file.stat().st_mode & 0o777 == 0o640
    write_offset_record(paths, S)  # idempotent
    assert paths.config_file.read_text() == text
    with pytest.raises(RemapError, match="already records offset"):
        write_offset_record(paths, 2 * S)
    remove_offset_record(paths, S)
    assert recorded_offset(paths) is None
    assert paths.config_file.read_text() == "# keep me\nhostname: h\nadmin_email: a@b.c\n"


def test_docker_info_must_be_a_json_object(monkeypatch) -> None:
    class Done:
        stdout = json.dumps(["not", "an", "object"])
    monkeypatch.setattr(offset, "_run", lambda cmd, capture, timeout: Done())
    with pytest.raises(RemapError, match="not a JSON object"):
        REAL_DOCKER_INFO()  # the autouse fixture stubbed offset.docker_info itself


def test_non_utf8_sources_are_refused(paths) -> None:
    paths.config_file.write_bytes(b"hostname: \xff\n")
    with pytest.raises(RemapError, match="cannot read"):
        recorded_offset(paths)
    (offset.ETC / "subuid").write_bytes(b"\xff:1:1\n")
    with pytest.raises(RemapError, match="cannot read"):
        offset.read_subids(offset.ETC / "subuid")
    (offset.ETC / "docker").mkdir()
    (offset.ETC / "docker" / "daemon.json").write_bytes(b"{\"\xff\": 1}")
    with pytest.raises(RemapError, match="cannot read"):
        offset.daemon_json_userns(offset.ETC)


def test_docker_info_has_a_short_timeout(monkeypatch) -> None:
    seen = {}

    class Done:
        stdout = "{}"

    def fake(cmd, capture, timeout):
        seen["timeout"] = timeout
        return Done()
    monkeypatch.setattr(offset, "_run", fake)
    REAL_DOCKER_INFO()
    assert seen["timeout"] <= 10


def test_empty_userns_remap_is_dockers_off(paths) -> None:
    (offset.ETC / "docker").mkdir()
    (offset.ETC / "docker" / "daemon.json").write_text('{"userns-remap": ""}')
    assert remap_offset(paths) == 0


def test_ranges_match_the_remap_users_uid_as_docker_does(tmp_path) -> None:
    (tmp_path / "passwd").write_text("root:x:0:0::/root:/bin/sh\n"
                                     "boxmunge-remap:x:998:998::/:/sbin/nologin\n")
    (tmp_path / "subuid").write_text("998:1048576:10\nboxmunge-remap:1048586:65526\n")
    (tmp_path / "subgid").write_text("boxmunge-remap:1048576:65536\n")
    uids, gids = offset.remap_ranges(tmp_path)
    assert [(r.start, r.count) for r in uids] == [(1048576, 10), (1048586, 65526)]
    assert [(r.start, r.count) for r in gids] == [(1048576, 65536)]
    with pytest.raises(RemapError, match="already has subordinate ids"):
        allocate_offset(tmp_path, host_ids=set())


@pytest.mark.parametrize("line", ["boxmunge-remap:\u00b2:65536", "boxmunge-remap:1:+5"])
def test_non_ascii_or_signed_digits_are_refused(tmp_path, line) -> None:
    (tmp_path / "subuid").write_text(line + "\n")
    with pytest.raises(RemapError, match="is not 'name:start:count'"):
        offset.read_subids(tmp_path / "subuid")

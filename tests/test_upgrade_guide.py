# SPDX-License-Identifier: Apache-2.0
"""The guide upgrade-howto prints, composed from a release's signed notes
(boxmunge.upgrade_guide)."""
from __future__ import annotations

import json

import pytest

from boxmunge.upgrade_guide import (
    compose_guide, guide_to_json, notes_baseline, render_guide, up_to_date_json,
    up_to_date_text,
)
from boxmunge.upgrade_notes import Entry, Guide, NotesError
from tests.upgrade_notes_helpers import entry, notes_bytes

ALL_SECTIONS = [
    entry("0.12.0", "box-first", "box", "before"),
    entry("0.12.0", "proj-first", "project", "before"),
    entry("0.12.0", "proj-after", "project", "after", files=["compose.yml"]),
    entry("0.12.0", "box-after", "box", "after"),
]


def _guide(entries: list[dict], installed: str = "0.11.8", **kwargs) -> Guide:
    return compose_guide(notes_bytes("0.12.0", entries, **kwargs), "0.12.0", installed)


def test_render_sections_in_order_and_omits_empty() -> None:
    text = render_guide(_guide([e for e in ALL_SECTIONS if e["id"] != "0.12.0-proj-first"]))
    headings = ["Upgrade guide: boxmunge 0.11.8 -> 0.12.0",
                "From the signed release notes of 0.12.0 (cosign-verified).",
                "Box, before the upgrade:", "Each project, after the upgrade:",
                "Box, after the upgrade:", "No project action needed for: 0.11.9",
                "Base images:", "Next steps:"]
    at = [text.index(h) for h in headings]
    assert at == sorted(at)
    assert "Each project, before the upgrade" not in text


def test_each_entry_renders_kind_title_change_and_verify() -> None:
    text = render_guide(_guide([entry("0.12.0", "floor", "box", "before",
                                      kind="recommended", change="Line one.\nLine two.",
                                      verify="Run it.")]))
    block = text[text.index("[recommended] Title of floor"):]
    lines = block.splitlines()
    assert lines[1].strip() == "Line one." and lines[2].strip() == "Line two."
    assert lines[1].startswith("      ")
    assert lines[3].strip() == "Verify: Run it."


def test_render_checklist_grouped_by_file() -> None:
    text = render_guide(_guide([
        entry("0.12.0", "docker", files=["Dockerfile"]),
        entry("0.12.0", "both", files=["manifest.yml", "compose.yml"]),
        entry("0.12.0", "manifest", files=["manifest.yml"]),
    ]))
    section = text[text.index("Each project, before the upgrade:"):text.index("Base images:")]
    files = [section.index(f"  {name}:") for name in ("manifest.yml", "compose.yml",
                                                      "Dockerfile")]
    assert files == sorted(files)
    manifest = section[files[0]:files[1]]
    compose = section[files[1]:files[2]]
    assert "[ ] [required] Title of both" in manifest and "Title of manifest" in manifest
    # Described once, under its first file; the other file points back to it.
    assert "Title of both (described under manifest.yml)" in compose
    assert section.count("Change this.") == 3
    assert "Title of docker" in section[files[2]:]


def test_no_entries_says_the_notes_ask_nothing() -> None:
    text = render_guide(_guide([], no_action=("0.11.8", "0.11.9")))
    assert "No project action needed for: 0.11.9\n" in text
    assert "ask nothing of this box or its projects" in text


def test_below_floor_text_computed_from_notes() -> None:
    guide = compose_guide(notes_bytes("0.12.5", ALL_SECTIONS, floor="0.12.0", bridge="0.12.3",
                                      no_action=()), "0.12.5", "0.10.4")
    text = render_guide(guide)
    assert guide.below_floor
    assert "0.10.4" in text and "0.12.0" in text and "0.12.3" in text
    assert "0.11" not in text
    assert "Title of" not in text


def test_below_floor_leads_to_the_bridges_own_guide_and_check() -> None:
    """Never straight to an upgrade: a "get ready" request must not upgrade
    the box, and the bridge has its own notes and check."""
    guide = compose_guide(notes_bytes("0.12.5", ALL_SECTIONS, floor="0.12.0", bridge="0.12.3",
                                      no_action=()), "0.12.5", "0.10.4")
    text = " ".join(render_guide(guide).split())
    howto = text.index("upgrade-howto --version 0.12.3")
    assert howto < text.index("upgrade-check --version 0.12.3")
    assert "upgrade --target" not in text and "force" not in text
    assert "Once the box runs 0.12.3, run upgrade-howto again." in text


def test_render_strips_nonprintable() -> None:
    bad = Entry(introduced="0.12.0", id="0.12.0-bad", scope="box", when="before",
                kind="required", title="Ti\x1b[31mtle‮", change="ch\rang\x07e\nok",
                verify="ve\x00rify", files=(), superseded_by=None, refs=())
    guide = Guide(installed="0.11.8", target="0.12.0", below_floor=False, floor="0.11.0",
                  bridge="0.11.6", box_before=(bad,), project_before=(), project_after=(),
                  box_after=(), no_action=())
    text = render_guide(guide)
    assert all(c == "\n" or c.isprintable() for c in text)
    assert "Ti[31mtle" in text and "change" in text and "verify" in text
    as_json = json.dumps(guide_to_json(guide))
    assert "\\u001b" not in as_json and "\\u202e" not in as_json


def test_next_steps_name_upgrade_check_and_never_force() -> None:
    text = render_guide(_guide(ALL_SECTIONS))
    steps = " ".join(text[text.index("Next steps:"):].split())
    assert "upgrade-check --version 0.12.0" in steps
    assert "upgrade --target 0.12.0" in steps
    assert "Get ready for an upgrade" in steps and "Prepare, then do it" in steps
    assert "If the check fails, do not upgrade; report per project." in steps
    assert "Never force: forcing is the operator's decision (force-target)." in steps


def test_base_image_advice_is_always_there() -> None:
    text = render_guide(_guide([]))
    advice = text[text.index("Base images:"):text.index("Next steps:")]
    assert "-slim or distroless" in advice and "digest" in advice
    assert "agent-help images" in advice


class TestCompose:
    def test_refuses_the_notes_of_another_release(self) -> None:
        """A signed older release's notes replayed at the target's URL."""
        with pytest.raises(NotesError, match="0.11.9.*not 0.12.0"):
            compose_guide(notes_bytes("0.11.9", []), "0.12.0", "0.11.8")

    @pytest.mark.parametrize("raw", [b"", b"not json", b"[" * 100_000, b"\xff\xfe",
                                     json.dumps({"format": 2}).encode()])
    def test_unusable_bytes_are_a_notes_error(self, raw: bytes) -> None:
        with pytest.raises(NotesError):
            compose_guide(raw, "0.12.0", "0.11.8")

    def test_entries_after_the_installed_release_only(self) -> None:
        guide = _guide([entry("0.11.9", "old", "box"), entry("0.12.0", "new", "box")],
                       installed="0.11.9")
        assert [e.id for e in guide.box_before] == ["0.12.0-new"]

    def test_a_pre_release_box_is_shown_its_releases_own_entries(self) -> None:
        guide = _guide([entry("0.11.9", "old", "box"), entry("0.12.0", "new", "box")],
                       installed="0.12.0-rc.1")
        assert [e.id for e in guide.box_before] == ["0.12.0-new"]
        assert guide.installed == "0.12.0-rc.1"
        assert "boxmunge 0.12.0-rc.1 -> 0.12.0" in render_guide(guide)


@pytest.mark.parametrize("installed,baseline", [
    ("0.11.8", "0.11.8"), ("0.12.1-rc.1", "0.12.0"), ("0.12.0-rc.1", "0.11.99999"),
    ("1.0.0-beta", "0.99999.99999"), ("0.0.0-dev", "0.0.0"),
])
def test_notes_baseline(installed: str, baseline: str) -> None:
    assert notes_baseline(installed) == baseline


def test_guide_to_json() -> None:
    doc = guide_to_json(_guide(ALL_SECTIONS))
    assert doc["guide"] == 1 and doc["status"] == "guide"
    assert (doc["installed"], doc["target"], doc["floor"], doc["bridge"]) == (
        "0.11.8", "0.12.0", "0.11.0", "0.11.6")
    assert [e["id"] for e in doc["project_after"]] == ["0.12.0-proj-after"]
    assert doc["project_after"][0]["files"] == ["compose.yml"]
    assert doc["no_action"] == ["0.11.9"]
    assert doc["text"].startswith("Upgrade guide:")
    json.dumps(doc)


def test_below_floor_json_status() -> None:
    guide = compose_guide(notes_bytes("0.12.0", ALL_SECTIONS), "0.12.0", "0.10.4")
    assert guide_to_json(guide)["status"] == "below_floor"


def test_up_to_date() -> None:
    assert up_to_date_text("0.12.0", newest=True) == (
        "This box runs 0.12.0, the newest release; nothing to prepare.")
    assert "newest" not in up_to_date_text("0.12.0", newest=False)
    doc = up_to_date_json("0.12.0", newest=True)
    assert doc["status"] == "up_to_date" and doc["target"] == doc["installed"] == "0.12.0"
    assert doc["box_before"] == [] and doc["text"] == up_to_date_text("0.12.0", newest=True)

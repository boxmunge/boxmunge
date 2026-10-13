# SPDX-License-Identifier: Apache-2.0
"""Keep the agent-facing entry points short enough to be read in full.

Agents skim long documents. The on-box docs total well over 100 kB, so the
default `agent-help` orientation is the one page an agent reliably reads end
to end. These tests keep it within budget and keep the rules that prevent
outages at the top, so they cannot be buried again by later additions.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge.commands.help import AGENT_HELP_TEXT, AGENT_HELP_TOPICS

REPO = Path(__file__).resolve().parents[1]
DOCS = REPO / "docs" / "on-server"

ORIENTATION_BUDGET = 3500   # bytes
RULES_WITHIN = 1200         # the outage rules must start this early
TOPIC_TLDR_WITHIN = 800     # a short topic's TL;DR must start this early
SHORT_TOPIC_BUDGET = 5000   # bytes, for topics meant to be read in one go
SHORT_TOPICS = {"images"}


def test_orientation_fits_its_budget() -> None:
    size = len(AGENT_HELP_TEXT.encode())
    assert size <= ORIENTATION_BUDGET, (
        f"agent-help orientation is {size} bytes (budget {ORIENTATION_BUDGET}). "
        "Move detail into a topic and leave a one-line pointer."
    )


def test_outage_rules_come_first_and_base_image_leads() -> None:
    rules_at = AGENT_HELP_TEXT.index("Rules that prevent outages")
    assert rules_at <= RULES_WITHIN
    first_rule = AGENT_HELP_TEXT[rules_at:].split("\n  1.", 1)[1].splitlines()[0]
    assert "Base image" in first_rule


def test_every_topic_exists_and_is_listed_in_the_orientation() -> None:
    for topic, filename in AGENT_HELP_TOPICS.items():
        assert (DOCS / filename).is_file(), f"agent-help {topic}: {filename} missing"
        assert f"  {topic} " in AGENT_HELP_TEXT, f"orientation does not list topic {topic!r}"


@pytest.mark.parametrize("topic", sorted(SHORT_TOPICS))
def test_short_topics_stay_short_and_lead_with_a_tldr(topic: str) -> None:
    text = (DOCS / AGENT_HELP_TOPICS[topic]).read_text()
    assert len(text.encode()) <= SHORT_TOPIC_BUDGET, f"{topic} exceeds {SHORT_TOPIC_BUDGET} bytes"
    assert 0 <= text.find("TL;DR") <= TOPIC_TLDR_WITHIN, f"{topic} must open with a TL;DR"

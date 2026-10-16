# SPDX-License-Identifier: Apache-2.0
"""Deploy writes the Caddy site journal but cannot create it: caddy/ is
root:deploy 750. Both the fresh-box bootstrap and install.sh (which every
upgrade runs) must create it, deploy-owned."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from boxmunge.caddy_journal import JOURNAL_DIRNAME

REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script, owner", [
    ("install.sh", "deploy"), ("bootstrap/init-host.sh", '"${DEPLOY_USER}"'),
])
def test_script_creates_the_site_journal_deploy_owned(script, owner) -> None:
    text = (REPO / script).read_text().replace("\\\n", " ")
    pattern = (rf"install -d -m 700 -o {re.escape(owner)} -g {re.escape(owner)}\s+"
               rf'"\$\{{BOXMUNGE_ROOT\}}/caddy/{re.escape(JOURNAL_DIRNAME)}"')
    assert re.search(pattern, text), f"{script} does not create caddy/{JOURNAL_DIRNAME}"

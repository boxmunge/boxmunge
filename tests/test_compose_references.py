# SPDX-License-Identifier: Apache-2.0
"""The reference walk refuses what it cannot check, naming the entry."""
from __future__ import annotations

import pytest
import yaml


def test_a_nul_in_an_env_file_name_is_refused_not_a_traceback(paths) -> None:
    """os.path.realpath and os.open raise ValueError("embedded null
    character") for a NUL; validation used to traceback on it."""
    from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump(
        {"services": {"web": {"image": "nginx", "env_file": "a\0b"}}}))
    assert "\0" in yaml.safe_load(compose.read_text())["services"]["web"]["env_file"]
    with pytest.raises(ComposeSecurityError, match="env_file 'a\\\\x00b' is not a usable path"):
        validate_user_compose(compose, paths, project_name="myapp")

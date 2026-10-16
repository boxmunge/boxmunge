"""Staging basic auth comes from the project's STAGING_AUTH_* secrets."""
import bcrypt
import pytest

from boxmunge.commands.stage_cmd import _staging_auth
from boxmunge.paths import BoxPaths
from boxmunge.secrets import SecretsFile, set_key


def test_no_secrets_means_no_auth(paths: BoxPaths) -> None:
    assert _staging_auth("myapp", paths) is None


def test_password_is_used_exactly_as_set(paths: BoxPaths) -> None:
    secrets = SecretsFile.project(paths, "myapp")
    set_key(secrets, "STAGING_AUTH_USER", "reviewer")
    set_key(secrets, "STAGING_AUTH_PASS", " pa$s # 'x' ")
    user, hashed = _staging_auth("myapp", paths)
    assert user == "reviewer"
    assert bcrypt.checkpw(b" pa$s # 'x' ", hashed.encode())


def test_ambiguous_legacy_password_is_refused(paths: BoxPaths) -> None:
    paths.project_dir("myapp").mkdir(parents=True)
    paths.project_secrets("myapp").write_text(
        "STAGING_AUTH_PASS=pa$s\nSTAGING_AUTH_USER=reviewer\n")
    with pytest.raises(ValueError, match="secrets set myapp 'STAGING_AUTH_PASS=<value>'"):
        _staging_auth("myapp", paths)

"""Staging basic auth comes from the project's STAGING_AUTH_* secrets."""
import bcrypt
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


def test_old_format_values_keep_working_after_upgrade(paths: BoxPaths) -> None:
    """Written unquoted by an older boxmunge; read as that version read it."""
    paths.project_dir("myapp").mkdir(parents=True)
    paths.project_secrets("myapp").write_text(
        "STAGING_AUTH_PASS=Xk9$qL2#z\nSTAGING_AUTH_USER=\"reviewer\"\n")
    user, hashed = _staging_auth("myapp", paths)
    assert user == "reviewer"
    assert bcrypt.checkpw(b"Xk9$qL2#z", hashed.encode())

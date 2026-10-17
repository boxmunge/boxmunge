"""init-host remaps before Docker's first start, and shrinks."""
from pathlib import Path

BOOT = Path(__file__).resolve().parents[1] / "bootstrap"
INSTALL_DOCKER = "apt-get install -y -qq docker-ce"


def _init_host() -> str:
    return (BOOT / "init-host.sh").read_text()


def test_init_host_sources_userns_before_installing_docker() -> None:
    text = _init_host()
    assert text.index('userns.sh"') < text.index(INSTALL_DOCKER)
    assert text.index("userns_before_docker") < text.index(INSTALL_DOCKER)
    assert "cat > /etc/docker/daemon.json" not in text
    assert text.index("userns_verify") > text.index("systemctl restart docker")
    assert text.index("userns_record") > text.index('cat > "${BOXMUNGE_ROOT}/config/boxmunge.yml"')
    assert len(text.splitlines()) < 500


def test_userns_refusals_come_before_init_host_changes_anything() -> None:
    text = _init_host()
    assert text.index("userns_preflight") < text.index("apt-get update")
    assert text.index("userns_preflight") > text.index('if [[ "$(id -u)" -ne 0 ]]')


def test_daemon_json_is_written_after_the_identity() -> None:
    body = (BOOT / "userns.sh").read_text().split("userns_before_docker() {", 1)[1]
    body = body.split("\n}", 1)[0]
    assert body.index("userns_identity") < body.index("userns_daemon_json")



def test_caddy_bind_sources_exist_before_caddy_first_starts() -> None:
    """dockerd would create a missing one owned by the remapped root."""
    text = _init_host()
    up = text.index('docker compose -f "${BOXMUNGE_ROOT}/caddy/compose.yml" up -d')
    assert text.index('"${BOXMUNGE_ROOT}/caddy/maintenance"') < up


def test_caddyfile_is_readable_by_caddys_remapped_root() -> None:
    """Remapped, Caddy's root is an "other" user to a root:deploy file."""
    text = _init_host()
    assert 'chmod 644 "${BOXMUNGE_ROOT}/caddy/Caddyfile"' in text
    assert 'chmod 640 "${BOXMUNGE_ROOT}/caddy/Caddyfile"' not in text


def test_aide_watches_the_remap_files() -> None:
    text = (BOOT / "aide.sh").read_text()
    for path in ("/etc/docker/daemon.json Full", "/etc/subuid Full", "/etc/subgid Full"):
        assert path in text


def test_init_host_sources_its_split_steps() -> None:
    """The bundle ships bootstrap/ whole (Makefile BUNDLE_DIRS), so a sourced
    step only has to exist beside init-host.sh."""
    text = _init_host()
    for name in ("userns.sh", "sshd.sh", "unattended.sh", "summary.sh"):
        assert f'source "$(dirname "$0")/{name}"' in text
        assert (BOOT / name).is_file()
    makefile = (BOOT.parent / "Makefile").read_text()
    assert any(line.startswith("BUNDLE_DIRS") and " bootstrap " in line
               for line in makefile.splitlines())

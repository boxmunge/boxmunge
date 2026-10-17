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
    assert len(text.splitlines()) < 602


def test_caddy_logs_is_created_for_caddys_remapped_root() -> None:
    """Never root-owned first and chowned later: docker-userns errors on that,
    and a chown that follows a link would hand its target to container root."""
    text = _init_host()
    assert 'userns_caddy_logs "${USERNS_OFFSET}"' in text
    assert '"${BOXMUNGE_ROOT}/caddy/logs"' not in text
    code = [line for line in (BOOT / "userns.sh").read_text().splitlines()
            if not line.lstrip().startswith("#")]
    assert not [line for line in code if "chown" in line]


def test_caddyfile_is_readable_by_caddys_remapped_root() -> None:
    """Remapped, Caddy's root is an "other" user to a root:deploy file."""
    text = _init_host()
    assert 'chmod 644 "${BOXMUNGE_ROOT}/caddy/Caddyfile"' in text
    assert 'chmod 640 "${BOXMUNGE_ROOT}/caddy/Caddyfile"' not in text


def test_aide_watches_the_remap_files() -> None:
    text = (BOOT / "aide.sh").read_text()
    for path in ("/etc/docker/daemon.json Full", "/etc/subuid Full", "/etc/subgid Full"):
        assert path in text

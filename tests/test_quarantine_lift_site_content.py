"""The quarantine lift publishes the site config it rendered.

caddy/sites is group-writable by deploy, and the lift runs as root from the
scan timer. Deploy can't edit a root-owned site file, but it can replace
the name. So the lift must never read the file back by name: what it would
read is whatever deploy put there, and the lift then publishes that text in
a world-readable site file.
"""
from __future__ import annotations

import pytest

from boxmunge import caddy
from boxmunge.commands import quarantine_lift
from boxmunge.cve.quarantine import QuarantineError
from tests.test_commands.cve_helpers import make_box

RENDERED = "demo.example.com {\n\treverse_proxy demo-web:8080\n}\n"


def test_lift_publishes_the_rendered_site_not_a_link_swapped_in_after(tmp_path, monkeypatch) -> None:
    paths = make_box(tmp_path, services=("web",))
    root_only = tmp_path / "root-only"
    root_only.write_text("a secret only root can read\n")
    real_write = caddy.write_site

    def write_then_swap(caddy_dir, site, content) -> None:
        real_write(caddy_dir, site, content)
        site.unlink()
        site.symlink_to(root_only)

    monkeypatch.setattr(caddy, "site_config", lambda paths_, project, manifest: (RENDERED, None))
    monkeypatch.setattr(caddy, "write_site", write_then_swap)
    monkeypatch.setattr(quarantine_lift, "compose_files_for", lambda paths_, project: [])
    published: list[str] = []
    monkeypatch.setattr(
        quarantine_lift, "lift_quarantine",
        lambda project, paths_, *, project_caddy_site_content, **rest:
            published.append(project_caddy_site_content))

    quarantine_lift._start(paths, "demo", {"project": "demo"}, "security-scan")

    assert published == [RENDERED]


def test_a_site_name_the_lift_cannot_write_is_a_failed_lift_not_a_crash(tmp_path, monkeypatch) -> None:
    """A link already at the site's name is refused by the site writer. The
    lift reports that as a failed lift, so `security resume` prints the
    cause and the scan re-asserts the quarantine, instead of a traceback."""
    paths = make_box(tmp_path, services=("web",))
    root_only = tmp_path / "root-only"
    root_only.write_text("a secret only root can read\n")
    paths.project_caddy_site("demo").symlink_to(root_only)
    monkeypatch.setattr(caddy, "site_config", lambda paths_, project, manifest: (RENDERED, None))
    monkeypatch.setattr(quarantine_lift, "lift_quarantine",
                        lambda *a, **k: pytest.fail("lifted with no site config"))

    with pytest.raises(QuarantineError, match="Failed to render Caddy"):
        quarantine_lift._start(paths, "demo", {"project": "demo"}, "security-scan")

    assert root_only.read_text() == "a secret only root can read\n"


def test_a_site_file_that_is_not_text_is_named_in_the_failed_lift(tmp_path, monkeypatch, capsys) -> None:
    """The decode error alone names no file; the operator is told which
    one it is, that it is not valid text, and what to do."""
    from unittest.mock import MagicMock

    from boxmunge.commands import quarantine_gate

    paths = make_box(tmp_path, services=("web",))
    site = paths.project_caddy_site("demo")
    site.parent.mkdir(parents=True, exist_ok=True)
    site.write_bytes(b"demo.example.com {\n\xff\xfe\n}\n")
    monkeypatch.setattr(quarantine_gate, "_verify_running", lambda *a, **k: None)
    monkeypatch.setattr(quarantine_gate, "_release_policies", lambda *a, **k: {})
    monkeypatch.setattr(quarantine_gate, "lift_quarantine",
                        lambda *a, **k: pytest.fail("lifted with an unreadable site"))
    clearance = MagicMock(cve_id="CVE-2099-0001")

    rc = quarantine_gate.lift_after_deploy(paths, "demo", "v2", clearance,
                                           txn=None, component="deploy")

    err = capsys.readouterr().err
    assert rc == 1
    assert str(site) in err
    assert "not valid UTF-8 text" in err
    assert "security resume demo" in err
    assert "codec can't decode" not in err

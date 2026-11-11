"""The quarantine lift publishes the site config it rendered.

caddy/sites is group-writable by deploy, and the lift runs as root from the
scan timer. Deploy can't edit a root-owned site file, but it can replace
the name. So the lift must never read the file back by name: what it would
read is whatever deploy put there, and the lift then publishes that text in
a world-readable site file.
"""
from __future__ import annotations

from boxmunge import caddy
from boxmunge.commands import quarantine_lift
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

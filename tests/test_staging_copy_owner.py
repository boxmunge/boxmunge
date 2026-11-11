"""A stage that copies production's data gives the copies to the staged users.

Review of #144 (design point): staging tests a new user without production's
data changing hands first, so no production downtime for a staging test.
"""
from __future__ import annotations

from boxmunge import staging_copy_owner as sco
from boxmunge.run_as import ServiceUser
from boxmunge.staging_copy_plan import CopyPlan, Store

NEW = ServiceUser("10002:10002", "manifest")


def _plan(project_dir) -> CopyPlan:
    return CopyPlan(pairs=[
        (Store("bind", "./data", str(project_dir / "data")),
         Store("bind", "./data", str(project_dir / "data-staging"))),
        (Store("volume", "db", "shop_db"), Store("volume", "db", "shop-staging_db")),
        (Store("volume", "shared", "shop_shared"), Store("volume", "shared", "shop-staging_shared")),
        (Store("bind", "./conf/app.toml", str(project_dir / "conf" / "app.toml")),
         Store("bind", "./conf/app.toml", str(project_dir / "conf-staging" / "app.toml"))),
    ])


def test_each_copy_goes_to_the_user_that_writes_it(paths, monkeypatch) -> None:
    project_dir = paths.project_dir("shop")
    calls = []
    monkeypatch.setattr(sco, "chown_under", lambda label, root, rel, ids:
                        calls.append(("bind", str(rel), ids)))
    monkeypatch.setattr(sco, "run_helper", lambda label, mounts, script:
                        calls.append(("volume", mounts[1], script)))
    services = {
        "app": {"volumes": [
            {"type": "bind", "source": str(project_dir / "data-staging" / "uploads"),
             "target": "/u"},
            {"type": "volume", "source": "shared", "target": "/s"},
            {"type": "bind", "source": str(project_dir / "conf-staging" / "app.toml"),
             "target": "/etc/app.toml", "read_only": True}]},
        "db": {"volumes": [{"type": "volume", "source": "db", "target": "/var/lib/db"}]},
        "worker": {"volumes": [{"type": "volume", "source": "shared", "target": "/s"}]},
    }
    users = {"app": NEW, "db": ServiceUser("0:0", "manifest"),
             "worker": ServiceUser("10003:10003", "manifest")}
    sco.give_copies(paths, "shop", _plan(project_dir), services, users)
    # data-staging goes to app's user; db's root and shared's two users are
    # left as they are (the owner check names them); a read-only file is not
    # written by anyone.
    assert calls == [("bind", "data-staging", (10002, 10002))]


def test_a_volume_copy_goes_to_its_writer(paths, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(sco, "run_helper", lambda label, mounts, script:
                        calls.append((mounts[1], script)))
    plan = CopyPlan(pairs=[(Store("volume", "db", "shop_db"),
                            Store("volume", "db", "shop-staging_db"))])
    sco.give_copies(paths, "shop", plan,
                    {"db": {"volumes": [{"type": "volume", "source": "db", "target": "/d"}]}},
                    {"db": ServiceUser(None, "image", "999:999")})
    assert calls == [("type=volume,src=shop-staging_db,dst=/x", "chown -R -h 999:999 /x")]


def test_a_service_that_binds_the_host_root_writes_every_bind_store(tmp_path) -> None:
    """`/` holds every path. Validation refuses such a bind today, but who
    counts as a writer must not depend on that: with a second writer the
    copy is given to nobody."""
    dest = Store("bind", "./data", str(tmp_path / "data-staging"))
    services = {"app": {"volumes": ["/:/host"]},
                "web": {"volumes": [f"{tmp_path}/elsewhere:/e"]},
                "ro": {"volumes": ["/:/host:ro"]}}
    assert sco._writers(dest, services) == {"app"}

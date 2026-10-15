"""release.sync_live_scripts: production's own copy of its smoke scripts."""
from __future__ import annotations

from boxmunge.release import sync_live_scripts


def _release(tmp_path, name: str, scripts: dict[str, str] | None):
    root = tmp_path / name
    root.mkdir()
    if scripts is not None:
        (root / "boxmunge-scripts").mkdir()
        for fname, text in scripts.items():
            (root / "boxmunge-scripts" / fname).write_text(text)
    return root


def test_mirrors_the_release_and_keeps_the_directory_inode(paths, tmp_path) -> None:
    paths.project_dir("myapp").mkdir(parents=True)
    live = paths.project_dir("myapp") / ".releases" / "live-scripts"
    sync_live_scripts(paths, "myapp", _release(tmp_path, "a", {
        "smoke.sh": "old\n", "gone.sh": "x\n"}))
    inode = live.stat().st_ino

    sync_live_scripts(paths, "myapp", _release(tmp_path, "b", {"smoke.sh": "new\n"}))

    assert live.stat().st_ino == inode  # a running container's mount survives
    assert sorted(p.name for p in live.iterdir()) == ["smoke.sh"]
    assert (live / "smoke.sh").read_text() == "new\n"


def test_release_without_scripts_empties_the_copy(paths, tmp_path) -> None:
    paths.project_dir("myapp").mkdir(parents=True)
    live = paths.project_dir("myapp") / ".releases" / "live-scripts"
    sync_live_scripts(paths, "myapp", _release(tmp_path, "a", {"smoke.sh": "x\n"}))
    sync_live_scripts(paths, "myapp", _release(tmp_path, "b", None))
    assert live.is_dir() and list(live.iterdir()) == []

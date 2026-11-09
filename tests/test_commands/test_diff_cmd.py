"""Tests for boxmunge diff command."""
import tarfile

import pytest
from boxmunge.commands.diff_cmd import run_diff

MANIFEST_V1 = """\
id: 01TEST
project: testapp
source: bundle
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
"""

MANIFEST_V2 = """\
id: 01TEST
project: testapp
source: bundle
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
  api:
    port: 9000
    routes:
      - path: /api/*
"""

def _setup_project(paths, manifest=MANIFEST_V1):
    pdir = paths.project_dir("testapp")
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "manifest.yml").write_text(manifest)
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (pdir / "src").mkdir(exist_ok=True)
    (pdir / "src" / "app.py").write_text("print('hello')\n")

def _place_bundle(paths, manifest=MANIFEST_V2, timestamp="2026-03-31T091500000000"):
    staging = paths.root / "tmp_staging" / "testapp"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.yml").write_text(manifest)
    (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n  api:\n    image: node\n")
    (staging / "src").mkdir(exist_ok=True)
    (staging / "src" / "app.py").write_text("print('hello v2')\n")
    (staging / "src" / "new_file.py").write_text("# new\n")
    bundle_path = paths.inbox / f"testapp-{timestamp}.tar.gz"
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(staging, arcname="testapp")
    return bundle_path

class TestRunDiff:
    def test_shows_changed_files(self, paths, capsys):
        _setup_project(paths)
        _place_bundle(paths)
        result = run_diff("testapp", paths)
        assert result == 0
        output = capsys.readouterr().out
        assert "manifest.yml" in output
        assert "changed" in output.lower()

    def test_shows_added_files(self, paths, capsys):
        _setup_project(paths)
        _place_bundle(paths)
        result = run_diff("testapp", paths)
        assert result == 0
        output = capsys.readouterr().out
        assert "added" in output.lower()

    def test_fails_no_project(self, paths):
        result = run_diff("nonexistent", paths)
        assert result == 1

    def test_fails_no_bundle(self, paths):
        _setup_project(paths)
        result = run_diff("testapp", paths)
        assert result == 1

    def test_identical_shows_no_changes(self, paths, capsys):
        _setup_project(paths)
        # Place a bundle identical to the current project
        staging = paths.root / "tmp_staging" / "testapp"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "manifest.yml").write_text(MANIFEST_V1)
        (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        (staging / "src").mkdir(exist_ok=True)
        (staging / "src" / "app.py").write_text("print('hello')\n")
        bundle_path = paths.inbox / "testapp-2026-03-31T091500000000.tar.gz"
        with tarfile.open(bundle_path, "w:gz") as tar:
            tar.add(staging, arcname="testapp")
        result = run_diff("testapp", paths)
        assert result == 0
        output = capsys.readouterr().out
        assert "no changes" in output.lower() or "identical" in output.lower()


class TestDiffIgnoresBoxState:
    def test_release_workspace_and_suppressions_not_listed(self, paths, capsys):
        from boxmunge.commands.diff_cmd import _compare_dirs
        current = paths.root / "current"
        incoming = paths.root / "incoming"
        for d in (current, incoming):
            d.mkdir()
            (d / "manifest.yml").write_text("x")
        (current / ".releases" / "previous").mkdir(parents=True)
        (current / ".releases" / "previous" / "manifest.yml").write_text("old")
        (current / "security").mkdir()
        (current / "security" / "suppressions.yml").write_text("s")
        changed, added, removed = _compare_dirs(current, incoming,
                                                {".releases", "security"})
        assert removed == []


def _identical_bundle(paths, compose="services:\n  web:\n    image: nginx\n"):
    staging = paths.root / "tmp_staging" / "testapp"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.yml").write_text(MANIFEST_V1)
    (staging / "compose.yml").write_text(compose)
    (staging / "src").mkdir(exist_ok=True)
    (staging / "src" / "app.py").write_text("print('hello')\n")
    with tarfile.open(paths.inbox / "testapp-2026-03-31T091500000000.tar.gz", "w:gz") as tar:
        tar.add(staging, arcname="testapp")


class TestDiffOverride:
    """#106: an operator's caddy.override.conf is box state, and the deploy
    writes it verbatim as the site config."""

    OVERRIDE = "testapp.example.com {\n  reverse_proxy web:8080\n  tls internal\n}\n"

    def _override(self, paths, site: str) -> None:
        _setup_project(paths)
        paths.project_caddy_override("testapp").write_text(self.OVERRIDE)
        paths.project_caddy_site("testapp").parent.mkdir(parents=True, exist_ok=True)
        paths.project_caddy_site("testapp").write_text(site)

    def test_override_is_not_removed_and_caddy_is_unchanged(self, paths, capsys):
        self._override(paths, self.OVERRIDE)
        _place_bundle(paths)
        assert run_diff("testapp", paths) == 0
        out = capsys.readouterr().out
        assert "caddy.override.conf" not in out.replace("(from caddy.override.conf)", "")
        assert "removed" not in out
        assert "Caddy config:     unchanged (from caddy.override.conf)" in out

    def test_stale_site_config_compares_against_the_override(self, paths, capsys):
        from boxmunge.caddy import generate_caddy_config
        import yaml
        self._override(paths, generate_caddy_config(yaml.safe_load(MANIFEST_V2)))
        _place_bundle(paths)
        assert run_diff("testapp", paths) == 0
        assert "Caddy config:     would change (from caddy.override.conf)" in \
            capsys.readouterr().out

    def test_without_override_compares_against_generated(self, paths, capsys):
        from boxmunge.caddy import generate_caddy_config
        import yaml
        _setup_project(paths)
        site = paths.project_caddy_site("testapp")
        site.parent.mkdir(parents=True, exist_ok=True)
        site.write_text(generate_caddy_config(yaml.safe_load(MANIFEST_V2)))
        _place_bundle(paths)
        assert run_diff("testapp", paths) == 0
        assert "Caddy config:     unchanged\n" in capsys.readouterr().out


class TestDiffKeepsWhatInstallKeeps:
    def test_box_owned_boxmunge_and_data_entries_not_removed(self, paths, capsys):
        """Everything install_release keeps (box_state) is left out: box-owned
        and boxmunge entries, recorded data dirs and their -staging copies."""
        _setup_project(paths)
        pdir = paths.project_dir("testapp")
        (pdir / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx\n    volumes:\n      - ./uploads:/u\n")
        for rel in ("uploads/a.png", "uploads-staging/b.png", "data/db.sqlite",
                    "backups/s.tar.age", "secrets.env", "compose.boxmunge.yml",
                    ".releases/previous/manifest.yml"):
            (pdir / rel).parent.mkdir(parents=True, exist_ok=True)
            (pdir / rel).write_text("x")
        _identical_bundle(paths, compose=(pdir / "compose.yml").read_text())
        assert run_diff("testapp", paths) == 0
        out = capsys.readouterr().out
        assert "removed" not in out, out
        assert "no changes" in out.lower()

    def test_stale_code_is_still_removed(self, paths, capsys):
        _setup_project(paths)
        (paths.project_dir("testapp") / "old.py").write_text("x")
        _identical_bundle(paths)
        assert run_diff("testapp", paths) == 0
        assert "old.py" in capsys.readouterr().out


def _bundle_with(paths, files: dict[str, str]) -> None:
    staging = paths.root / "tmp_staging" / "testapp"
    staging.mkdir(parents=True, exist_ok=True)
    base = {"manifest.yml": MANIFEST_V1,
            "compose.yml": "services:\n  web:\n    image: nginx\n",
            "src/app.py": "print('hello')\n"}
    for rel, text in {**base, **files}.items():
        (staging / rel).parent.mkdir(parents=True, exist_ok=True)
        (staging / rel).write_text(text)
    with tarfile.open(paths.inbox / "testapp-2026-03-31T091500000000.tar.gz", "w:gz") as tar:
        tar.add(staging, arcname="testapp")


class TestDiffRefusesWhatADeployRefuses:
    @pytest.mark.parametrize("entry", ["caddy.override.conf", "secrets.env"])
    def test_box_owned_entry_in_the_bundle(self, paths, capsys, entry):
        _setup_project(paths)
        _bundle_with(paths, {entry: "x\n"})
        assert run_diff("testapp", paths) == 1
        err = capsys.readouterr().err
        assert "a deploy would refuse this bundle" in err and entry in err

    @pytest.mark.parametrize("named", ["other", "testapp-staging", "../../etc"])
    def test_manifest_naming_another_project(self, paths, capsys, named):
        _setup_project(paths)
        paths.project_caddy_override("testapp").write_text("x\n")
        _bundle_with(paths, {"manifest.yml": MANIFEST_V1.replace(
            "project: testapp", f"project: '{named}'")})
        assert run_diff("testapp", paths) == 1
        err = capsys.readouterr().err
        assert "a deploy would refuse this bundle" in err
        assert repr(named) in err and "'testapp'" in err

    def test_unreadable_compose_names_the_bundle_file(self, paths, capsys):
        _setup_project(paths)
        _bundle_with(paths, {"compose.yml": "services: [\n"})
        assert run_diff("testapp", paths) == 1
        err = capsys.readouterr().err
        assert "a deploy would refuse this bundle: cannot read compose.yml" in err
        assert "upload the bundle again" in err
        assert "/tmp" not in err and "fix the file by hand" not in err

    def test_missing_compose(self, paths, capsys):
        _setup_project(paths)
        staging = paths.root / "tmp_staging" / "testapp"
        staging.mkdir(parents=True)
        (staging / "manifest.yml").write_text(MANIFEST_V1)
        with tarfile.open(paths.inbox / "testapp-2026-03-31T091500000000.tar.gz",
                          "w:gz") as tar:
            tar.add(staging, arcname="testapp")
        assert run_diff("testapp", paths) == 1
        assert "no compose.yml" in capsys.readouterr().err


def test_site_config_reads_the_named_projects_override(paths) -> None:
    import yaml
    from boxmunge.caddy import site_config
    for name in ("testapp", "other"):
        paths.project_dir(name).mkdir(parents=True, exist_ok=True)
    paths.project_caddy_override("other").write_text("other's\n")
    manifest = yaml.safe_load(MANIFEST_V1.replace("project: testapp", "project: other"))
    content, override = site_config(paths, "testapp", manifest)
    assert override is None and "other's" not in content


def test_content_for_a_data_dir_is_refused_as_a_deploy_would(paths, capsys) -> None:
    _setup_project(paths)
    rw = "services:\n  web:\n    image: nginx\n    volumes:\n      - ./uploads:/u\n"
    (paths.project_dir("testapp") / "compose.yml").write_text(rw)
    _bundle_with(paths, {"compose.yml": rw, "uploads/seed.png": "x"})
    assert run_diff("testapp", paths) == 1
    err = capsys.readouterr().err
    assert "a deploy would refuse this bundle" in err and "uploads" in err

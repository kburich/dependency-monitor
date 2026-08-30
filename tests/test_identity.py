"""Guards on the identity a monitor derives from its manifest.

The id names a branch and two labels, and both are durable: a change to it
orphans an existing baseline and opens fresh issues. So these pin the shape of
the slug, not merely that one exists — and pin the collision property that the
truncation depends on, since two monitors sharing an id silently overwrite each
other's state.
"""

import shutil
import subprocess

import pytest

from monitor import identity

#: The slug rules mirror `git check-ref-format`. Mirroring is how they drift,
#: so the branch-name guard below asks git itself rather than re-stating them.
_GIT = shutil.which("git")
requires_git = pytest.mark.skipif(_GIT is None, reason="git not on PATH")


def git_accepts_branch(name: str) -> bool:
    return subprocess.run(
        [_GIT, "check-ref-format", f"refs/heads/{name}"],
        capture_output=True,
    ).returncode == 0


class TestSlugify:
    def test_a_plain_manifest_survives_unchanged(self):
        assert identity.slugify("package-lock.json") == "package-lock.json"

    def test_path_separators_become_dashes(self):
        assert identity.slugify("web/package-lock.json") == "web-package-lock.json"

    def test_runs_of_unsafe_characters_collapse(self):
        assert identity.slugify("a//b  c") == "a-b-c"

    @pytest.mark.parametrize("value", ["-leading", "trailing-", ".dotted."])
    def test_separators_are_stripped_from_both_ends(self, value):
        slug = identity.slugify(value)
        assert not slug.startswith(("-", "."))
        assert not slug.endswith(("-", "."))

    def test_a_slug_with_nothing_usable_is_empty(self):
        assert identity.slugify("///") == ""

    @pytest.mark.parametrize("manifest,expected", [
        ("poetry.lock", "poetry-lock"),
        ("uv.lock", "uv-lock"),
        ("yarn.lock", "yarn-lock"),
        ("Gemfile.lock", "Gemfile-lock"),
        ("web/poetry.lock", "web-poetry-lock"),
    ])
    def test_a_trailing_lock_suffix_is_defused(self, manifest, expected):
        """git reserves `.lock` on a ref component; four auto-detected
        manifests end in it, so this is the ordinary path."""
        assert identity.slugify(manifest) == expected

    def test_only_a_trailing_lock_is_rewritten(self):
        """The suffix is only reserved at the end of a component."""
        assert identity.slugify("a.lockfile.json") == "a.lockfile.json"

    def test_the_lock_suffix_is_matched_case_sensitively(self):
        """git rejects `.lock` but accepts `.LOCK`; rewriting both would
        change ids that were always valid."""
        assert identity.slugify("poetry.LOCK") == "poetry.LOCK"

    def test_a_bare_lock_suffix_survives_as_a_word(self):
        assert identity.slugify(".lock") == "lock"

    @pytest.mark.parametrize("value,expected", [
        ("a/../b", "a-.-b"),
        ("pkgs..old/uv.lock", "pkgs.old-uv-lock"),
    ])
    def test_dot_runs_collapse(self, value, expected):
        """`..` is forbidden anywhere in a ref, and `.` survives the character
        whitelist, so nothing else would catch it."""
        assert identity.slugify(value) == expected


class TestMonitorId:
    def test_the_manifest_is_the_default_source(self):
        assert identity.monitor_id("web/package-lock.json") == "web-package-lock.json"

    def test_an_explicit_id_overrides_the_manifest(self):
        assert identity.monitor_id("package-lock.json", "frontend") == "frontend"

    def test_an_explicit_id_is_slugged_too(self):
        assert identity.monitor_id("package-lock.json", "front/end") == "front-end"

    def test_an_unusable_manifest_is_rejected(self):
        with pytest.raises(ValueError):
            identity.monitor_id("///")

    def test_a_long_manifest_fits_a_label(self):
        """Longest prefix + '/' + id must stay inside GitHub's 50-char limit."""
        long_path = "packages/" * 6 + "package-lock.json"
        ident = identity.monitor_id(long_path)
        assert len(ident) <= identity.MAX_ID_LEN
        assert len(f"{identity.MARKER_STANDARD_PREFIX}/{ident}") <= 50

    def test_a_short_manifest_is_not_truncated(self):
        assert identity.monitor_id("requirements.txt") == "requirements.txt"

    def test_long_manifests_sharing_a_prefix_stay_distinct(self):
        """The digest covers the whole slug, not the truncated head."""
        prefix = "packages/some/deeply/nested/path/"
        first = identity.monitor_id(prefix + "package-lock.json")
        second = identity.monitor_id(prefix + "requirements.txt")
        assert first != second

    def test_truncation_leaves_no_doubled_separator(self):
        ident = identity.monitor_id("a" * 24 + "/" + "b" * 20)
        assert "--" not in ident


class TestBaselineBranch:
    def test_auto_derives_a_branch_per_monitor(self):
        assert identity.resolve_baseline_branch(
            identity.AUTO, "package-lock.json"
        ) == "dependency-baseline/package-lock.json"

    def test_an_explicit_branch_is_used_as_given(self):
        assert identity.resolve_baseline_branch("custom", "x") == "custom"

    def test_empty_means_the_scanned_branch(self):
        assert identity.resolve_baseline_branch("", "x") == ""

    @requires_git
    @pytest.mark.parametrize("manifest", [
        "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
        "uv.lock", "requirements.txt", "Gemfile.lock", "pyproject.toml",
        "setup.cfg", "package.json", "Gemfile",
        "web/poetry.lock", "a/../b/uv.lock", ".hidden/Gemfile.lock",
        "packages/" * 6 + "poetry.lock",
    ])
    def test_every_auto_detected_manifest_names_a_pushable_branch(self, manifest):
        """The push builds `refs/heads/<branch>`, and an invalid refspec is
        refused outright — after the delta comment has already been posted.
        The list mirrors the auto-detection order in action.yml."""
        branch = identity.resolve_baseline_branch(
            identity.AUTO, identity.monitor_id(manifest))
        assert git_accepts_branch(branch), branch


class TestCli:
    def test_every_output_is_written(self, tmp_path, monkeypatch, capsys):
        out = tmp_path / "gh-output"
        monkeypatch.setenv("GITHUB_OUTPUT", str(out))
        rc = identity.run(["--manifest", "web/package-lock.json"])
        assert rc == 0
        written = dict(line.split("=", 1)
                       for line in out.read_text().splitlines())
        assert written == {
            "id": "web-package-lock.json",
            "baseline-branch": "dependency-baseline/web-package-lock.json",
            "marker-standard": "dependency-monitor/web-package-lock.json",
            "marker-critical": "dependency-malware/web-package-lock.json",
        }

    def test_the_two_markers_are_never_equal(self, tmp_path, monkeypatch):
        """The issue lookup relies on this: disjoint markers are what replaced
        the exclude-label filtering the two buckets used to need."""
        monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "gh-output"))
        identity.run(["--manifest", "package-lock.json"])
        written = dict(
            line.split("=", 1)
            for line in (tmp_path / "gh-output").read_text().splitlines())
        assert written["marker-standard"] != written["marker-critical"]

    def test_an_unusable_manifest_fails_the_step(self, monkeypatch, capsys):
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        assert identity.run(["--manifest", "///"]) == 1
        assert "::error::" in capsys.readouterr().err

    def test_outputs_survive_an_unset_github_output(self, monkeypatch, capsys):
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        assert identity.run(["--manifest", "package-lock.json"]) == 0
        assert "id=package-lock.json" in capsys.readouterr().out

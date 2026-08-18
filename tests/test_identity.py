"""Guards on the identity a monitor derives from its manifest.

The id names a branch and two labels, and both are durable: a change to it
orphans an existing baseline and opens fresh issues. So these pin the shape of
the slug, not merely that one exists — and pin the collision property that the
truncation depends on, since two monitors sharing an id silently overwrite each
other's state.
"""

import pytest

from monitor import identity


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
        ) == "rl-protect-baseline/package-lock.json"

    def test_an_explicit_branch_is_used_as_given(self):
        assert identity.resolve_baseline_branch("custom", "x") == "custom"

    def test_empty_means_the_scanned_branch(self):
        assert identity.resolve_baseline_branch("", "x") == ""


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
            "baseline-branch": "rl-protect-baseline/web-package-lock.json",
            "marker-standard": "rl-protect-monitor/web-package-lock.json",
            "marker-critical": "rl-protect-malware/web-package-lock.json",
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

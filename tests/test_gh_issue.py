"""Guards on the `gh` calls the notifier builds.

`subprocess.run` is faked, so these assert the arguments the module *builds*,
not that `gh` accepts them. That is enough for the invariant worth protecting:
each run's delta is measured against the previous run's baseline and lives
only in its comment — so on an existing issue the comment must be posted
before the body edit, and a newly created issue must get the delta comment
its stats body points at.
"""

import json
import subprocess

import pytest

from monitor import gh_issue

CREATED_URL = "https://github.com/owner/name/issues/9"


class FakeGh:
    """Records `gh` invocations; answers `issue list` with `open_number`.

    `open_issues` overrides that with (number, labels) pairs newest first —
    the order `gh issue list` returns — for the cases that turn on which
    labels an issue carries.
    """

    def __init__(self, open_number=None, open_issues=None):
        self.open_number = open_number
        self.open_issues = open_issues
        self.calls = []

    def _listing(self, cmd):
        if self.open_issues is None:
            if self.open_number is None:
                return []
            return [{"number": self.open_number, "labels": []}]
        wanted = flag(cmd, "--label")
        return [{"number": number,
                 "labels": [{"name": name} for name in labels]}
                for number, labels in self.open_issues if wanted in labels]

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        stdout = ""
        if cmd[:3] == ["gh", "issue", "list"]:
            stdout = json.dumps(self._listing(cmd))
        elif cmd[:3] == ["gh", "issue", "create"]:
            stdout = CREATED_URL + "\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    def issue_calls(self):
        """`gh issue <verb> …` argv lists, in call order."""
        return [c for c in self.calls if c[:2] == ["gh", "issue"]]

    def verbs(self):
        return [c[2] for c in self.issue_calls()]

    def call(self, verb):
        matched = [c for c in self.issue_calls() if c[2] == verb]
        assert len(matched) == 1, f"expected exactly one `gh issue {verb}`"
        return matched[0]


def flag(argv, name):
    return argv[argv.index(name) + 1]


def label_creates(fake):
    """`gh label create …` argv lists, in call order."""
    return [c for c in fake.calls if c[:3] == ["gh", "label", "create"]]


@pytest.fixture
def outputs(tmp_path):
    (tmp_path / "issue.title").write_text(
        "🚨 Malware/tampering detected in dependencies (package-lock.json)\n")
    (tmp_path / "issue.md").write_text(
        "rl-protect flagged **malware or tampering**.\n\n"
        "### Monitoring stats\n\n- **Runs with alerts:** 3\n")
    (tmp_path / "issue_comment.md").write_text(
        "**🚨 Malware/tampering: 1 new**\n\n<details>\n"
        "<summary>Show the full delta</summary>\n\n"
        "| Packages | Category | Finding |\n|---|---|---|\n"
        "| `pkg:npm/left-pad@1.3.0` | malware | MAL-2026-1 |\n\n</details>\n")
    return tmp_path


def notify(monkeypatch, fake, outputs, labels=("rl-protect-monitor",),
           exclude=(), body_only=False, rc=0):
    monkeypatch.setattr(gh_issue.subprocess, "run", fake)
    argv = ["--repo", "owner/name",
            "--title-file", str(outputs / "issue.title"),
            "--body-file", str(outputs / "issue.md")]
    argv += (["--body-only"] if body_only
             else ["--comment-file", str(outputs / "issue_comment.md")])
    for label in labels:
        argv += ["--label", label]
    for label in exclude:
        argv += ["--exclude-label", label]
    assert gh_issue.run(argv) == rc
    return fake


class TestLabelCreation:
    def test_every_label_is_created(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=1), outputs,
                      labels=("rl-protect-malware", "rl-protect-monitor"))
        assert [c[3] for c in label_creates(fake)] == ["rl-protect-malware",
                                                       "rl-protect-monitor"]

    def test_an_existing_label_is_not_overwritten(self, monkeypatch, outputs):
        """`--force` makes this an upsert, which resets a maintainer's own
        colour and description on every notifying run."""
        fake = notify(monkeypatch, FakeGh(open_number=1), outputs)
        assert not any("--force" in cmd for cmd in label_creates(fake))


class TestExistingIssue:
    def test_comment_is_posted_before_the_body_edit(self, monkeypatch, outputs):
        """Reordering these two reintroduces the delta loss fixed in 1.2.0."""
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        verbs = fake.verbs()
        assert verbs.index("comment") < verbs.index("edit")

    def test_comment_carries_the_delta_file(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        comment = fake.call("comment")
        assert flag(comment, "--body-file") == str(outputs / "issue_comment.md")
        assert "--body" not in comment

    def test_edit_targets_the_open_issue_with_body_and_title(self, monkeypatch,
                                                             outputs):
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        edit = fake.call("edit")
        assert edit[3] == "7"
        assert flag(edit, "--body-file") == str(outputs / "issue.md")
        assert flag(edit, "--title").startswith("🚨 Malware/tampering")

    def test_no_second_issue_is_opened(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        assert "create" not in fake.verbs()

    def test_comment_file_is_required(self, monkeypatch, outputs):
        """Falling back to the body would post the stats page as the delta
        comment and the findings would never reach the issue."""
        fake = FakeGh(open_number=7)
        monkeypatch.setattr(gh_issue.subprocess, "run", fake)
        with pytest.raises(SystemExit):
            gh_issue.run(["--repo", "owner/name",
                          "--title-file", str(outputs / "issue.title"),
                          "--body-file", str(outputs / "issue.md"),
                          "--label", "rl-protect-monitor"])
        assert fake.issue_calls() == []

    def test_empty_comment_file_is_rejected_before_any_gh_call(self,
                                                               monkeypatch,
                                                               outputs):
        """argparse turns "" into Path('.') — gh must never see it."""
        fake = FakeGh(open_number=7)
        monkeypatch.setattr(gh_issue.subprocess, "run", fake)
        with pytest.raises(SystemExit):
            gh_issue.run(["--repo", "owner/name",
                          "--title-file", str(outputs / "issue.title"),
                          "--body-file", str(outputs / "issue.md"),
                          "--comment-file", "",
                          "--label", "rl-protect-monitor"])
        assert fake.calls == []


class TestNoOpenIssue:
    def test_creation_is_followed_by_the_delta_comment(self, monkeypatch,
                                                       outputs):
        """The stats body points at the newest comment — it has to exist."""
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs)
        assert fake.verbs() == ["list", "create", "comment"]
        comment = fake.call("comment")
        assert comment[3] == "9"  # parsed from the URL `gh issue create` printed
        assert flag(comment, "--body-file") == str(outputs / "issue_comment.md")

    def test_create_carries_every_label(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      labels=("rl-protect-monitor", "rl-protect-malware"))
        create = fake.call("create")
        labels = [create[i + 1] for i, arg in enumerate(create) if arg == "--label"]
        assert labels == ["rl-protect-monitor", "rl-protect-malware"]

    def test_create_opens_the_issue_with_the_stats_body_and_title(
            self, monkeypatch, outputs):
        """The create path had no argv assertion at all: swapping the comment
        file in as the body opens every rolling issue with a delta as its
        landing page, and the stats body never reaches the issue that first
        creates it."""
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs)
        create = fake.call("create")
        assert flag(create, "--body-file") == str(outputs / "issue.md")
        assert flag(create, "--title").startswith("🚨 Malware/tampering")

    def test_rolling_issue_is_looked_up_by_the_first_label(self, monkeypatch,
                                                           outputs):
        """The first label is the marker; the rest are decoration."""
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      labels=("rl-protect-monitor", "rl-protect-malware"))
        assert flag(fake.call("list"), "--label") == "rl-protect-monitor"

    def test_created_issue_url_is_echoed_to_the_log(self, monkeypatch, outputs,
                                                    capsys):
        notify(monkeypatch, FakeGh(open_number=None), outputs)
        assert CREATED_URL in capsys.readouterr().out

    def test_create_failure_surfaces_gh_stderr(self, monkeypatch, outputs,
                                               capsys):
        """CalledProcessError's message is only the exit status — the actual
        reason (missing issues:write, issues disabled) is on gh's stderr."""
        class FailingCreateGh(FakeGh):
            def __call__(self, cmd, **kwargs):
                result = super().__call__(cmd, **kwargs)
                if cmd[:3] == ["gh", "issue", "create"]:
                    return subprocess.CompletedProcess(
                        cmd, 1, stdout="",
                        stderr="GraphQL: Issues are disabled for this repo\n")
                return result

        monkeypatch.setattr(gh_issue.subprocess, "run", FailingCreateGh())
        with pytest.raises(subprocess.CalledProcessError):
            gh_issue.run(["--repo", "owner/name",
                          "--title-file", str(outputs / "issue.title"),
                          "--body-file", str(outputs / "issue.md"),
                          "--comment-file", str(outputs / "issue_comment.md"),
                          "--label", "rl-protect-monitor"])
        assert "Issues are disabled" in capsys.readouterr().err


class TestBodyOnlyRefresh:
    """A run that only resolved findings. Its counters moved, so the stats
    body is stale and must be refreshed — but there is nothing to report, so
    nothing is posted and no issue is opened."""

    def test_the_body_is_edited_and_nothing_is_posted(self, monkeypatch,
                                                       outputs):
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs,
                      body_only=True)
        assert fake.verbs() == ["list", "edit"]
        edit = fake.call("edit")
        assert edit[3] == "7"
        assert flag(edit, "--body-file") == str(outputs / "issue.md")

    def test_no_issue_is_opened_when_none_is_open(self, monkeypatch, outputs):
        """Opening an issue to announce that nothing is wrong is noise."""
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      body_only=True)
        assert fake.verbs() == ["list"]

    def test_body_only_and_comment_file_are_mutually_exclusive(self,
                                                               monkeypatch,
                                                               outputs):
        """Both together is ambiguous: --body-only would silently win and the
        delta it was given would never be posted anywhere."""
        fake = FakeGh(open_number=7)
        monkeypatch.setattr(gh_issue.subprocess, "run", fake)
        with pytest.raises(SystemExit):
            gh_issue.run(["--repo", "owner/name",
                          "--title-file", str(outputs / "issue.title"),
                          "--body-file", str(outputs / "issue.md"),
                          "--comment-file", str(outputs / "issue_comment.md"),
                          "--body-only",
                          "--label", "rl-protect-monitor"])
        assert fake.calls == []


MALWARE_ISSUE = (2, ["rl-protect-malware", "rl-protect-monitor"])
STANDARD_ISSUE = (1, ["rl-protect-monitor"])


class TestBucketIsolation:
    """The critical issue carries the shared issue-label as well as its own
    marker, so a standard lookup by the shared label alone can land on the
    malware incident — commenting a standard delta into that thread and
    replacing its title and body with the standard bucket's stats page."""

    def test_the_malware_issue_is_not_adopted_as_the_standard_issue(
            self, monkeypatch, outputs):
        fake = notify(monkeypatch,
                      FakeGh(open_issues=[MALWARE_ISSUE, STANDARD_ISSUE]),
                      outputs, exclude=("rl-protect-malware",))
        assert fake.call("comment")[3] == "1"
        assert fake.call("edit")[3] == "1"

    def test_a_new_issue_opens_when_only_the_malware_issue_matches(
            self, monkeypatch, outputs):
        """A second standard issue is recoverable; a clobbered incident is
        not — the malware issue's counters would be gone for good."""
        fake = notify(monkeypatch, FakeGh(open_issues=[MALWARE_ISSUE]),
                      outputs, exclude=("rl-protect-malware",))
        assert "edit" not in fake.verbs()
        assert "create" in fake.verbs()

    def test_the_critical_lookup_still_finds_its_own_issue(self, monkeypatch,
                                                           outputs):
        """Its marker is unique to the bucket, so it needs no exclusion."""
        fake = notify(monkeypatch, FakeGh(open_issues=[MALWARE_ISSUE]),
                      outputs,
                      labels=("rl-protect-malware", "rl-protect-monitor"))
        assert fake.call("edit")[3] == "2"


class TestLookupPaging:
    """The lookup reads one page of labelled issues. A rolling issue past the
    end of it reads as absent, and the caller opens a duplicate of the thread
    already holding the bucket's history — so a full page has to say so."""

    def test_the_lookup_asks_for_the_full_page(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=1), outputs)
        assert (int(flag(fake.call("list"), "--limit"))
                == gh_issue.ISSUE_LOOKUP_LIMIT)

    def test_a_full_page_of_excluded_issues_warns_before_duplicating(
            self, monkeypatch, outputs, capsys):
        # Every issue carries the marker *and* the exclusion, so the page
        # fills without a match — the bucket's own issue could be just past.
        crowd = [(n, ["rl-protect-monitor", "rl-protect-malware"])
                 for n in range(gh_issue.ISSUE_LOOKUP_LIMIT, 0, -1)]
        fake = notify(monkeypatch, FakeGh(open_issues=crowd), outputs,
                      exclude=("rl-protect-malware",))
        assert "create" in fake.verbs()
        assert "::warning::" in capsys.readouterr().err

    def test_a_partial_page_creates_without_warning(self, monkeypatch,
                                                    outputs, capsys):
        """The page was not full, so "no match" is the whole truth."""
        fake = notify(monkeypatch, FakeGh(open_issues=[MALWARE_ISSUE]),
                      outputs, exclude=("rl-protect-malware",))
        assert "create" in fake.verbs()
        assert "::warning::" not in capsys.readouterr().err


class BadCreateOutputGh(FakeGh):
    """`gh issue create` prints something that doesn't end in the number.

    `issue list` answers `found_after_create` once the create has happened,
    mimicking the just-created issue being (or not being) findable by label.
    """

    def __init__(self, found_after_create=None):
        super().__init__(open_number=None)
        self.found_after_create = found_after_create

    def __call__(self, cmd, **kwargs):
        result = super().__call__(cmd, **kwargs)
        if cmd[:3] == ["gh", "issue", "create"]:
            self.open_number = self.found_after_create
            return subprocess.CompletedProcess(
                cmd, 0, stdout="Creating issue in owner/name\n", stderr="")
        return result


class TestUnparseableCreateOutput:
    def test_issue_is_refound_by_label_and_gets_the_comment(self, monkeypatch,
                                                            outputs):
        """The delta lives only in the comment — recover the number by label."""
        fake = notify(monkeypatch, BadCreateOutputGh(found_after_create=9),
                      outputs)
        assert fake.verbs() == ["list", "create", "list", "comment"]
        comment = fake.call("comment")
        assert comment[3] == "9"
        assert flag(comment, "--body-file") == str(outputs / "issue_comment.md")

    def test_run_fails_when_the_issue_cannot_be_refound(self, monkeypatch,
                                                        outputs):
        """Exiting 0 here would commit the baseline and lose the delta."""
        fake = notify(monkeypatch, BadCreateOutputGh(found_after_create=None),
                      outputs, rc=1)
        assert "comment" not in fake.verbs()

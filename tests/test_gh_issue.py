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
           body_only=False, rc=0, assignees=()):
    monkeypatch.setattr(gh_issue.subprocess, "run", fake)
    argv = ["--repo", "owner/name",
            "--title-file", str(outputs / "issue.title"),
            "--body-file", str(outputs / "issue.md")]
    argv += (["--body-only"] if body_only
             else ["--comment-file", str(outputs / "issue_comment.md")])
    for label in labels:
        argv += ["--label", label]
    for user in assignees:
        argv += ["--assignee", user]
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


#: How the two buckets of one monitor are labelled: a marker naming bucket and
#: monitor, plus bare classification labels that are only there for humans to
#: filter on. `pkg` stands in for the monitor id.
CRITICAL_LABELS = ("rl-protect-malware/pkg", "rl-protect-malware",
                   "rl-protect-monitor")
STANDARD_LABELS = ("rl-protect-monitor/pkg", "rl-protect-monitor")

MALWARE_ISSUE = (2, list(CRITICAL_LABELS))
STANDARD_ISSUE = (1, list(STANDARD_LABELS))
#: Another monitor in the same repo, scanning a second manifest.
OTHER_MALWARE_ISSUE = (3, ["rl-protect-malware/req", "rl-protect-malware",
                           "rl-protect-monitor"])


class TestBucketIsolation:
    """Markers name bucket *and* monitor, so every lookup is unambiguous.

    Both issues carry the bare `rl-protect-monitor` label, so a lookup by that
    alone could land the standard bucket's delta on the malware incident —
    commenting into that thread and replacing its title and stats body. The
    marker is what keeps them apart, with no exclusion rules involved.
    """

    def test_the_malware_issue_is_not_adopted_as_the_standard_issue(
            self, monkeypatch, outputs):
        fake = notify(monkeypatch,
                      FakeGh(open_issues=[MALWARE_ISSUE, STANDARD_ISSUE]),
                      outputs, labels=STANDARD_LABELS)
        assert fake.call("comment")[3] == "1"
        assert fake.call("edit")[3] == "1"

    def test_a_new_issue_opens_when_only_the_malware_issue_is_open(
            self, monkeypatch, outputs):
        """A second standard issue is recoverable; a clobbered incident is
        not — the malware issue's counters would be gone for good."""
        fake = notify(monkeypatch, FakeGh(open_issues=[MALWARE_ISSUE]),
                      outputs, labels=STANDARD_LABELS)
        assert "edit" not in fake.verbs()
        assert "create" in fake.verbs()

    def test_the_critical_lookup_finds_its_own_issue(self, monkeypatch,
                                                     outputs):
        fake = notify(monkeypatch, FakeGh(open_issues=[MALWARE_ISSUE]),
                      outputs, labels=CRITICAL_LABELS)
        assert fake.call("edit")[3] == "2"

    def test_another_monitors_issue_is_never_adopted(self, monkeypatch,
                                                     outputs):
        """Two manifests scanned in one repo each own their thread: adopting
        the other's would interleave deltas and overwrite its stats body."""
        fake = notify(monkeypatch, FakeGh(open_issues=[OTHER_MALWARE_ISSUE]),
                      outputs, labels=CRITICAL_LABELS)
        assert "edit" not in fake.verbs()
        assert "create" in fake.verbs()

    def test_no_exclusion_is_needed_to_get_there(self, monkeypatch, outputs):
        """The property the deleted --exclude-label machinery used to buy."""
        fake = notify(monkeypatch,
                      FakeGh(open_issues=[MALWARE_ISSUE, STANDARD_ISSUE]),
                      outputs, labels=STANDARD_LABELS)
        assert not any("--exclude-label" in cmd for cmd in fake.calls)


class TestLookup:
    def test_the_marker_is_the_only_filter(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=1), outputs,
                      labels=STANDARD_LABELS)
        listing = fake.call("list")
        assert flag(listing, "--label") == "rl-protect-monitor/pkg"
        assert listing.count("--label") == 1

    def test_one_row_is_enough(self, monkeypatch, outputs):
        """The marker names one bucket of one monitor, so the newest match is
        the answer — no page to scan and nothing to skip past."""
        fake = notify(monkeypatch, FakeGh(open_number=1), outputs)
        assert flag(fake.call("list"), "--limit") == "1"


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


class TestAssignees:
    """Assignment is the only lever the action has on who gets notified.

    A label cannot subscribe anyone — GitHub has no per-label notification —
    so on a repository nobody watches, an unassigned rolling issue alerts into
    a void. These pin that the assignment happens, that it happens early
    enough to matter, and that it can never cost us the alert itself.
    """

    def test_assignees_are_added_to_a_newly_created_issue(self, monkeypatch,
                                                          outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      assignees=("alice", "bob"))
        edit = fake.call("edit")
        assert edit[3] == "9"
        added = [edit[i + 1] for i, arg in enumerate(edit)
                 if arg == "--add-assignee"]
        assert added == ["alice", "bob"]

    def test_assignment_precedes_the_delta_comment(self, monkeypatch, outputs):
        """Assigning after the comment would subscribe them one delta too
        late: they would be told they own the issue, not what it says."""
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      assignees=("alice",))
        assert fake.verbs() == ["list", "create", "edit", "comment"]

    def test_no_assignees_means_no_edit_call(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs)
        assert fake.verbs() == ["list", "create", "comment"]

    def test_an_existing_issue_is_not_reassigned(self, monkeypatch, outputs):
        """Re-adding every run would revert a maintainer who unassigned
        themselves — the upsert bug `--force` caused for labels."""
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs,
                      assignees=("alice",))
        assert not any("--add-assignee" in cmd for cmd in fake.calls)

    def test_a_failed_assignment_does_not_lose_the_alert(self, monkeypatch,
                                                         outputs, capsys):
        """A typo'd username must not stop a malware alert from landing."""
        class FailingAssignGh(FakeGh):
            def __call__(self, cmd, **kwargs):
                result = super().__call__(cmd, **kwargs)
                if cmd[:3] == ["gh", "issue", "edit"]:
                    return subprocess.CompletedProcess(
                        cmd, 1, stdout="",
                        stderr="could not assign user 'alicce'\n")
                return result

        fake = notify(monkeypatch, FailingAssignGh(open_number=None), outputs,
                      assignees=("alicce",))
        assert "comment" in fake.verbs()
        err = capsys.readouterr().err
        assert "::warning::" in err and "alicce" in err

    def test_body_only_never_assigns(self, monkeypatch, outputs):
        """A resolution-only run opens nothing, so there is nothing to assign
        and its edit must stay a plain body refresh."""
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs,
                      body_only=True, assignees=("alice",))
        assert not any("--add-assignee" in cmd for cmd in fake.calls)

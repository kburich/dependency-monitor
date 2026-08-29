"""Guards on the `gh` calls the notifier builds.

`subprocess.run` is faked, so these assert the arguments the module *builds*,
not that `gh` accepts them. That is enough for the invariant worth protecting:
the rolling issue is append-only — its body is written once, at creation,
carrying that run's delta, and every later delta is a comment. Nothing is
ever edited, so each delta's only durable copy is the body or comment that
carries it, and a resolution-only delta must never open an issue.
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
    (tmp_path / "issue_comment.md").write_text(
        "**🚨 Malware/tampering: 1 new**\n\n<details>\n"
        "<summary>Show the full delta</summary>\n\n"
        "| Packages | Category | Finding |\n|---|---|---|\n"
        "| `pkg:npm/left-pad@1.3.0` | malware | MAL-2026-1 |\n\n</details>\n")
    return tmp_path


def notify(monkeypatch, fake, outputs, labels=("rl-protect-monitor",),
           no_create=False, rc=0, assignees=()):
    monkeypatch.setattr(gh_issue.subprocess, "run", fake)
    argv = ["--repo", "owner/name",
            "--title-file", str(outputs / "issue.title"),
            "--comment-file", str(outputs / "issue_comment.md")]
    if no_create:
        argv += ["--no-create"]
    for label in labels:
        argv += ["--label", label]
    for user in assignees:
        argv += ["--assignee", user]
    assert gh_issue.run(argv) == rc
    return fake


class TestLabelCreation:
    def test_every_label_is_created_before_the_issue(self, monkeypatch,
                                                     outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      labels=("rl-protect-malware", "rl-protect-monitor"))
        assert [c[3] for c in label_creates(fake)] == ["rl-protect-malware",
                                                       "rl-protect-monitor"]

    def test_an_existing_label_is_not_overwritten(self, monkeypatch, outputs):
        """`--force` makes this an upsert, which resets a maintainer's own
        colour and description on the run that used it."""
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs)
        assert not any("--force" in cmd for cmd in label_creates(fake))

    def test_commenting_touches_no_labels(self, monkeypatch, outputs):
        """Labels are applied at creation, the only moment they are needed;
        commenting on an existing issue must not make label API calls."""
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        assert label_creates(fake) == []


class TestExistingIssue:
    def test_the_delta_is_posted_as_a_comment(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        comment = fake.call("comment")
        assert comment[3] == "7"
        assert flag(comment, "--body-file") == str(outputs / "issue_comment.md")
        assert "--body" not in comment

    def test_nothing_is_edited(self, monkeypatch, outputs):
        """Append-only: no body refresh, no title refresh — an edit call
        here means the thread is no longer a faithful changelog."""
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        assert fake.verbs() == ["list", "comment"]

    def test_no_second_issue_is_opened(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        assert "create" not in fake.verbs()

    def test_comment_file_is_required(self, monkeypatch, outputs):
        fake = FakeGh(open_number=7)
        monkeypatch.setattr(gh_issue.subprocess, "run", fake)
        with pytest.raises(SystemExit):
            gh_issue.run(["--repo", "owner/name",
                          "--title-file", str(outputs / "issue.title"),
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
                          "--comment-file", "",
                          "--label", "rl-protect-monitor"])
        assert fake.calls == []


class TestNoOpenIssue:
    def test_the_issue_is_created_with_the_delta_as_its_body(self, monkeypatch,
                                                             outputs):
        """Creation is what notifies, with the body — so the body must be
        the delta itself, and no separate comment should follow it: the
        thread would open with the same delta twice."""
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs)
        assert fake.verbs() == ["list", "create"]
        create = fake.call("create")
        assert flag(create, "--body-file") == str(outputs / "issue_comment.md")
        assert flag(create, "--title").startswith("🚨 Malware/tampering")

    def test_create_carries_every_label(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      labels=("rl-protect-monitor", "rl-protect-malware"))
        create = fake.call("create")
        labels = [create[i + 1] for i, arg in enumerate(create) if arg == "--label"]
        assert labels == ["rl-protect-monitor", "rl-protect-malware"]

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
                          "--comment-file", str(outputs / "issue_comment.md"),
                          "--label", "rl-protect-monitor"])
        assert "Issues are disabled" in capsys.readouterr().err


class TestNoCreate:
    """A resolution-only delta: commented onto the bucket's open issue, but
    an issue must never be opened to announce that something nobody was ever
    told about has been fixed."""

    def test_an_open_issue_still_gets_the_resolution_comment(self,
                                                             monkeypatch,
                                                             outputs):
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs,
                      no_create=True)
        assert fake.verbs() == ["list", "comment"]
        assert fake.call("comment")[3] == "7"

    def test_no_issue_is_opened_when_none_is_open(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      no_create=True)
        assert fake.verbs() == ["list"]
        assert label_creates(fake) == []

    def test_never_assigns_when_nothing_was_created(self, monkeypatch,
                                                    outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      no_create=True, assignees=("alice",))
        assert not any("--add-assignee" in cmd for cmd in fake.calls)


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

    Both issues carry the bare `rl-protect-monitor` label, so a lookup by
    that alone could land the standard bucket's delta on the malware
    incident's thread. The marker is what keeps them apart, with no
    exclusion rules involved.
    """

    def test_the_malware_issue_is_not_adopted_as_the_standard_issue(
            self, monkeypatch, outputs):
        fake = notify(monkeypatch,
                      FakeGh(open_issues=[MALWARE_ISSUE, STANDARD_ISSUE]),
                      outputs, labels=STANDARD_LABELS)
        assert fake.call("comment")[3] == "1"

    def test_a_new_issue_opens_when_only_the_malware_issue_is_open(
            self, monkeypatch, outputs):
        """A second standard issue is recoverable; a delta commented into
        the malware incident's thread is not."""
        fake = notify(monkeypatch, FakeGh(open_issues=[MALWARE_ISSUE]),
                      outputs, labels=STANDARD_LABELS)
        assert "comment" not in fake.verbs()
        assert "create" in fake.verbs()

    def test_the_critical_lookup_finds_its_own_issue(self, monkeypatch,
                                                     outputs):
        fake = notify(monkeypatch, FakeGh(open_issues=[MALWARE_ISSUE]),
                      outputs, labels=CRITICAL_LABELS)
        assert fake.call("comment")[3] == "2"

    def test_another_monitors_issue_is_never_adopted(self, monkeypatch,
                                                     outputs):
        """Two manifests scanned in one repo each own their thread: adopting
        the other's would interleave their deltas."""
        fake = notify(monkeypatch, FakeGh(open_issues=[OTHER_MALWARE_ISSUE]),
                      outputs, labels=CRITICAL_LABELS)
        assert "comment" not in fake.verbs()
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
    """The number only matters for assignment now: the delta is already
    durable in the body the create call just wrote, so a lost number costs
    at worst a subscription — a warning, never the run."""

    def test_issue_is_refound_by_label_for_the_assignment(self, monkeypatch,
                                                          outputs):
        fake = notify(monkeypatch, BadCreateOutputGh(found_after_create=9),
                      outputs, assignees=("alice",))
        assert fake.verbs() == ["list", "create", "list", "edit"]
        edit = fake.call("edit")
        assert edit[3] == "9"
        assert flag(edit, "--add-assignee") == "alice"

    def test_an_unfindable_issue_warns_instead_of_failing(self, monkeypatch,
                                                          outputs, capsys):
        fake = notify(monkeypatch, BadCreateOutputGh(found_after_create=None),
                      outputs, assignees=("alice",))
        assert "edit" not in fake.verbs()
        err = capsys.readouterr().err
        assert "::warning::" in err and "alice" in err

    def test_without_assignees_the_number_is_not_even_looked_up(self,
                                                                monkeypatch,
                                                                outputs):
        fake = notify(monkeypatch, BadCreateOutputGh(found_after_create=9),
                      outputs)
        assert fake.verbs() == ["list", "create"]


class TestAssignees:
    """Assignment is the only lever the action has on who gets notified.

    A label cannot subscribe anyone — GitHub has no per-label notification —
    so on a repository nobody watches, an unassigned rolling issue alerts into
    a void. These pin that the assignment happens on creation, and that it
    can never cost us the alert itself.
    """

    def test_assignees_are_added_to_a_newly_created_issue(self, monkeypatch,
                                                          outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      assignees=("alice", "bob"))
        assert fake.verbs() == ["list", "create", "edit"]
        edit = fake.call("edit")
        assert edit[3] == "9"
        added = [edit[i + 1] for i, arg in enumerate(edit)
                 if arg == "--add-assignee"]
        assert added == ["alice", "bob"]

    def test_assignment_is_not_folded_into_the_create_call(self, monkeypatch,
                                                           outputs):
        """A typo'd username on `gh issue create --assignee` fails the
        creation itself — the alert must land before anyone is subscribed."""
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs,
                      assignees=("alice",))
        assert "--assignee" not in fake.call("create")

    def test_no_assignees_means_no_edit_call(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs)
        assert fake.verbs() == ["list", "create"]

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
        assert "create" in fake.verbs()
        err = capsys.readouterr().err
        assert "::warning::" in err and "alicce" in err

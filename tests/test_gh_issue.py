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
    """Records `gh` invocations; answers `issue list` with `open_number`."""

    def __init__(self, open_number=None):
        self.open_number = open_number
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        stdout = ""
        if cmd[:3] == ["gh", "issue", "list"]:
            found = [] if self.open_number is None else [{"number": self.open_number}]
            stdout = json.dumps(found)
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
           rc=0):
    monkeypatch.setattr(gh_issue.subprocess, "run", fake)
    argv = ["--repo", "owner/name",
            "--title-file", str(outputs / "issue.title"),
            "--body-file", str(outputs / "issue.md"),
            "--comment-file", str(outputs / "issue_comment.md")]
    for label in labels:
        argv += ["--label", label]
    assert gh_issue.run(argv) == rc
    return fake


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

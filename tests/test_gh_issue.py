"""Guards on the `gh` calls the notifier builds.

`subprocess.run` is faked, so these assert the arguments the module *builds*,
not that `gh` accepts them. That is enough for the invariant worth protecting:
each run's delta is measured against the previous run's baseline, so a body
edit discards the earlier delta outright — the comment is the only durable
copy, and it must be posted first.
"""

import json
import subprocess

import pytest

from monitor import gh_issue


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
        "| Packages | Category | Finding |\n|---|---|---|\n"
        "| `pkg:npm/left-pad@1.3.0` | malware | MAL-2026-1 |\n")
    return tmp_path


def notify(monkeypatch, fake, outputs, labels=("rl-protect-monitor",)):
    monkeypatch.setattr(gh_issue.subprocess, "run", fake)
    argv = ["--repo", "owner/name",
            "--title-file", str(outputs / "issue.title"),
            "--body-file", str(outputs / "issue.md")]
    for label in labels:
        argv += ["--label", label]
    assert gh_issue.run(argv) == 0
    return fake


class TestExistingIssue:
    def test_comment_is_posted_before_the_body_edit(self, monkeypatch, outputs):
        """Reordering these two reintroduces the delta loss fixed in 1.2.0."""
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        verbs = fake.verbs()
        assert verbs.index("comment") < verbs.index("edit")

    def test_comment_carries_the_delta_body(self, monkeypatch, outputs):
        """A static one-liner here would leave the delta nowhere durable."""
        fake = notify(monkeypatch, FakeGh(open_number=7), outputs)
        comment = fake.call("comment")
        assert flag(comment, "--body-file") == str(outputs / "issue.md")
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


class TestNoOpenIssue:
    def test_issue_is_created_without_a_comment(self, monkeypatch, outputs):
        fake = notify(monkeypatch, FakeGh(open_number=None), outputs)
        assert fake.verbs() == ["list", "create"]

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

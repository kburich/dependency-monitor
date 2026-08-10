"""Create or update the rolling notification issue via the `gh` CLI.

One open issue per severity bucket (identified by label). On a new delta:
  - if an open issue with the label exists, post the delta as a comment and
    edit the body to match (edits don't notify subscribers — the comment does);
  - otherwise create the issue.

Each run's delta is reported relative to the baseline written by the previous
run, so consecutive deltas do not overlap. The body therefore only ever shows
the latest one; the comment thread is what preserves earlier deltas.

`--issue-comment notice` posts a one-line ping instead, after the edit rather
than before it (nothing durable is at stake). Quieter, but the delta then lives
only in the body until the next run overwrites it.

Usage:
    python -m monitor.gh_issue \
        --repo owner/name \
        --title-file out/issue_critical.title \
        --body-file out/issue_critical.md \
        --label rl-protect-monitor --label rl-protect-malware

Requires GH_TOKEN in the environment with `issues: write`.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

NOTICE_COMMENT = ("New findings detected by the scheduled rl-protect scan — "
                  "the issue body above has been updated.")


def _gh(args: List[str], capture: bool = True) -> str:
    result = subprocess.run(
        ["gh"] + args,
        check=True,
        text=True,
        capture_output=capture,
    )
    return result.stdout if capture else ""


def _ensure_labels(repo: str, labels: List[str]) -> None:
    for label in labels:
        subprocess.run(
            ["gh", "label", "create", label, "--repo", repo,
             "--color", "D93F0B", "--force",
             "--description", "Managed by rl-protect-monitor"],
            check=False, capture_output=True, text=True,
        )


def _find_open_issue(repo: str, label: str) -> Optional[int]:
    out = _gh(["issue", "list", "--repo", repo, "--state", "open",
               "--label", label, "--json", "number", "--limit", "1"])
    issues = json.loads(out or "[]")
    return issues[0]["number"] if issues else None


def run(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="rl-protect-monitor-notify")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--title-file", required=True, type=Path)
    parser.add_argument("--body-file", required=True, type=Path)
    parser.add_argument("--label", action="append", required=True,
                        dest="labels", help="May be given multiple times; "
                        "the first label identifies the rolling issue")
    parser.add_argument("--issue-comment", choices=("delta", "notice"),
                        default="delta",
                        help="What to post on an existing issue: the full "
                        "delta (default) or a one-line notice")
    args = parser.parse_args(argv)

    title = args.title_file.read_text().strip()
    marker_label = args.labels[0]

    _ensure_labels(args.repo, args.labels)
    number = _find_open_issue(args.repo, marker_label)

    if number is None:
        _gh(["issue", "create", "--repo", args.repo,
             "--title", title,
             "--body-file", str(args.body_file)]
            + [arg for label in args.labels for arg in ("--label", label)],
            capture=False)
        print(f"Created new issue labeled {marker_label}")
    else:
        edit = ["issue", "edit", str(number), "--repo", args.repo,
                "--title", title, "--body-file", str(args.body_file)]
        if args.issue_comment == "delta":
            # Comment first: the body edit discards the previous delta, and a
            # failure between the two calls must not lose it.
            _gh(["issue", "comment", str(number), "--repo", args.repo,
                 "--body-file", str(args.body_file)], capture=False)
            _gh(edit, capture=False)
        else:
            # The notice points at the body, so the body has to be current
            # first. It carries no delta of its own to lose.
            _gh(edit, capture=False)
            _gh(["issue", "comment", str(number), "--repo", args.repo,
                 "--body", NOTICE_COMMENT], capture=False)
        print(f"Updated existing issue #{number}")
    return 0


if __name__ == "__main__":
    sys.exit(run())

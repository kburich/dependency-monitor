"""Create or update the rolling notification issue via the `gh` CLI.

One open issue per severity bucket, identified by its first (marker) label.
Markers are per monitor and per bucket — `rl-protect-monitor/<id>` and
`rl-protect-malware/<id>`, derived in `monitor.identity` — so a lookup can
never resolve to the other bucket's thread or to another monitor's. The
issue carries the bare `rl-protect-monitor` / `rl-protect-malware` labels too,
but only for humans to filter on. The body is the
issue's landing page — cumulative stats, edited to current on every alert —
while each run's delta is posted as a comment (comments notify subscribers;
body edits do not). Each delta is measured against the baseline the previous
run wrote, so consecutive deltas never overlap: the comment is the only
durable copy of its delta.

On a new delta:
  - existing open issue: post the delta comment first, then edit the body —
    a failure between the two calls must not lose the delta;
  - no open issue: create it (creation itself notifies, with the body), then
    post the delta comment so the thread holds the delta the body points at.

A run that only *resolved* findings passes `--body-only`: the stats it shows
have moved, so the body is refreshed, but there is nothing to report and a
body edit does not notify. It never opens an issue.

Usage:
    python -m monitor.gh_issue \
        --repo owner/name \
        --title-file out/issue_critical.title \
        --body-file out/issue_critical.md \
        --comment-file out/issue_critical_comment.md \
        --label rl-protect-malware/package-lock.json \
        --label rl-protect-malware --label rl-protect-monitor

Requires GH_TOKEN in the environment with `issues: write`.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def _gh(args: List[str], capture: bool = True) -> str:
    result = subprocess.run(
        ["gh"] + args,
        check=False,
        text=True,
        capture_output=capture,
    )
    if result.returncode != 0:
        # gh's diagnostic is on stderr; CalledProcessError's message is only
        # the exit status, so surface the captured text before raising.
        if capture and result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        raise subprocess.CalledProcessError(
            result.returncode, result.args, result.stdout, result.stderr)
    return result.stdout if capture else ""


def _nonempty_path(value: str) -> Path:
    # argparse type: Path("") is PosixPath("."), which is truthy — an empty
    # flag value must fail parsing, not surface as a `gh` call against ".".
    if not value:
        raise argparse.ArgumentTypeError("path must be non-empty")
    return Path(value)


def _ensure_labels(repo: str, labels: List[str]) -> None:
    """Create each label if it does not exist yet, and otherwise leave it be.

    Deliberately without `--force`, which is an upsert: it reset the colour
    and description on every notifying run, so a maintainer who restyled a
    label to fit their scheme — or described it for their team — had the
    change silently reverted by the next scan. Creation is the only thing
    this action needs; how the label looks afterwards is the repo's own.
    `gh` exits nonzero when the label already exists, which is the expected
    steady state and is what `check=False` is swallowing.
    """
    for label in labels:
        subprocess.run(
            ["gh", "label", "create", label, "--repo", repo,
             "--color", "D93F0B",
             "--description", "Managed by rl-protect-monitor"],
            check=False, capture_output=True, text=True,
        )


def _find_open_issue(repo: str, label: str) -> Optional[int]:
    """Newest open issue carrying the marker `label`, or None.

    The marker names one bucket of one monitor, so the newest match *is* the
    answer and one row is enough. `gh issue list` is the strongly consistent
    endpoint, which matters because the post-creation lookup below re-reads an
    issue made seconds earlier — the search index lags behind writes.
    """
    out = _gh(["issue", "list", "--repo", repo, "--state", "open",
               "--label", label, "--json", "number", "--limit", "1"])
    issues = json.loads(out or "[]")
    return issues[0]["number"] if issues else None


def run(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="rl-protect-monitor-notify")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--title-file", required=True, type=_nonempty_path)
    parser.add_argument("--body-file", required=True, type=_nonempty_path,
                        help="Issue body: cumulative stats landing page")
    parser.add_argument("--comment-file", type=_nonempty_path,
                        help="Delta comment: the only durable copy of this "
                        "run's findings — the body is just the stats page")
    parser.add_argument("--body-only", action="store_true",
                        help="Refresh an existing issue's stats body without "
                        "commenting, for a run that only resolved findings. "
                        "Never opens an issue: there is nothing to report.")
    parser.add_argument("--label", action="append", required=True,
                        dest="labels", help="May be given multiple times; "
                        "the first label identifies the rolling issue")
    args = parser.parse_args(argv)
    # Exactly one of the two: silently falling back to the body would post
    # the stats page as the delta comment, and a delta with no comment at all
    # has no durable copy anywhere.
    if bool(args.comment_file) == args.body_only:
        parser.error("pass either --comment-file or --body-only")

    title = args.title_file.read_text().strip()
    comment_file = args.comment_file
    marker_label = args.labels[0]

    _ensure_labels(args.repo, args.labels)
    number = _find_open_issue(args.repo, marker_label)

    if args.body_only:
        if number is None:
            print(f"No open issue labeled {marker_label} — nothing to refresh")
            return 0
        _gh(["issue", "edit", str(number), "--repo", args.repo,
             "--title", title, "--body-file", str(args.body_file)],
            capture=False)
        print(f"Refreshed the stats body on issue #{number} (no new findings)")
        return 0

    if number is None:
        out = _gh(["issue", "create", "--repo", args.repo,
                   "--title", title,
                   "--body-file", str(args.body_file)]
                  + [arg for label in args.labels for arg in ("--label", label)])
        url = out.strip().splitlines()[-1] if out.strip() else ""
        print(f"Created new issue labeled {marker_label}"
              + (f": {url}" if url else ""))
        # `gh issue create` prints the new issue's URL; the delta comment
        # needs its number. The comment is the delta's only durable copy,
        # so if the URL is unparseable, re-find the issue by its marker
        # label — and fail rather than drop the delta: a nonzero exit keeps
        # the baseline uncommitted, so the next run regenerates it.
        tail = url.rsplit("/", 1)[-1] if url else ""
        if not tail.isdigit():
            print("Could not parse the new issue's number from `gh issue "
                  "create` output — looking it up by label", file=sys.stderr)
            number = _find_open_issue(args.repo, marker_label)
            if number is None:
                print(f"No open issue labeled {marker_label} found after "
                      "creation — delta comment not posted", file=sys.stderr)
                return 1
            tail = str(number)
        _gh(["issue", "comment", tail, "--repo", args.repo,
             "--body-file", str(comment_file)], capture=False)
    else:
        # Comment first: the body edit replaces the stats snapshot, but the
        # delta exists only here — a failure between the two calls must not
        # lose it.
        _gh(["issue", "comment", str(number), "--repo", args.repo,
             "--body-file", str(comment_file)], capture=False)
        _gh(["issue", "edit", str(number), "--repo", args.repo,
             "--title", title, "--body-file", str(args.body_file)],
            capture=False)
        print(f"Updated existing issue #{number}")
    return 0


if __name__ == "__main__":
    sys.exit(run())

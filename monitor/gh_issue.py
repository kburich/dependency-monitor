"""Create or comment on the rolling notification issue via the `gh` CLI.

One open issue per severity bucket, identified by its first (marker) label.
Markers are per monitor and per bucket — `dependency-monitor/<id>` and
`dependency-malware/<id>`, derived in `monitor.identity` — so a lookup can
never resolve to the other bucket's thread or to another monitor's. The
issue carries the bare `dependency-monitor` / `dependency-malware` labels
too, but only for humans to filter on.

The issue is append-only. Its body is written once, at creation, and carries
that run's delta; every later run's delta — resolutions included — is posted
as a comment, and nothing is ever edited. Each delta is measured against the
baseline the previous run wrote, so consecutive deltas never overlap: the
thread holds the only durable copy of every delta (the body for the first,
a comment for each later one) and reads as a changelog, newest at the bottom.

On a delta:
  - existing open issue: post the delta comment. Nothing else — no body or
    title refresh, ever.
  - no open issue: create it with the delta as its body (creation itself
    notifies, with the body), then assign anyone named by `--assignee` so
    they are subscribed to the comments that follow.
  - no open issue and `--no-create`: do nothing. Resolution-only runs pass
    this — an issue must not be opened to announce that something nobody
    was ever told about has been fixed.

Usage:
    python -m monitor.gh_issue \
        --repo owner/name \
        --title-file out/issue_critical.title \
        --comment-file out/issue_critical_comment.md \
        --label dependency-malware/package-lock.json \
        --label dependency-malware --label dependency-monitor

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
    and description on every run that used it, so a maintainer who restyled a
    label to fit their scheme — or described it for their team — had the
    change silently reverted by the next scan. Creation is the only thing
    this action needs; how the label looks afterwards is the repo's own.
    `gh` exits nonzero when the label already exists, which is the expected
    steady state and is what `check=False` is swallowing.

    Only called when an issue is about to be created — the one moment the
    labels are applied. Commenting on an existing issue touches no labels.
    """
    for label in labels:
        subprocess.run(
            ["gh", "label", "create", label, "--repo", repo,
             "--color", "D93F0B",
             "--description", "Managed by dependency-monitor"],
            check=False, capture_output=True, text=True,
        )


def _find_open_issue(repo: str, label: str) -> Optional[int]:
    """Newest open issue carrying the marker `label`, or None.

    The marker names one bucket of one monitor, so the newest match *is* the
    answer and one row is enough. `gh issue list` is the strongly consistent
    endpoint, which matters because the post-creation lookup below re-reads
    an issue made seconds earlier — the search index lags behind writes.
    """
    out = _gh(["issue", "list", "--repo", repo, "--state", "open",
               "--label", label, "--json", "number", "--limit", "1"])
    issues = json.loads(out or "[]")
    return issues[0]["number"] if issues else None


def _assign(repo: str, number: str, assignees: List[str]) -> None:
    """Subscribe humans to a newly opened issue by assigning them.

    Assignment is the only thing this action can do to reach someone who is
    not watching the repository. A label cannot: GitHub has no per-label
    subscription, so an unwatched repo's alerts notify nobody at all — the
    silent failure the heartbeat exists to catch, arriving by another route.

    Best-effort on purpose. A typo'd or unauthorised username must never stop
    a malware alert from being delivered, so a failure here warns and returns
    rather than raising — and it is not folded into the `gh issue create`
    call for the same reason: a bad username there fails the creation itself.
    GitHub also drops assignees who lack repo access without erroring, so the
    warning is the only signal in either direction.

    Only ever called on issue creation. Re-adding an assignee on every run
    would revert a maintainer who deliberately unassigned themselves — the
    same upsert bug that `--force` caused for labels.
    """
    if not assignees:
        return
    result = subprocess.run(
        ["gh", "issue", "edit", number, "--repo", repo]
        + [arg for user in assignees for arg in ("--add-assignee", user)],
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"::warning::Could not assign {', '.join(assignees)} to issue "
              f"#{number}: {result.stderr.strip()} — the issue itself was "
              "created. Assign someone by hand, or they are notified only if "
              "they watch the repository.", file=sys.stderr)


def run(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="dependency-monitor-notify")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--title-file", required=True, type=_nonempty_path,
                        help="Title used if the issue has to be created; an "
                        "existing issue's title is never touched")
    parser.add_argument("--comment-file", required=True, type=_nonempty_path,
                        help="This run's delta: posted as a comment on the "
                        "open rolling issue, or — when none is open — used "
                        "as the body the issue is created with")
    parser.add_argument("--no-create", action="store_true",
                        help="Never open an issue: comment if one is open, "
                        "otherwise do nothing. Passed for resolution-only "
                        "deltas, which have nothing to alert on.")
    parser.add_argument("--label", action="append", required=True,
                        dest="labels", help="May be given multiple times; "
                        "the first label identifies the rolling issue")
    parser.add_argument("--assignee", action="append", default=[],
                        dest="assignees", help="Assigned when the issue is "
                        "opened, which subscribes them to the thread. May be "
                        "given multiple times. Without one, only watchers of "
                        "the repository are notified.")
    args = parser.parse_args(argv)

    marker_label = args.labels[0]
    number = _find_open_issue(args.repo, marker_label)

    if number is not None:
        _gh(["issue", "comment", str(number), "--repo", args.repo,
             "--body-file", str(args.comment_file)], capture=False)
        print(f"Posted the delta as a comment on issue #{number}")
        return 0

    if args.no_create:
        print(f"No open issue labeled {marker_label} — resolution-only "
              "delta, nothing to alert on, no issue opened")
        return 0

    title = args.title_file.read_text().strip()
    _ensure_labels(args.repo, args.labels)
    out = _gh(["issue", "create", "--repo", args.repo,
               "--title", title,
               "--body-file", str(args.comment_file)]
              + [arg for label in args.labels for arg in ("--label", label)])
    url = out.strip().splitlines()[-1] if out.strip() else ""
    print(f"Created new issue labeled {marker_label}"
          + (f": {url}" if url else ""))

    if args.assignees:
        # `gh issue create` prints the new issue's URL; assignment needs its
        # number. If the URL is unparseable, re-find the issue by its marker
        # label — and if that fails too, warn rather than fail: the delta is
        # already durable in the body just created, and a missed assignment
        # is recoverable by hand.
        tail = url.rsplit("/", 1)[-1] if url else ""
        if not tail.isdigit():
            print("Could not parse the new issue's number from `gh issue "
                  "create` output — looking it up by label", file=sys.stderr)
            number = _find_open_issue(args.repo, marker_label)
            tail = str(number) if number is not None else ""
        if tail:
            _assign(args.repo, tail, args.assignees)
        else:
            print("::warning::Could not determine the new issue's number, so "
                  f"{', '.join(args.assignees)} were not assigned — the "
                  "issue itself was created. Assign them by hand.",
                  file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(run())

"""CLI entrypoint: normalize a fresh rl-protect report, diff it against the
committed baseline, emit markdown/JSON outputs, and update the baseline.

Usage:
    python -m monitor.main \
        --report rl-protect.report.json \
        --baseline .rl-protect/baseline.json \
        --manifest package-lock.json \
        --out-dir out/

Always exits 0 — gating (fail-on) is a decision for the calling workflow,
made from the emitted outputs, so that notification and baseline-commit
steps are never skipped by a failing diff step.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .diff import Delta, diff
from .normalize import Finding, normalize, scan_metadata
from .render import (issue_title, render_issue_body, render_issue_comment,
                     render_summary)

#: 2 moved the alerted-key set onto the finding records it duplicated.
BASELINE_SCHEMA = 2

Key = Tuple[str, str, str]


@dataclass
class Baseline:
    """A loaded baseline, whole: findings, counters, and what has alerted.

    `payload` is the raw file, kept so a rewrite can be decided by comparing
    what was durably stored against what would be stored now.
    """
    findings: List[Finding] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)
    alerted: Set[Key] = field(default_factory=set)
    payload: Dict = field(default_factory=dict)


def load_baseline(path: Path) -> Optional[Baseline]:
    """Read the baseline, or None if none exists yet."""
    if not path.exists():
        return None
    with open(path) as fh:
        data = json.load(fh)
    records = data.get("findings") or []
    findings = [Finding.from_dict(d) for d in records]
    alerted = {f.key for f, record in zip(findings, records)
               if record.get("alerted")}
    if not alerted:
        alerted = _legacy_alerted(data)
    stats = data.get("stats")
    return Baseline(findings=findings,
                    stats=stats if isinstance(stats, dict) else {},
                    alerted=alerted, payload=data)


def _legacy_alerted(data: Dict) -> Set[Key]:
    """Alerted keys from a schema-1 baseline's parallel `stats.*.alerted`.

    Without this an upgrade silently forgets what has already alerted, which
    zeroes "currently outstanding" and stops counting resolutions against
    every finding reported before the upgrade.
    """
    keys: Set[Key] = set()
    stats = data.get("stats")
    if not isinstance(stats, dict):
        return keys
    for name in ("critical", "standard"):
        bucket = stats.get(name)
        entries = bucket.get("alerted") if isinstance(bucket, dict) else None
        if isinstance(entries, list):
            keys |= {tuple(entry) for entry in entries if _is_key(entry)}
    return keys


def _count(value) -> int:
    # Corrupt stats heal to 0 like every other malformed-stats shape does —
    # a mangled cosmetic counter must not take down the whole alerting run.
    # OverflowError included: json.load accepts the non-standard `Infinity`
    # literal, and int() on the resulting float raises it rather than ValueError.
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _is_key(entry) -> bool:
    """Whether a schema-1 `alerted` entry still has `Finding.key`'s shape.

    A migration reads whatever the file happens to hold, so anything that is
    not three strings is dropped: a nested list is unhashable as a set
    element, a non-string part makes comparisons raise on mixed types, and a
    wrong-arity entry could never match a real key anyway.
    """
    return (isinstance(entry, list) and len(entry) == 3
            and all(isinstance(part, str) for part in entry))


def _bucket(raw) -> Dict:
    raw = raw if isinstance(raw, dict) else {}
    return {k: _count(raw.get(k))
            for k in ("runs", "new", "changed", "resolved")}


def update_stats(previous: Dict, alerted: Set[Key], delta: Delta,
                 now: str) -> Tuple[Dict, Set[Key]]:
    """Fold this run's delta into the counters and the alerted-key set.

    The counters cover alerts *since monitoring started*: a backlog absorbed
    silently on the first run is deliberately not counted — including its
    resolutions, so `resolved` counts only keys that had alerted. `since` is
    set the first time stats are written and preserved afterwards.
    """
    stats = {
        "since": str(previous.get("since") or now),
        "critical": _bucket(previous.get("critical")),
        "standard": _bucket(previous.get("standard")),
    }
    alerted = set(alerted)
    for name, critical in (("critical", True), ("standard", False)):
        new, changed = delta.alerts(critical)
        resolved = (delta.resolved_critical if critical
                    else delta.resolved_standard)
        bucket = stats[name]
        if new or changed:
            bucket["runs"] += 1
        bucket["new"] += len(new)
        bucket["changed"] += len(changed)
        bucket["resolved"] += sum(1 for f in resolved if f.key in alerted)
        # A resolved key leaves the set: if the finding ever returns, it
        # alerts — and is counted — as new again.
        alerted |= {f.key for f in new} | {c.after.key for c in changed}
        alerted -= {f.key for f in resolved}
    return stats, alerted


def _outstanding(findings: List[Finding], critical: bool,
                 alerted: Set[Key]) -> Tuple[int, int]:
    """(outstanding, backlog) for a severity bucket, on the stats' own basis.

    The alerted set holds exactly the keys that have alerted and not since
    been resolved, so its intersection with what is present *is* the
    outstanding count — on the same basis as `new`/`changed`/`resolved`.
    Counting every current finding instead silently folds in the first-run
    backlog those three deliberately exclude, which leaves the four numbers
    rendered as one list unable to reconcile: a reader who expects
    outstanding ≈ alerted − resolved concludes that findings appeared
    without ever alerting. The backlog gets its own line instead.
    """
    present = {f.key for f in findings
               if (f.severity == "critical") == critical}
    return len(present & alerted), len(present - alerted)


def _records(findings: List[Finding], alerted: Set[Key]) -> List[dict]:
    # purl is part of the sort key because one package can appear at several
    # versions under the same finding key; without it the file order would
    # follow report order and churn between otherwise identical scans.
    records = []
    for f in sorted(findings, key=lambda f: (f.key, f.purl)):
        record = f.to_dict()
        if f.key in alerted:
            # Flagged on the record rather than kept as a parallel list of
            # keys beside the counters. That list duplicated the key of a
            # record already in this file, grew the baseline ~44%, and turned
            # a routine lockfile bump into a multi-thousand-line diff hunk.
            record["alerted"] = True
        records.append(record)
    return records


#: Fields that move on every run regardless of findings, so they can never on
#: their own justify rewriting (and re-committing) the baseline.
_VOLATILE_FIELDS = ("generated", "scan")


def _durable(payload: Dict) -> Dict:
    return {k: v for k, v in payload.items() if k not in _VOLATILE_FIELDS}


def write_baseline(path: Path, findings: List[Finding], manifest: str,
                   meta: dict, stats: Dict, alerted: Set[Key],
                   previous: Optional[Baseline] = None) -> bool:
    """Write the baseline. Returns False if it was left untouched.

    An unconditional rewrite dirties the file even when nothing was found,
    which makes the workflow commit and push a large baseline after every
    scheduled scan. The decision compares everything durable, wholesale,
    rather than naming the fields that count: a field added later then
    participates on its own, instead of the rule living in someone's memory.
    """
    payload = {
        "schema": BASELINE_SCHEMA,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000"),
        "manifest": manifest,
        "scan": meta,
        "stats": stats,
        "findings": _records(findings, alerted),
    }
    if previous is not None and path.exists():
        if _durable(previous.payload) == _durable(payload):
            return False
        # Everything durable here is defined to move only when findings do.
        # If one moved on its own, the baseline is now rewritten, committed
        # and pushed after every scheduled scan — the churn 1.1.0 removed.
        # Migrations legitimately rewrite once, so they are not flagged.
        migrating = (previous.payload.get("schema") != BASELINE_SCHEMA
                     or not previous.stats)
        if not migrating and previous.payload.get("findings") == payload["findings"]:
            print("Baseline rewritten though no finding changed — something "
                  "in it now moves on quiet runs, which re-commits the whole "
                  "file after every scan. See write_baseline.", file=sys.stderr)

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")
    return True


def _github_output(outputs: dict) -> None:
    out_file = os.environ.get("GITHUB_OUTPUT")
    if not out_file:
        return
    with open(out_file, "a") as fh:
        for key, value in outputs.items():
            fh.write(f"{key}={value}\n")


def _github_step_summary(markdown: str) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    with open(summary_file, "a") as fh:
        fh.write(markdown)
        fh.write("\n")


def run(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="rl-protect-monitor")
    parser.add_argument("--report", required=True, type=Path,
                        help="Path to the rl-protect scan report JSON")
    parser.add_argument("--baseline", required=True, type=Path,
                        help="Path to the baseline JSON (created if missing)")
    parser.add_argument("--manifest", default="",
                        help="Manifest path, for display in summaries/issues")
    parser.add_argument("--out-dir", type=Path, default=Path("rl-protect-monitor-out"),
                        help="Directory for delta.json / markdown outputs")
    parser.add_argument("--alert-on-first-run", action="store_true",
                        help="Treat all findings as new when no baseline exists")
    parser.add_argument("--run-url", default=os.environ.get("MONITOR_RUN_URL", ""),
                        help="Workflow run URL to link from issue bodies")
    parser.add_argument("--quota-note", default="",
                        help="Optional quota warning appended to the summary")
    args = parser.parse_args(argv)

    with open(args.report) as fh:
        report = json.load(fh)
    current = normalize(report)
    meta = scan_metadata(report)
    manifest = args.manifest or "unknown manifest"

    baseline = load_baseline(args.baseline)
    first_run = baseline is None
    previous = baseline or Baseline()
    previous_stats = previous.stats

    if first_run and not args.alert_on_first_run:
        delta = Delta()
    else:
        delta = diff(previous.findings, current)

    now = datetime.now(timezone.utc)
    stats, alerted = update_stats(previous_stats, previous.alerted, delta,
                                  now.strftime("%Y-%m-%dT%H:%M:%S+0000"))
    date = now.strftime("%Y-%m-%d")
    if not previous_stats:
        # Expected once (first run, or a pre-stats baseline adopting stats).
        # On every run it means the rewritten baseline is never persisted:
        # the issue's "cumulative" stats are resetting each time.
        print(f"Cumulative stats initialized (since {date}) — they persist "
              "via the rewritten baseline", file=sys.stderr)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    delta_path = args.out_dir / "delta.json"
    with open(delta_path, "w") as fh:
        json.dump(delta.to_dict(), fh, indent=2)
        fh.write("\n")

    summary_md = render_summary(delta, manifest, first_run=first_run,
                                quota_note=args.quota_note or None)
    summary_path = args.out_dir / "summary.md"
    summary_path.write_text(summary_md)
    _github_step_summary(summary_md)

    issue_files = {}
    comment_files = {}
    for critical, name in ((True, "critical"), (False, "standard")):
        new, changed = delta.alerts(critical)
        resolved = (delta.resolved_critical if critical
                    else delta.resolved_standard)
        # Resolutions refresh the body too: they move `resolved` and
        # `outstanding` in the committed baseline, so skipping them leaves the
        # open issue asserting a pre-resolution count forever, under a footer
        # promising the body tracks the cumulative picture. No comment is
        # written for them — a body edit does not notify, and good news at
        # 03:00 should not page anyone.
        if not (new or changed or resolved):
            continue
        outstanding, backlog = _outstanding(current, critical, alerted)
        body_path = args.out_dir / f"issue_{name}.md"
        body_path.write_text(render_issue_body(
            delta, manifest, critical,
            run_url=args.run_url or None,
            stats=stats,
            outstanding=outstanding,
            backlog=backlog,
            date=date))
        title_path = args.out_dir / f"issue_{name}.title"
        title_path.write_text(issue_title(manifest, critical))
        issue_files[name] = body_path
        if new or changed:
            comment_path = args.out_dir / f"issue_{name}_comment.md"
            comment_path.write_text(render_issue_comment(
                delta, critical, manifest=manifest,
                run_url=args.run_url or None, date=date))
            comment_files[name] = comment_path

    if write_baseline(args.baseline, current, manifest, meta, stats,
                      alerted, previous=baseline):
        print(f"Baseline written to {args.baseline}", file=sys.stderr)
    else:
        print("Findings unchanged — baseline left untouched", file=sys.stderr)

    counts = delta.to_dict()["counts"]
    _github_output({
        "first-run": str(first_run).lower(),
        "new-count": counts["new"],
        "new-critical-count": counts["new_critical"],
        "changed-count": counts["changed"],
        "resolved-count": counts["resolved"],
        "has-alerts": str(delta.has_alerts).lower(),
        "has-critical-alerts": str(delta.has_critical_alerts).lower(),
        # Alerts *or* resolutions: the notify step gates on this, because a
        # resolution-only run still has a stats body to refresh.
        "has-updates": str(bool(issue_files)).lower(),
        "delta-json": delta_path,
        "summary-md": summary_path,
        "issue-critical-body": issue_files.get("critical", ""),
        "issue-standard-body": issue_files.get("standard", ""),
        "issue-critical-comment": comment_files.get("critical", ""),
        "issue-standard-comment": comment_files.get("standard", ""),
    })

    print(summary_md)
    return 0


if __name__ == "__main__":
    sys.exit(run())

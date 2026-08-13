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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .diff import Delta, diff
from .normalize import Finding, normalize, scan_metadata
from .render import (issue_title, render_issue_body, render_issue_comment,
                     render_summary)

BASELINE_SCHEMA = 1


def load_baseline(path: Path) -> Tuple[Optional[List[Finding]], Dict]:
    """Return (findings, stats). Findings is None if no baseline exists yet."""
    if not path.exists():
        return None, {}
    with open(path) as fh:
        data = json.load(fh)
    findings = [Finding.from_dict(d) for d in data.get("findings", [])]
    stats = data.get("stats")
    return findings, stats if isinstance(stats, dict) else {}


def _bucket(raw) -> Dict[str, int]:
    raw = raw if isinstance(raw, dict) else {}
    return {k: int(raw.get(k) or 0) for k in ("runs", "new", "changed", "resolved")}


def update_stats(previous: Dict, delta: Delta, now: str) -> Dict:
    """Fold this run's delta into the cumulative counters kept in the baseline.

    The counters cover alerts *since monitoring started*: a backlog absorbed
    silently on the first run is deliberately not counted. `since` is set the
    first time stats are written and preserved afterwards.
    """
    stats = {
        "since": str(previous.get("since") or now),
        "critical": _bucket(previous.get("critical")),
        "standard": _bucket(previous.get("standard")),
    }
    for name, new, changed, resolved in (
        ("critical", delta.new_critical, delta.changed_critical,
         delta.resolved_critical),
        ("standard", delta.new_standard, delta.changed_standard,
         delta.resolved_standard),
    ):
        bucket = stats[name]
        if new or changed:
            bucket["runs"] += 1
        bucket["new"] += len(new)
        bucket["changed"] += len(changed)
        bucket["resolved"] += len(resolved)
    return stats


def _outstanding(findings: List[Finding], critical: bool) -> int:
    """Distinct finding keys currently present in the given severity bucket."""
    return len({f.key for f in findings
                if (f.severity == "critical") == critical})


def _records(findings: List[Finding]) -> List[dict]:
    # purl is part of the sort key because one package can appear at several
    # versions under the same finding key; without it the file order would
    # follow report order and churn between otherwise identical scans.
    return [f.to_dict() for f in sorted(findings, key=lambda f: (f.key, f.purl))]


def write_baseline(path: Path, findings: List[Finding], manifest: str, meta: dict,
                   stats: Dict, previous: Optional[List[Finding]] = None,
                   previous_stats: Optional[Dict] = None) -> bool:
    """Write the baseline. Returns False if it was left untouched.

    The payload carries a `generated` timestamp and scan metadata that move on
    every run, so an unconditional rewrite dirties the file even when nothing
    was found — which makes the workflow commit and push a large baseline after
    every scheduled scan. Only a change in findings — or in the cumulative
    stats, which themselves only move when findings do (plus once, when a
    pre-stats baseline adopts them) — justifies a rewrite.
    """
    records = _records(findings)
    if (previous is not None and path.exists()
            and _records(previous) == records and previous_stats == stats):
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": BASELINE_SCHEMA,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000"),
        "manifest": manifest,
        "scan": meta,
        "stats": stats,
        "findings": records,
    }
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

    baseline, previous_stats = load_baseline(args.baseline)
    first_run = baseline is None

    if first_run and not args.alert_on_first_run:
        delta = Delta()
    else:
        delta = diff(baseline or [], current)

    now = datetime.now(timezone.utc)
    stats = update_stats(previous_stats, delta,
                         now.strftime("%Y-%m-%dT%H:%M:%S+0000"))
    date = now.strftime("%Y-%m-%d")

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
        relevant = (delta.new_critical or delta.changed_critical) if critical \
            else (delta.new_standard or delta.changed_standard)
        if not relevant:
            continue
        body_path = args.out_dir / f"issue_{name}.md"
        body_path.write_text(render_issue_body(
            delta, manifest, critical,
            run_url=args.run_url or None,
            stats=stats,
            outstanding=_outstanding(current, critical),
            date=date))
        comment_path = args.out_dir / f"issue_{name}_comment.md"
        comment_path.write_text(render_issue_comment(
            delta, critical, run_url=args.run_url or None, date=date))
        title_path = args.out_dir / f"issue_{name}.title"
        title_path.write_text(issue_title(manifest, critical))
        issue_files[name] = body_path
        comment_files[name] = comment_path

    if write_baseline(args.baseline, current, manifest, meta, stats,
                      previous=baseline, previous_stats=previous_stats):
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

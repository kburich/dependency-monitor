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
from typing import Dict, List, Optional

from .diff import Delta, diff
from .normalize import Finding, normalize, scan_metadata
from .render import issue_title, render_issue_comment, render_summary

#: 3 dropped the cumulative stats block and the per-record `alerted` flags.
#: The rolling issues are append-only alert logs, so nothing consumes either
#: any more; a schema-1/2 baseline is read as-is — only its findings matter —
#: and sheds the dead weight in one migration rewrite.
BASELINE_SCHEMA = 3


@dataclass
class Baseline:
    """A loaded baseline: findings, plus the raw payload they came from.

    `payload` is the raw file, kept so a rewrite can be decided by comparing
    what was durably stored against what would be stored now.
    """
    findings: List[Finding] = field(default_factory=list)
    payload: Dict = field(default_factory=dict)


def _finding_record(record) -> Optional[Finding]:
    """A baseline finding record, or None if it is too malformed to use.

    Only the three fields that make up the key are required, and only as
    strings: `split_purl` calls `.partition` on the purl, and a non-string
    part would raise on the mixed-type comparisons the key is sorted and
    matched by. Everything else already heals (`coerce_count`,
    `_normalize_status`), so a record past this check cannot raise.
    """
    if not isinstance(record, dict):
        return None
    if not all(isinstance(record.get(k), str)
               for k in ("purl", "category", "id")):
        return None
    return Finding.from_dict(record)


def load_baseline(path: Path) -> Optional[Baseline]:
    """Read the baseline, or None if none exists yet.

    Unreadable finding records are dropped rather than raised on: one
    hand-edited record must not leave the monitor dead until someone
    notices. Dropping errs the safe way — a missing baseline record makes
    its finding look new, so it alerts again rather than going quiet.
    """
    if not path.exists():
        return None
    with open(path) as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        data = {}
    records = data.get("findings")
    findings: List[Finding] = []
    dropped = 0
    for record in records if isinstance(records, list) else []:
        finding = _finding_record(record)
        if finding is None:
            dropped += 1
            continue
        findings.append(finding)
    if dropped:
        print(f"Dropped {dropped} unreadable finding record(s) from {path} — "
              "whatever they held will alert again as new", file=sys.stderr)
    return Baseline(findings=findings, payload=data)


def _records(findings: List[Finding]) -> List[dict]:
    # purl is part of the sort key because one package can appear at several
    # versions under the same finding key; without it the file order would
    # follow report order and churn between otherwise identical scans.
    return [f.to_dict()
            for f in sorted(findings, key=lambda f: (f.key, f.purl))]


#: Fields that move on every run regardless of findings, so they can never on
#: their own justify rewriting (and re-committing) the baseline.
_VOLATILE_FIELDS = ("generated", "scan")


def _durable(payload: Dict) -> Dict:
    return {k: v for k, v in payload.items() if k not in _VOLATILE_FIELDS}


def write_baseline(path: Path, findings: List[Finding], manifest: str,
                   meta: dict, previous: Optional[Baseline] = None) -> bool:
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
        "findings": _records(findings),
    }
    if previous is not None and path.exists():
        if _durable(previous.payload) == _durable(payload):
            return False
        # Everything durable here is defined to move only when findings do.
        # If one moved on its own, the baseline is now rewritten, committed
        # and pushed after every scheduled scan — the churn 1.1.0 removed.
        # Migrations legitimately rewrite once, so they are not flagged.
        migrating = previous.payload.get("schema") != BASELINE_SCHEMA
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
    parser = argparse.ArgumentParser(prog="dependency-monitor")
    parser.add_argument("--report", required=True, type=Path,
                        help="Path to the rl-protect scan report JSON")
    parser.add_argument("--baseline", required=True, type=Path,
                        help="Path to the baseline JSON (created if missing)")
    parser.add_argument("--manifest", default="",
                        help="Manifest path, for display in summaries/issues")
    parser.add_argument("--out-dir", type=Path, default=Path("dependency-monitor-out"),
                        help="Directory for delta.json / markdown outputs")
    parser.add_argument("--alert-on-first-run", action="store_true",
                        help="Treat all findings as new when no baseline exists")
    parser.add_argument("--run-url", default=os.environ.get("MONITOR_RUN_URL", ""),
                        help="Workflow run URL to link from delta comments")
    args = parser.parse_args(argv)

    with open(args.report) as fh:
        report = json.load(fh)
    current = normalize(report)
    meta = scan_metadata(report)
    manifest = args.manifest or "unknown manifest"

    baseline = load_baseline(args.baseline)
    first_run = baseline is None
    previous = baseline or Baseline()

    if first_run and not args.alert_on_first_run:
        delta = Delta()
    else:
        delta = diff(previous.findings, current)

    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    args.out_dir.mkdir(parents=True, exist_ok=True)

    delta_path = args.out_dir / "delta.json"
    with open(delta_path, "w") as fh:
        json.dump(delta.to_dict(), fh, indent=2)
        fh.write("\n")

    summary_md = render_summary(delta, manifest, first_run=first_run)
    summary_path = args.out_dir / "summary.md"
    summary_path.write_text(summary_md)
    _github_step_summary(summary_md)

    # One comment per bucket per run, resolutions included: the rolling issue
    # is an append-only log, so a resolution is reported the same way its
    # alert was — as a comment. Whether a bucket may *open* an issue is a
    # separate question, answered by the alerts flag below: a resolution-only
    # delta comments on an existing thread but must never start one.
    comment_files = {}
    alerting = {}
    for critical, name in ((True, "critical"), (False, "standard")):
        new, changed = delta.alerts(critical)
        resolved = (delta.resolved_critical if critical
                    else delta.resolved_standard)
        if not (new or changed or resolved):
            continue
        title_path = args.out_dir / f"issue_{name}.title"
        title_path.write_text(issue_title(manifest, critical))
        comment_path = args.out_dir / f"issue_{name}_comment.md"
        comment_path.write_text(render_issue_comment(
            delta, critical, manifest=manifest,
            run_url=args.run_url or None, date=date))
        comment_files[name] = comment_path
        alerting[name] = bool(new or changed)

    if write_baseline(args.baseline, current, manifest, meta,
                      previous=baseline):
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
        # resolution-only run still posts its resolution comment.
        "has-updates": str(bool(comment_files)).lower(),
        "delta-json": delta_path,
        "summary-md": summary_path,
        "issue-critical-comment": comment_files.get("critical", ""),
        "issue-standard-comment": comment_files.get("standard", ""),
        # Whether the bucket's delta carries alerts (new/worsened) rather
        # than only resolutions — the notify step opens an issue only if so.
        "issue-critical-alerts": str(alerting.get("critical", False)).lower(),
        "issue-standard-alerts": str(alerting.get("standard", False)).lower(),
    })

    print(summary_md)
    return 0


if __name__ == "__main__":
    sys.exit(run())

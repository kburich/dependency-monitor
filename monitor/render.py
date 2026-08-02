"""Render a Delta into Markdown: job summary + GitHub issue bodies."""

from __future__ import annotations

from typing import List, Optional

from .diff import Change, Delta
from .normalize import Finding

_STATUS_EMOJI = {"warn": "⚠️", "fail": "❌"}


def _finding_row(f: Finding) -> str:
    score = f"{f.score}" if f.score is not None else "—"
    emoji = _STATUS_EMOJI.get(f.status, "")
    return f"| `{f.purl}` | {f.category} | {f.finding_id} | {emoji} {f.status} | {score} | {f.title} |"


def _finding_table(findings: List[Finding]) -> str:
    header = (
        "| Package | Category | Finding | Status | CVSS | Details |\n"
        "|---|---|---|---|---|---|"
    )
    return "\n".join([header] + [_finding_row(f) for f in findings])


def _change_row(c: Change) -> str:
    what = "status escalated" if c.escalated else "count increased"
    return (
        f"| `{c.after.purl}` | {c.after.category} | {c.after.finding_id} | {what} | "
        f"{c.before.status}({c.before.count}) → {c.after.status}({c.after.count}) |"
    )


def _change_table(changes: List[Change]) -> str:
    header = "| Package | Category | Finding | Change | Before → After |\n|---|---|---|---|---|"
    return "\n".join([header] + [_change_row(c) for c in changes])


def render_summary(delta: Delta, manifest: str, first_run: bool = False,
                   quota_note: Optional[str] = None) -> str:
    """Markdown for the GitHub Actions job summary."""
    lines = ["# rl-protect monitor", "", f"Manifest: `{manifest}`", ""]

    if first_run:
        lines += [
            "🆕 **First run** — baseline recorded. Future runs alert only on "
            "*new* findings relative to this baseline.",
            "",
        ]

    if delta.is_empty and not first_run:
        lines += ["✅ **No changes** since the last scan.", ""]

    if delta.new_critical or delta.changed_critical:
        lines += ["## 🚨 New critical findings (malware / tampering)", ""]
        if delta.new_critical:
            lines += [_finding_table(delta.new_critical), ""]
        if delta.changed_critical:
            lines += [_change_table(delta.changed_critical), ""]

    if delta.new_standard:
        lines += ["## New findings", "", _finding_table(delta.new_standard), ""]

    if delta.changed_standard:
        lines += ["## Worsened findings", "", _change_table(delta.changed_standard), ""]

    if delta.resolved:
        lines += ["## Resolved since last scan", "", _finding_table(delta.resolved), ""]

    counts = delta.to_dict()["counts"]
    lines += [
        "---",
        f"New: **{counts['new']}** · Worsened: **{counts['changed']}** · "
        f"Resolved: **{counts['resolved']}** · Critical alerts: **{counts['new_critical']}**",
        "",
    ]

    if quota_note:
        lines += [f"> {quota_note}", ""]

    return "\n".join(lines)


def render_issue_body(delta: Delta, manifest: str, critical: bool,
                      run_url: Optional[str] = None) -> str:
    """Markdown body for the rolling GitHub issue (one per severity bucket)."""
    if critical:
        new, changed = delta.new_critical, delta.changed_critical
        intro = (
            "rl-protect flagged **malware or tampering** in a dependency that "
            "was previously clean. Treat this as an incident: the affected "
            "version may already be installed in dev machines and CI."
        )
    else:
        new, changed = delta.new_standard, delta.changed_standard
        intro = (
            "rl-protect found new (non-malware) findings in previously "
            "scanned dependencies."
        )

    lines = [intro, "", f"Manifest: `{manifest}`", ""]
    if new:
        lines += ["## New findings", "", _finding_table(new), ""]
    if changed:
        lines += ["## Worsened findings", "", _change_table(changed), ""]
    if run_url:
        lines += [f"[Workflow run]({run_url})", ""]
    lines += [
        "---",
        "_Maintained by the rl-protect-monitor action. This issue is updated "
        "in place when new deltas appear; it will not be duplicated._",
    ]
    return "\n".join(lines)


def issue_title(manifest: str, critical: bool) -> str:
    if critical:
        return f"🚨 Malware/tampering detected in dependencies ({manifest})"
    return f"New dependency findings from rl-protect ({manifest})"

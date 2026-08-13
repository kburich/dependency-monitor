"""Render a Delta into Markdown: job summary, issue bodies, delta comments.

Real reports are large and highly repetitive: a single Go-based npm package
ships ~20 per-platform variants that each carry the same stdlib CVEs, so 58
distinct CVEs can expand to 1200+ findings. Rows are therefore grouped by
finding (not by package), tables are capped, and issue bodies are clipped to
GitHub's hard body limit so the `gh issue create` call can never 422.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .diff import Change, Delta
from .normalize import Finding

_STATUS_EMOJI = {"warn": "⚠️", "fail": "❌"}

#: Max grouped rows per table. Issue bodies are tighter than job summaries.
MAX_ROWS_ISSUE = 40
MAX_ROWS_SUMMARY = 100

#: Packages listed inline in a grouped row before collapsing to "+N more".
MAX_PACKAGES_PER_ROW = 3

#: GitHub rejects issue bodies over 65536 characters.
GITHUB_BODY_LIMIT = 65536

_FULL_LIST_NOTE = ("_The full, ungrouped list is in the `delta.json` "
                   "workflow artifact._")


def _fmt_score(score: Optional[float]) -> str:
    # Scores arrive as float32 artifacts (5.300000190734863).
    return "—" if score is None else f"{score:.1f}"


def _packages_cell(purls: List[str]) -> str:
    shown = [f"`{p}`" for p in purls[:MAX_PACKAGES_PER_ROW]]
    extra = len(purls) - len(shown)
    if extra > 0:
        shown.append(f"+{extra} more")
    return "<br>".join(shown)


def _group_findings(findings: List[Finding]) -> List[Tuple[Finding, List[str]]]:
    """Collapse findings that are the same issue seen on several packages.

    Grouped on everything a row displays except the package, so a row never
    merges rows that would have read differently.
    """
    groups: Dict[Tuple, Tuple[Finding, List[str]]] = {}
    for f in findings:
        key = (f.category, f.finding_id, f.status, f.count, f.title)
        if key in groups:
            groups[key][1].append(f.purl)
        else:
            groups[key] = (f, [f.purl])
    return [(f, sorted(purls)) for f, purls in groups.values()]


def _group_changes(changes: List[Change]) -> List[Tuple[Change, List[str]]]:
    groups: Dict[Tuple, Tuple[Change, List[str]]] = {}
    for c in changes:
        key = (c.after.category, c.after.finding_id, c.before.status,
               c.before.count, c.after.status, c.after.count)
        if key in groups:
            groups[key][1].append(c.after.purl)
        else:
            groups[key] = (c, [c.after.purl])
    return [(c, sorted(purls)) for c, purls in groups.values()]


def _table(header: str, rows: List[str], total_groups: int, max_rows: int) -> str:
    shown = rows[:max_rows]
    out = "\n".join([header] + shown)
    hidden = total_groups - len(shown)
    if hidden > 0:
        out += (f"\n\n_… and {hidden} more finding"
                f"{'s' if hidden != 1 else ''} not shown._ {_FULL_LIST_NOTE}")
    return out


def _finding_table(findings: List[Finding], max_rows: int = MAX_ROWS_SUMMARY) -> str:
    header = (
        "| Packages | Category | Finding | Status | CVSS | Details |\n"
        "|---|---|---|---|---|---|"
    )
    groups = _group_findings(findings)
    rows = [
        f"| {_packages_cell(purls)} | {f.category} | {f.finding_id} | "
        f"{_STATUS_EMOJI.get(f.status, '')} {f.status} | {_fmt_score(f.score)} | "
        f"{f.title} |"
        for f, purls in groups
    ]
    return _table(header, rows, len(groups), max_rows)


def _change_table(changes: List[Change], max_rows: int = MAX_ROWS_SUMMARY) -> str:
    header = ("| Packages | Category | Finding | Change | Before → After |\n"
              "|---|---|---|---|---|")
    groups = _group_changes(changes)
    rows = []
    for c, purls in groups:
        what = "status escalated" if c.escalated else "count increased"
        if c.version_changed:
            what += " (version changed)"
        rows.append(
            f"| {_packages_cell(purls)} | {c.after.category} | {c.after.finding_id} | "
            f"{what} | {c.before.status}({c.before.count}) → "
            f"{c.after.status}({c.after.count}) |"
        )
    return _table(header, rows, len(groups), max_rows)


def _clip(body: str, limit: int = GITHUB_BODY_LIMIT) -> str:
    """Last-resort guard so an oversized body never fails the `gh` call."""
    if len(body) <= limit:
        return body
    notice = f"\n\n_Body truncated to fit GitHub's size limit._ {_FULL_LIST_NOTE}"
    keep = body[: limit - len(notice)]
    keep = keep[: keep.rfind("\n")] if "\n" in keep else keep
    return keep + notice


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


def _delta_headline(new_count: int, changed_count: int) -> str:
    parts = []
    if new_count:
        parts.append(f"{new_count} new")
    if changed_count:
        parts.append(f"{changed_count} worsened")
    return " · ".join(parts) or "no changes"


def render_issue_body(delta: Delta, manifest: str, critical: bool,
                      run_url: Optional[str] = None,
                      stats: Optional[Dict] = None,
                      outstanding: Optional[int] = None,
                      date: str = "") -> str:
    """Markdown body for the rolling GitHub issue (one per severity bucket).

    The body is the issue's landing page: cumulative monitoring stats and a
    pointer at the newest comment, which carries the latest delta. The delta
    itself is deliberately not repeated here — the comment is its durable,
    notifying copy.
    """
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

    if stats:
        bucket = stats.get("critical" if critical else "standard") or {}
        since = str(stats.get("since") or "")[:10]
        lines += ["### Monitoring stats", ""]
        if since:
            lines.append(f"- **Monitoring since:** {since}")
        lines += [
            f"- **Runs with alerts:** {bucket.get('runs', 0)}",
            f"- **Alerted so far:** {bucket.get('new', 0)} new · "
            f"{bucket.get('changed', 0)} worsened",
            f"- **Resolved since then:** {bucket.get('resolved', 0)}",
        ]
        if outstanding is not None:
            lines.append(f"- **Currently outstanding:** {outstanding}")
        lines.append("")

    latest = f"**Latest change{f' ({date})' if date else ''}:** " \
             f"{_delta_headline(len(new), len(changed))} — the full delta is " \
             "in the newest comment below."
    lines += [latest, ""]

    if run_url:
        lines += [f"[Workflow run]({run_url})", ""]
    footer = ("_Maintained by the rl-protect-monitor action. This issue is not "
              "duplicated: every delta — including earlier ones — is posted as "
              "a comment below, and the body above tracks the cumulative "
              "picture._")
    lines += ["---", footer]
    return _clip("\n".join(lines))


def render_issue_comment(delta: Delta, critical: bool,
                         run_url: Optional[str] = None,
                         date: str = "") -> str:
    """Markdown for the delta comment on the rolling issue.

    The headline stays visible when the comment is collapsed; the tables sit
    inside a <details> block so a long thread scans like a changelog. Most
    email clients ignore <details>, so the notification email still shows the
    full delta expanded.
    """
    if critical:
        new, changed = delta.new_critical, delta.changed_critical
        label = "🚨 Malware/tampering"
    else:
        new, changed = delta.new_standard, delta.changed_standard
        label = "New findings"

    head = f"**{label}: {_delta_headline(len(new), len(changed))}**"
    if date:
        head += f" — {date}"
    if run_url:
        head += f" · [workflow run]({run_url})"

    lines = [head, "", "<details>", "<summary>Show the full delta</summary>", ""]
    if new:
        lines += ["### New findings", "",
                  _finding_table(new, MAX_ROWS_ISSUE), ""]
    if changed:
        lines += ["### Worsened findings", "",
                  _change_table(changed, MAX_ROWS_ISSUE), ""]
    lines += ["</details>"]
    return _clip("\n".join(lines))


def issue_title(manifest: str, critical: bool) -> str:
    if critical:
        return f"🚨 Malware/tampering detected in dependencies ({manifest})"
    return f"New dependency findings from rl-protect ({manifest})"

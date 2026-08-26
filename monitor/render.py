"""Render a Delta into Markdown: the job summary and the delta comments.

Real reports are large and highly repetitive: a single Go-based npm package
ships ~20 per-platform variants that each carry the same stdlib CVEs, so 58
distinct CVEs can expand to 1200+ findings. Rows are therefore grouped by
finding (not by package), tables are capped, and comments are clipped to
GitHub's hard body limit so the `gh issue create` call can never 422.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .diff import Change, Delta
from .normalize import Finding

_STATUS_EMOJI = {"warn": "⚠️", "fail": "❌"}

#: Max grouped rows per table. Issue comments are tighter than job summaries.
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


def _cell(value) -> str:
    """Report-supplied text, made safe as a plain Markdown table cell.

    Titles and identifiers come from the vendor's finding database, so they
    can carry anything: a `|` adds phantom columns, a newline ends the row
    and with it the table, and a literal `<details>`/`</details>` opens or
    closes the HTML block the delta comment wraps its tables in.
    """
    text = " ".join(str(value).split())
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|")


def _code_cell(value) -> str:
    """Report-supplied text, made safe inside a `code span` table cell.

    A code span renders HTML literally, so entity-escaping would show the
    reader `&lt;` instead of `<`; angle brackets are substituted the way the
    backtick that would end the span early already is. GitHub does escape a
    tag inside a code span, so this is not about injection — it is that
    `_unclosed_details` counts tags on the raw string, and a purl carrying
    `</details>` makes an open block look closed. `_clip` would then leave
    the truncation notice hidden inside the collapsed block, the one failure
    it exists to prevent. The pipe is escaped because GitHub splits columns
    on it even inside code.
    """
    text = " ".join(str(value).split())
    for bad, safe in (("`", "'"), ("<", "‹"), (">", "›"), ("|", "\\|")):
        text = text.replace(bad, safe)
    return f"`{text}`"


def _packages_cell(purls: List[str]) -> str:
    shown = [_code_cell(p) for p in purls[:MAX_PACKAGES_PER_ROW]]
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


def _table(header: str, rows: List[str], total_groups: int, max_rows: int,
           total_findings: int) -> str:
    """Render the rows, then reconcile the two counts the reader can see.

    Headlines and the stats counters are package-level — one per (package,
    finding) pair, the same unit as `delta.json` and the action's count
    outputs — while a row here is one *distinct* finding across all the
    packages carrying it. On a real scan those differ by an order of
    magnitude (1218 against 58), so a table that just says "findings" leaves
    one comment stating two numbers that cannot be reconciled.
    """
    shown = rows[:max_rows]
    lead = ""
    if total_findings > total_groups:
        lead = (f"_{total_findings} findings across all affected packages, "
                f"grouped into {total_groups} distinct finding"
                f"{'s' if total_groups != 1 else ''} below._\n\n")
    out = lead + "\n".join([header] + shown)
    hidden = total_groups - len(shown)
    if hidden > 0:
        out += (f"\n\n_… and {hidden} more distinct finding"
                f"{'s' if hidden != 1 else ''} not shown._ {_FULL_LIST_NOTE}")
    return out


def _finding_table(findings: List[Finding], max_rows: int = MAX_ROWS_SUMMARY) -> str:
    header = (
        "| Packages | Category | Finding | Status | CVSS | Details |\n"
        "|---|---|---|---|---|---|"
    )
    groups = _group_findings(findings)
    rows = [
        f"| {_packages_cell(purls)} | {_cell(f.category)} | "
        f"{_cell(f.finding_id)} | "
        f"{_STATUS_EMOJI.get(f.status, '')} {_cell(f.status)} | "
        f"{_fmt_score(f.score)} | {_cell(f.title)} |"
        for f, purls in groups
    ]
    return _table(header, rows, len(groups), max_rows, len(findings))


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
            f"| {_packages_cell(purls)} | {_cell(c.after.category)} | "
            f"{_cell(c.after.finding_id)} | {what} | "
            f"{_cell(c.before.status)}({_cell(c.before.count)}) → "
            f"{_cell(c.after.status)}({_cell(c.after.count)}) |"
        )
    return _table(header, rows, len(groups), max_rows, len(changes))


def _unclosed_details(text: str) -> int:
    """How many <details> blocks `text` leaves open."""
    return max(text.count("<details>") - text.count("</details>"), 0)


def _clip(body: str, limit: int = GITHUB_BODY_LIMIT) -> str:
    """Last-resort guard so an oversized body never fails the `gh` call."""
    if len(body) <= limit:
        return body
    notice = f"\n\n_Body truncated to fit GitHub's size limit._ {_FULL_LIST_NOTE}"
    closer = "\n\n</details>"
    budget = max(limit - len(notice), 0)

    def fits(keep: str) -> bool:
        return len(keep) + len(closer) * _unclosed_details(keep) <= budget

    # Largest prefix that still leaves room to reclose the <details> blocks
    # the cut leaves open — GitHub auto-closes them at the end of the
    # comment, which would render the notice hidden inside the collapsed
    # block. Searched rather than computed from the whole body's tag count:
    # that reserve can exceed the limit outright, which makes the slice
    # index negative so it trims from the tail and returns *more* than the
    # limit this guard exists to enforce.
    lo, hi = 0, len(body)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fits(body[:mid]):
            lo = mid
        else:
            hi = mid - 1
    keep = body[:lo]

    # Prefer a clean line break, but not at the cost of the budget: cutting
    # away a trailing </details> costs a closer longer than the text removed.
    line_break = keep.rfind("\n")
    if line_break != -1 and fits(keep[:line_break]):
        keep = keep[:line_break]
    return keep + closer * _unclosed_details(keep) + notice


def render_summary(delta: Delta, manifest: str, first_run: bool = False) -> str:
    """Markdown for the GitHub Actions job summary.

    The quota warning is not rendered here: it is measured by a later step in
    action.yml, after this summary has been written, and that step appends
    its own line to $GITHUB_STEP_SUMMARY.
    """
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

    return "\n".join(lines)


def _delta_headline(new_count: int, changed_count: int,
                    resolved_count: int = 0) -> str:
    parts = []
    if new_count:
        parts.append(f"{new_count} new")
    if changed_count:
        parts.append(f"{changed_count} worsened")
    if resolved_count:
        parts.append(f"{resolved_count} resolved")
    return " · ".join(parts) or "no changes"


def render_issue_comment(delta: Delta, critical: bool,
                         manifest: str = "",
                         run_url: Optional[str] = None,
                         date: str = "") -> str:
    """Markdown for a delta comment on the rolling issue.

    Doubles as the body the issue is created with: the body is written once,
    at creation, carrying that run's delta, and is never edited afterwards —
    every later delta, resolutions included, is a comment. The thread is an
    append-only changelog whose newest entry is the newest comment.

    The headline stays visible when the comment is collapsed; the tables sit
    inside a <details> block so a long thread scans like a changelog. Most
    email clients ignore <details>, so the notification email still shows the
    full delta expanded. The manifest lives in the headline because one
    rolling issue can cover several manifests, and the alert email must name
    which one this delta is about.
    """
    new, changed = delta.alerts(critical)
    resolved = (delta.resolved_critical if critical
                else delta.resolved_standard)
    label = "Malware/tampering" if critical else "Dependency findings"
    if critical and (new or changed):
        # The siren marks an active alert; a resolution-only delta is the
        # opposite of one.
        label = f"\U0001F6A8 {label}"

    head = (f"**{label}: "
            f"{_delta_headline(len(new), len(changed), len(resolved))}**")
    if manifest:
        head += f" \u00b7 `{manifest}`"
    if date:
        head += f" \u2014 {date}"
    if run_url:
        head += f" \u00b7 [workflow run]({run_url})"

    lines = [head, ""]
    lines += ["<details>", "<summary>Show the full delta</summary>", ""]
    if new:
        lines += ["### New findings", "",
                  _finding_table(new, MAX_ROWS_ISSUE), ""]
    if changed:
        lines += ["### Worsened findings", "",
                  _change_table(changed, MAX_ROWS_ISSUE), ""]
    if resolved:
        lines += ["### Resolved findings", "",
                  _finding_table(resolved, MAX_ROWS_ISSUE), ""]
    lines += ["</details>"]
    return _clip("\n".join(lines))


def issue_title(manifest: str, critical: bool) -> str:
    if critical:
        return f"🚨 Malware/tampering detected in dependencies ({manifest})"
    return f"New dependency findings from rl-protect ({manifest})"

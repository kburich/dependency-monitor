import pytest

from monitor.diff import Change, Delta
from monitor.normalize import Finding
from monitor.render import (
    GITHUB_BODY_LIMIT,
    MAX_PACKAGES_PER_ROW,
    MAX_ROWS_ISSUE,
    render_issue_body,
    render_issue_comment,
    render_summary,
)


def cve(purl, cve_id="CVE-2025-47912", status="fail", score=7.5, title="Some CVE"):
    return Finding(purl=purl, category="vulnerabilities", finding_id=cve_id,
                   status=status, count=1, title=title, score=score)


def esbuild_fanout(cve_id="CVE-2025-47912", n=36):
    """The real-world shape: one CVE repeated across per-platform packages."""
    return [cve(f"pkg:npm/%40esbuild/plat{i}@0.21.5", cve_id) for i in range(n)]


def rows(table_md):
    return [ln for ln in table_md.splitlines()
            if ln.startswith("|") and not ln.startswith("|---")]


STATS = {
    "since": "2026-03-01T06:00:00+0000",
    "critical": {"runs": 1, "new": 1, "changed": 0, "resolved": 0},
    "standard": {"runs": 13, "new": 36, "changed": 12, "resolved": 21},
}


class TestGrouping:
    def test_same_cve_across_packages_is_one_row(self):
        comment = render_issue_comment(Delta(new=esbuild_fanout()), critical=False)
        data_rows = [r for r in rows(comment) if "CVE-2025-47912" in r]
        assert len(data_rows) == 1
        assert f"+{36 - MAX_PACKAGES_PER_ROW} more" in data_rows[0]

    def test_distinct_cves_stay_separate(self):
        delta = Delta(new=esbuild_fanout("CVE-1", 3) + esbuild_fanout("CVE-2", 3))
        comment = render_issue_comment(delta, critical=False)
        assert len([r for r in rows(comment) if "CVE-1" in r]) == 1
        assert len([r for r in rows(comment) if "CVE-2" in r]) == 1

    def test_differing_status_is_not_merged(self):
        delta = Delta(new=[cve("pkg:npm/a@1", status="fail"),
                           cve("pkg:npm/b@1", status="warn")])
        comment = render_issue_comment(delta, critical=False)
        assert len([r for r in rows(comment) if "CVE-2025-47912" in r]) == 2


class TestTruncation:
    def test_comment_caps_rows_and_says_so(self):
        delta = Delta(new=[cve(f"pkg:npm/p{i}@1", f"CVE-{i}")
                           for i in range(MAX_ROWS_ISSUE + 25)])
        comment = render_issue_comment(delta, critical=False)
        assert len([r for r in rows(comment) if r.startswith("| `pkg:")]) == MAX_ROWS_ISSUE
        assert "and 25 more findings not shown" in comment
        assert "delta.json" in comment

    def test_full_report_comment_stays_under_github_limit(self):
        # ~1200 findings, the size seen in a real pnpm workspace scan
        delta = Delta(new=[cve(f"pkg:npm/p{i}@1", f"CVE-{i}", title="x" * 168)
                           for i in range(1237)])
        comment = render_issue_comment(delta, critical=False)
        assert len(comment) < GITHUB_BODY_LIMIT

    def test_clip_is_a_backstop_for_oversized_rows(self):
        delta = Delta(new=[cve(f"pkg:npm/p{i}@1", f"CVE-{i}", title="x" * 10000)
                           for i in range(MAX_ROWS_ISSUE)])
        comment = render_issue_comment(delta, critical=False)
        assert len(comment) <= GITHUB_BODY_LIMIT
        assert "truncated to fit GitHub's size limit" in comment

    def test_no_truncation_note_when_everything_fits(self):
        comment = render_issue_comment(Delta(new=[cve("pkg:npm/a@1")]),
                                       critical=False)
        assert "not shown" not in comment
        assert "truncated" not in comment


class TestIssueBody:
    def test_body_shows_stats_instead_of_finding_tables(self):
        body = render_issue_body(Delta(new=esbuild_fanout()), "pnpm-lock.yaml",
                                 critical=False, stats=STATS, outstanding=16)
        assert "**Monitoring since:** 2026-03-01" in body
        assert "**Runs with alerts:** 13" in body
        assert "**Alerted so far:** 36 new · 12 worsened" in body
        assert "**Resolved since then:** 21" in body
        assert "**Currently outstanding:** 16" in body
        # the delta itself lives in the comment, not the body
        assert "CVE-2025-47912" not in body

    def test_body_shows_the_buckets_own_stats(self):
        body = render_issue_body(Delta(), "m", critical=True, stats=STATS)
        assert "**Runs with alerts:** 1" in body
        assert "**Alerted so far:** 1 new · 0 worsened" in body

    def test_body_points_at_the_newest_comment(self):
        body = render_issue_body(Delta(new=[cve("pkg:npm/a@1")]), "m",
                                 critical=False, stats=STATS, date="2026-08-12")
        assert "**Latest change (2026-08-12):** 1 new" in body
        assert "newest comment below" in body

    def test_footer_promises_the_comment_thread(self):
        body = render_issue_body(Delta(new=[cve("pkg:npm/a@1")]), "m",
                                 critical=False)
        assert "posted as a comment below" in body


class TestIssueComment:
    def test_headline_stays_outside_the_collapsed_block(self):
        comment = render_issue_comment(Delta(new=[cve("pkg:npm/a@1")]),
                                       critical=False, date="2026-08-12")
        head, sep, details = comment.partition("<details>")
        assert sep
        assert "**New findings: 1 new** — 2026-08-12" in head
        assert "<summary>Show the full delta</summary>" in details
        assert "CVE-2025-47912" in details
        assert details.rstrip().endswith("</details>")

    def test_critical_headline_is_loud(self):
        malware = Finding(purl="pkg:npm/ua-parser-js@0.7.29", category="malware",
                          finding_id="malware", status="fail", count=1)
        comment = render_issue_comment(Delta(new=[malware]), critical=True)
        assert comment.startswith("**🚨 Malware/tampering: 1 new**")

    def test_headline_counts_worsened_findings(self):
        before = cve("pkg:npm/a@1.0.0", status="warn")
        after = cve("pkg:npm/a@1.0.0", status="fail")
        comment = render_issue_comment(Delta(changed=[Change(before, after)]),
                                       critical=False)
        assert "1 worsened" in comment


class TestFormatting:
    @pytest.mark.parametrize("score,expected", [
        (5.300000190734863, "5.3"),
        (9.800000190734863, "9.8"),
        (6.5, "6.5"),
        (None, "—"),
    ])
    def test_scores_are_rounded_for_display(self, score, expected):
        summary = render_summary(Delta(new=[cve("pkg:npm/a@1", score=score)]), "m")
        assert f"| {expected} |" in summary

    def test_change_row_flags_version_change(self):
        before = cve("pkg:npm/a@1.0.0", status="warn")
        after = cve("pkg:npm/a@2.0.0", status="fail")
        summary = render_summary(Delta(changed=[Change(before, after)]), "m")
        assert "status escalated (version changed)" in summary


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

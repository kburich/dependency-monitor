import pytest

from monitor.diff import Change, Delta
from monitor.normalize import Finding
from monitor.render import (
    GITHUB_BODY_LIMIT,
    MAX_PACKAGES_PER_ROW,
    MAX_ROWS_ISSUE,
    render_issue_body,
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


class TestGrouping:
    def test_same_cve_across_packages_is_one_row(self):
        body = render_issue_body(Delta(new=esbuild_fanout()), "pnpm-lock.yaml",
                                 critical=False)
        data_rows = [r for r in rows(body) if "CVE-2025-47912" in r]
        assert len(data_rows) == 1
        assert f"+{36 - MAX_PACKAGES_PER_ROW} more" in data_rows[0]

    def test_distinct_cves_stay_separate(self):
        delta = Delta(new=esbuild_fanout("CVE-1", 3) + esbuild_fanout("CVE-2", 3))
        body = render_issue_body(delta, "pnpm-lock.yaml", critical=False)
        assert len([r for r in rows(body) if "CVE-1" in r]) == 1
        assert len([r for r in rows(body) if "CVE-2" in r]) == 1

    def test_differing_status_is_not_merged(self):
        delta = Delta(new=[cve("pkg:npm/a@1", status="fail"),
                           cve("pkg:npm/b@1", status="warn")])
        body = render_issue_body(delta, "m", critical=False)
        assert len([r for r in rows(body) if "CVE-2025-47912" in r]) == 2


class TestTruncation:
    def test_issue_body_caps_rows_and_says_so(self):
        delta = Delta(new=[cve(f"pkg:npm/p{i}@1", f"CVE-{i}")
                           for i in range(MAX_ROWS_ISSUE + 25)])
        body = render_issue_body(delta, "m", critical=False)
        assert len([r for r in rows(body) if r.startswith("| `pkg:")]) == MAX_ROWS_ISSUE
        assert "and 25 more findings not shown" in body
        assert "delta.json" in body

    def test_full_report_body_stays_under_github_limit(self):
        # ~1200 findings, the size seen in a real pnpm workspace scan
        delta = Delta(new=[cve(f"pkg:npm/p{i}@1", f"CVE-{i}", title="x" * 168)
                           for i in range(1237)])
        body = render_issue_body(delta, "pnpm-lock.yaml", critical=False)
        assert len(body) < GITHUB_BODY_LIMIT

    def test_clip_is_a_backstop_for_oversized_rows(self):
        delta = Delta(new=[cve(f"pkg:npm/p{i}@1", f"CVE-{i}", title="x" * 10000)
                           for i in range(MAX_ROWS_ISSUE)])
        body = render_issue_body(delta, "m", critical=False)
        assert len(body) <= GITHUB_BODY_LIMIT
        assert "truncated to fit GitHub's size limit" in body

    def test_no_truncation_note_when_everything_fits(self):
        body = render_issue_body(Delta(new=[cve("pkg:npm/a@1")]), "m", critical=False)
        assert "not shown" not in body
        assert "truncated" not in body


class TestFooter:
    def test_comment_thread_is_promised_by_default(self):
        body = render_issue_body(Delta(new=[cve("pkg:npm/a@1")]), "m", critical=False)
        assert "posted as a comment below" in body

    def test_comment_thread_is_not_promised_in_notice_mode(self):
        """A thread of one-line notices holds no history to point readers at."""
        body = render_issue_body(Delta(new=[cve("pkg:npm/a@1")]), "m",
                                 critical=False, delta_comments=False)
        assert "posted as a comment below" not in body
        assert "the body above always shows the latest delta." in body


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

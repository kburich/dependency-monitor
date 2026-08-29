import pytest

from monitor.diff import Change, Delta
from monitor.normalize import Finding
from monitor.render import (
    GITHUB_BODY_LIMIT,
    MAX_PACKAGES_PER_ROW,
    MAX_ROWS_ISSUE,
    _clip,
    _unclosed_details,
    render_issue_comment,
    render_summary,
)


def cve(purl, cve_id="CVE-2025-47912", status="fail", score=7.5, title="Some CVE"):
    return Finding(purl=purl, category="vulnerabilities", finding_id=cve_id,
                   status=status, count=1, title=title, score=score)


def malware(purl="pkg:npm/ua-parser-js@0.7.29"):
    return Finding(purl=purl, category="malware", finding_id="malware",
                   status="fail", count=1, title="Malware detected", score=None)


def esbuild_fanout(cve_id="CVE-2025-47912", n=36):
    """The real-world shape: one CVE repeated across per-platform packages."""
    return [cve(f"pkg:npm/%40esbuild/plat{i}@0.21.5", cve_id) for i in range(n)]


def rows(table_md):
    return [ln for ln in table_md.splitlines()
            if ln.startswith("|") and not ln.startswith("|---")]


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

    def test_the_headline_count_reconciles_with_the_row_count(self):
        """The headline counts findings (one per affected package) while a row
        is one distinct finding. Left unexplained, the same comment states two
        counts an order of magnitude apart, both called "findings"."""
        comment = render_issue_comment(Delta(new=esbuild_fanout(n=36)),
                                       critical=False)
        assert "**Dependency findings: 36 new**" in comment
        assert len([r for r in rows(comment) if "CVE-2025-47912" in r]) == 1
        assert ("36 findings across all affected packages, grouped into 1 "
                "distinct finding below") in comment

    def test_no_grouping_note_when_nothing_was_collapsed(self):
        delta = Delta(new=[cve("pkg:npm/a@1", "CVE-1"),
                           cve("pkg:npm/b@1", "CVE-2")])
        comment = render_issue_comment(delta, critical=False)
        assert "grouped into" not in comment


class TestTruncation:
    def test_comment_caps_rows_and_says_so(self):
        delta = Delta(new=[cve(f"pkg:npm/p{i}@1", f"CVE-{i}")
                           for i in range(MAX_ROWS_ISSUE + 25)])
        comment = render_issue_comment(delta, critical=False)
        assert len([r for r in rows(comment) if r.startswith("| `pkg:")]) == MAX_ROWS_ISSUE
        assert "and 25 more distinct findings not shown" in comment
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

    def test_clip_recloses_the_details_block_before_the_notice(self):
        """A cut inside <details> must not leave it unclosed — GitHub would
        auto-close at comment end and swallow the truncation notice into the
        collapsed section."""
        delta = Delta(new=[cve(f"pkg:npm/p{i}@1", f"CVE-{i}", title="x" * 10000)
                           for i in range(MAX_ROWS_ISSUE)])
        comment = render_issue_comment(delta, critical=False)
        assert comment.count("<details>") == comment.count("</details>")
        assert comment.rfind("</details>") < comment.rfind("truncated to fit")

    def test_clip_holds_when_the_body_is_dense_with_details_tags(self):
        """Sizing the closer reserve from the whole body's tag count can make
        it exceed the limit, turning the slice index negative — which trims
        from the tail and returns *more* than the limit."""
        body = "<details>" * 6000 + "\n" + "y" * 70000
        clipped = _clip(body)
        assert len(clipped) <= GITHUB_BODY_LIMIT
        assert clipped.count("<details>") == clipped.count("</details>")

    def test_clip_keeps_as_much_of_the_body_as_the_budget_allows(self):
        """Staying under the limit by discarding everything is not a fix."""
        body = "<details>" * 6000 + "\n" + "y" * 70000
        assert len(_clip(body)) > GITHUB_BODY_LIMIT // 2

    def test_no_truncation_note_when_everything_fits(self):
        comment = render_issue_comment(Delta(new=[cve("pkg:npm/a@1")]),
                                       critical=False)
        assert "not shown" not in comment
        assert "truncated" not in comment


class TestUntrustedFindingText:
    """Titles and ids come from the vendor's finding database, so the report
    controls them — the renderer must not let them break out of their cell."""

    def test_a_details_tag_in_a_title_cannot_close_the_collapse(self):
        delta = Delta(new=[cve("pkg:npm/b@1", title="oops </details> **x**")])
        comment = render_issue_comment(delta, critical=False)
        assert comment.count("<details>") == comment.count("</details>")
        assert "&lt;/details&gt;" in comment

    def test_a_pipe_in_a_title_does_not_add_a_column(self):
        delta = Delta(new=[cve("pkg:npm/b@1", title="bad | title")])
        row = [r for r in rows(render_issue_comment(delta, critical=False))
               if r.startswith("| `pkg:npm/b@1`")][0]
        assert row.count("|") - row.count("\\|") - 1 == 6  # the header's width

    def test_a_newline_in_a_title_does_not_end_the_table(self):
        delta = Delta(new=[cve("pkg:npm/b@1", title="first\nsecond")])
        matched = [r for r in rows(render_issue_comment(delta, critical=False))
                   if r.startswith("| `pkg:npm/b@1`")]
        assert len(matched) == 1
        assert "first second" in matched[0]

    def test_a_pipe_in_a_purl_does_not_add_a_column(self):
        """Code spans do not protect a cell: GitHub splits columns on a pipe
        even inside backticks."""
        delta = Delta(new=[cve("pkg:npm/b|evil@1")])
        row = [r for r in rows(render_issue_comment(delta, critical=False))
               if r.startswith("| `pkg:npm/b")][0]
        assert row.count("|") - row.count("\\|") - 1 == 6

    def test_a_details_tag_in_a_purl_does_not_unbalance_the_count(self):
        """`_clip` counts tags on the raw string, so a purl carrying the
        closing tag would make an open block look closed — and the
        truncation notice would land inside the collapse."""
        delta = Delta(new=[cve("pkg:npm/b</details>@1")])
        comment = render_issue_comment(delta, critical=False)
        assert comment.count("<details>") == 1
        assert comment.count("</details>") == 1
        assert _unclosed_details(comment) == 0


class TestResolutions:
    """Resolutions are deltas like any other and are posted as comments, so
    the thread stays a complete changelog. The monitor alerts — it does not
    track — so there is no outstanding count anywhere; whether an issue may
    be *opened* for a resolution-only delta is gh_issue's --no-create."""

    def test_resolved_findings_get_their_own_table(self):
        comment = render_issue_comment(Delta(resolved=[cve("pkg:npm/a@1")]),
                                       critical=False)
        assert "### Resolved findings" in comment
        assert "CVE-2025-47912" in comment

    def test_headline_counts_resolutions_beside_alerts(self):
        delta = Delta(new=[cve("pkg:npm/a@1", "CVE-1")],
                      resolved=[cve("pkg:npm/b@1", "CVE-2")])
        comment = render_issue_comment(delta, critical=False)
        assert "**Dependency findings: 1 new · 1 resolved**" in comment

    def test_resolved_rows_carry_no_status_column(self):
        """A "❌ fail" beside a finding that just went away reads as if it
        were still failing. The column goes, in the comment and the summary
        alike, and rows differing only by status collapse into one."""
        resolved = [cve("pkg:npm/a@1", status="fail"),
                    cve("pkg:npm/b@1", status="warn")]
        for md in (render_issue_comment(Delta(resolved=resolved), critical=False),
                   render_summary(Delta(resolved=resolved), "m")):
            header = [r for r in rows(md) if r.startswith("| Packages")][0]
            assert "Status" not in header
            assert "❌" not in md and "⚠️" not in md
            assert len([r for r in rows(md) if "CVE-2025-47912" in r]) == 1

    def test_new_rows_keep_the_status_column(self):
        md = render_issue_comment(Delta(new=[cve("pkg:npm/a@1")]), critical=False)
        assert "| Status |" in md
        assert "❌ fail" in md

    def test_a_resolution_only_critical_comment_is_not_loud(self):
        """The siren marks an active alert; a resolution is the opposite."""
        comment = render_issue_comment(Delta(resolved=[malware()]),
                                       critical=True)
        assert comment.startswith("**Malware/tampering: 1 resolved**")
        assert "🚨" not in comment


class TestIssueComment:
    def test_headline_stays_outside_the_collapsed_block(self):
        comment = render_issue_comment(Delta(new=[cve("pkg:npm/a@1")]),
                                       critical=False, date="2026-08-12")
        head, sep, details = comment.partition("<details>")
        assert sep
        assert "**Dependency findings: 1 new** — 2026-08-12" in head
        assert "<summary>Show the full delta</summary>" in details
        assert "CVE-2025-47912" in details
        assert details.rstrip().endswith("</details>")

    def test_critical_headline_is_loud(self):
        comment = render_issue_comment(Delta(new=[malware()]), critical=True)
        assert comment.startswith("**🚨 Malware/tampering: 1 new**")

    def test_headline_counts_worsened_findings(self):
        before = cve("pkg:npm/a@1.0.0", status="warn")
        after = cve("pkg:npm/a@1.0.0", status="fail")
        comment = render_issue_comment(Delta(changed=[Change(before, after)]),
                                       critical=False)
        assert "1 worsened" in comment

    def test_headline_names_the_manifest(self):
        """One rolling issue can cover several manifests, and the comment is
        what lands in the alert email — so the manifest lives in the
        headline, not in a body nobody is notified about."""
        comment = render_issue_comment(Delta(new=[cve("pkg:npm/a@1")]),
                                       critical=False,
                                       manifest="services/api/package-lock.json",
                                       date="2026-08-14")
        assert "`services/api/package-lock.json`" in comment.splitlines()[0]

    def test_no_editorial_guidance_is_added(self):
        """The 🚨 title and headline carry the urgency; the comment body is
        the delta and nothing else."""
        comment = render_issue_comment(Delta(new=[malware()]), critical=True)
        assert "incident" not in comment
        assert "already be installed" not in comment


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

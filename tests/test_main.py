import json
from pathlib import Path

import pytest

from monitor.main import _durable, load_baseline, run, write_baseline
from monitor.normalize import Finding

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def env(tmp_path, monkeypatch):
    gh_out = tmp_path / "gh_output.txt"
    gh_out.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_out))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    return tmp_path, gh_out


def outputs(gh_out):
    return dict(line.split("=", 1) for line in gh_out.read_text().splitlines())


def invoke(tmp_path, report, extra=(), out_dir="out"):
    # out_dir is per-run where a test asserts on a file's *absence*: the
    # action gets a fresh RUNNER_TEMP each run, so a shared directory here
    # would let an earlier run's file masquerade as this run's output.
    return run([
        "--report", str(FIXTURES / report),
        "--baseline", str(tmp_path / ".rl-protect" / "baseline.json"),
        "--manifest", "package-lock.json",
        "--out-dir", str(tmp_path / out_dir),
        *extra,
    ])


def test_first_run_creates_baseline_without_alert(env, capsys):
    tmp_path, gh_out = env
    assert invoke(tmp_path, "report_baseline.json") == 0
    out = outputs(gh_out)
    assert out["first-run"] == "true"
    assert out["has-alerts"] == "false"
    baseline = json.loads((tmp_path / ".rl-protect" / "baseline.json").read_text())
    assert len(baseline["findings"]) == 2
    assert baseline["manifest"] == "package-lock.json"
    assert "First run" in capsys.readouterr().out


def test_second_run_detects_new_malware(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json")
    gh_out.write_text("")  # reset outputs between runs
    invoke(tmp_path, "report_new_malware.json")
    out = outputs(gh_out)
    assert out["first-run"] == "false"
    assert out["has-critical-alerts"] == "true"
    assert out["new-critical-count"] == "1"
    # the delta lives in the comment; the body is the stats landing page
    comment = Path(out["issue-critical-comment"]).read_text()
    assert "ua-parser-js" in comment
    assert "malware" in comment
    assert "<details>" in comment
    critical_body = Path(out["issue-critical-body"]).read_text()
    assert "ua-parser-js" not in critical_body
    assert "newest comment below" in critical_body
    assert "**Runs with alerts:** 1" in critical_body
    title = (tmp_path / "out" / "issue_critical.title").read_text()
    assert title.startswith("🚨")
    # baseline updated to include the malware finding
    baseline = json.loads((tmp_path / ".rl-protect" / "baseline.json").read_text())
    assert any(f["category"] == "malware" for f in baseline["findings"])


def test_no_change_produces_no_issue_bodies(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json")
    gh_out.write_text("")
    invoke(tmp_path, "report_baseline.json")
    out = outputs(gh_out)
    assert out["has-alerts"] == "false"
    assert out["issue-critical-body"] == ""
    assert out["issue-standard-body"] == ""
    assert out["issue-critical-comment"] == ""
    assert out["issue-standard-comment"] == ""


def test_new_cve_goes_to_standard_issue(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json")
    gh_out.write_text("")
    invoke(tmp_path, "report_new_cve.json")
    out = outputs(gh_out)
    assert out["has-alerts"] == "true"
    assert out["has-critical-alerts"] == "false"
    assert out["issue-critical-body"] == ""
    assert out["issue-critical-comment"] == ""
    assert "CVE-2022-25927" in Path(out["issue-standard-comment"]).read_text()
    assert "CVE-2022-25927" not in Path(out["issue-standard-body"]).read_text()


def test_resolved_only_is_not_alert(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json")
    gh_out.write_text("")
    invoke(tmp_path, "report_resolved.json")
    out = outputs(gh_out)
    assert out["has-alerts"] == "false"
    assert out["resolved-count"] == "1"


def test_baseline_not_rewritten_when_findings_unchanged(env):
    tmp_path, _ = env
    baseline = tmp_path / ".rl-protect" / "baseline.json"
    invoke(tmp_path, "report_baseline.json")
    before = baseline.read_text()
    invoke(tmp_path, "report_baseline.json")
    # the `generated` stamp must not churn the file, or every scheduled scan
    # commits and pushes an otherwise unchanged baseline
    assert baseline.read_text() == before


def test_baseline_order_is_independent_of_report_order(env):
    tmp_path, _ = env
    baseline = tmp_path / ".rl-protect" / "baseline.json"
    invoke(tmp_path, "report_baseline.json")
    before = baseline.read_text()

    shuffled = json.loads((FIXTURES / "report_baseline.json").read_text())
    shuffled["analysis"]["report"]["packages"].reverse()
    shuffled_path = tmp_path / "shuffled.json"
    shuffled_path.write_text(json.dumps(shuffled))
    run([
        "--report", str(shuffled_path),
        "--baseline", str(baseline),
        "--manifest", "package-lock.json",
        "--out-dir", str(tmp_path / "out"),
    ])
    assert baseline.read_text() == before


def test_baseline_rewritten_when_findings_change(env):
    tmp_path, _ = env
    baseline = tmp_path / ".rl-protect" / "baseline.json"
    invoke(tmp_path, "report_baseline.json")
    before = baseline.read_text()
    invoke(tmp_path, "report_new_cve.json")
    assert baseline.read_text() != before


def test_alert_on_first_run_flag(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_new_malware.json", extra=["--alert-on-first-run"])
    out = outputs(gh_out)
    assert out["first-run"] == "true"
    assert out["has-critical-alerts"] == "true"


def baseline_payload(tmp_path):
    return json.loads((tmp_path / ".rl-protect" / "baseline.json").read_text())


def baseline_stats(tmp_path):
    return baseline_payload(tmp_path)["stats"]


def alerted_keys(tmp_path):
    """Finding keys of the records flagged as alerted. Keys are
    version-independent, so they are derived rather than read off `purl`."""
    return sorted({Finding.from_dict(r).key
                   for r in baseline_payload(tmp_path)["findings"]
                   if r.get("alerted")})


def test_first_run_absorbs_backlog_without_counting_it(env):
    """Stats count alerts since monitoring started, not the standing backlog."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json")
    stats = baseline_stats(tmp_path)
    assert stats["standard"] == {"runs": 0, "new": 0, "changed": 0,
                                 "resolved": 0}
    assert stats["since"]


def test_stats_accumulate_across_runs(env):
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json")
    since = baseline_stats(tmp_path)["since"]

    invoke(tmp_path, "report_new_malware.json")
    stats = baseline_stats(tmp_path)
    assert stats["critical"]["new"] == 1
    assert stats["critical"]["runs"] == 1

    # malware gone again, a CVE appears: resolved and new both accumulate
    invoke(tmp_path, "report_new_cve.json")
    stats = baseline_stats(tmp_path)
    assert stats["critical"] == {"runs": 1, "new": 1, "changed": 0,
                                 "resolved": 1}
    assert alerted_keys(tmp_path) == [NEW_CVE]  # malware resolved, unflagged
    assert stats["standard"]["new"] == 1
    assert stats["standard"]["runs"] == 1
    assert stats["since"] == since


def test_corrupt_stats_values_heal_instead_of_crashing(env):
    """A hand-edited or merge-mangled counter heals to 0 like every other
    malformed-stats shape, instead of taking down the alerting run."""
    tmp_path, _ = env
    baseline = tmp_path / ".rl-protect" / "baseline.json"
    invoke(tmp_path, "report_baseline.json")
    data = json.loads(baseline.read_text())
    data["stats"]["standard"] = {"runs": "1.5", "new": [2], "changed": None,
                                 "alerted": "oops"}
    baseline.write_text(json.dumps(data))

    assert invoke(tmp_path, "report_new_cve.json") == 0
    stats = baseline_stats(tmp_path)
    assert stats["standard"]["runs"] == 1  # healed to 0 + this run's alert
    assert stats["standard"]["new"] == 1


def test_outstanding_counts_only_what_was_alerted_on(env):
    """The default first run absorbs a 2-finding backlog silently. Counting
    every current finding as outstanding puts that number on a different
    basis from the three counters beside it, so the body reads "Alerted so
    far: 1 new … Currently outstanding: 3" and a reader concludes two
    findings appeared without ever alerting."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json", out_dir="out1")
    invoke(tmp_path, "report_new_cve.json", out_dir="out2")

    body = (tmp_path / "out2" / "issue_standard.md").read_text()
    assert "**Alerted so far:** 1 new · 0 worsened" in body
    assert "**Resolved since then:** 0" in body
    assert "**Currently outstanding:** 1" in body
    # …and the backlog is still visible, just not folded into the above
    assert "**Pre-existing backlog:** 2" in body


def test_alert_on_first_run_has_no_backlog(env):
    """With --alert-on-first-run the backlog *was* alerted on, so it counts
    as outstanding and there is nothing left over."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json", extra=["--alert-on-first-run"],
           out_dir="out1")
    body = (tmp_path / "out1" / "issue_standard.md").read_text()
    assert "**Currently outstanding:** 2" in body
    assert "Pre-existing backlog" not in body


def test_a_resolution_only_run_refreshes_the_body_without_a_comment(env):
    """The counters move on a resolution, so a body that is not re-rendered
    keeps asserting the pre-resolution numbers for as long as the issue
    stays open — under a footer promising it tracks the cumulative picture.
    No comment, though: a body edit does not notify, and it shouldn't."""
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json", out_dir="out1")
    invoke(tmp_path, "report_new_malware.json", out_dir="out2")
    gh_out.write_text("")  # reset outputs between runs
    invoke(tmp_path, "report_baseline.json", out_dir="out3")
    out_dir = tmp_path / "out3"

    body = (out_dir / "issue_critical.md").read_text()
    assert "**Resolved since then:** 1" in body
    assert "**Currently outstanding:** 0" in body
    assert "1 resolved" in body
    assert not (out_dir / "issue_critical_comment.md").exists()

    out = outputs(gh_out)
    assert out["has-alerts"] == "false"     # nothing to page anyone about
    assert out["has-updates"] == "true"     # but the stats body is stale
    assert out["issue-critical-comment"] == ""


def test_a_quiet_run_renders_no_issue_files_at_all(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json", out_dir="out1")
    gh_out.write_text("")
    invoke(tmp_path, "report_baseline.json", out_dir="out2")
    out_dir = tmp_path / "out2"
    assert not (out_dir / "issue_critical.md").exists()
    assert not (out_dir / "issue_standard.md").exists()
    assert outputs(gh_out)["has-updates"] == "false"


def test_an_infinite_counter_heals_instead_of_crashing(env):
    """`json.load` accepts the non-standard `Infinity` literal, and int() on
    the resulting float raises OverflowError rather than ValueError — so it
    slipped past the healing that every other corrupt counter goes through."""
    tmp_path, _ = env
    baseline = tmp_path / ".rl-protect" / "baseline.json"
    invoke(tmp_path, "report_baseline.json")
    data = json.loads(baseline.read_text())
    data["stats"]["standard"]["runs"] = float("inf")
    baseline.write_text(json.dumps(data))  # emits a bare `Infinity`

    assert invoke(tmp_path, "report_new_cve.json") == 0
    assert baseline_stats(tmp_path)["standard"]["runs"] == 1  # 0 + this run


class TestRewriteContract:
    """Only a durable change justifies rewriting the baseline — the workflow
    commits and pushes it, so a field that moves on quiet runs re-commits a
    multi-hundred-KB file after every scheduled scan."""

    def seed(self, tmp_path):
        path = tmp_path / "baseline.json"
        stats = {"since": "2026-01-01", "critical": {}, "standard": {}}
        write_baseline(path, [], "m", {"tool": "1.0"}, stats, set())
        return path, stats, load_baseline(path)

    def test_a_field_added_later_participates_without_being_named(self):
        """The whole point of comparing by exclusion. Listing the fields that
        count works today and silently stops working the moment someone adds
        one — which is how the counters and the alerted keys ended up in two
        homes, split on churn rather than on meaning."""
        payload = {"schema": 2, "generated": "t", "manifest": "m", "scan": {},
                   "stats": {}, "findings": [], "added_later": 1}
        assert _durable(payload) == {"schema": 2, "manifest": "m", "stats": {},
                                     "findings": [], "added_later": 1}

    def test_volatile_fields_alone_do_not_rewrite(self, tmp_path):
        """`generated` and `scan` move every run by construction."""
        path, stats, previous = self.seed(tmp_path)
        assert write_baseline(path, [], "m", {"tool": "2.0"}, stats, set(),
                              previous=previous) is False

    def test_a_field_that_moves_on_quiet_runs_is_reported(self, tmp_path,
                                                           capsys):
        """The regression this guard exists to catch: a counter added later
        that advances whether or not any finding changed."""
        path, stats, previous = self.seed(tmp_path)
        churning = dict(stats, quiet_runs=1)
        assert write_baseline(path, [], "m", {"tool": "1.0"}, churning, set(),
                              previous=previous) is True
        assert "moves on quiet runs" in capsys.readouterr().err

    def test_a_findings_change_rewrites_without_complaint(self, tmp_path):
        path, stats, previous = self.seed(tmp_path)
        finding = Finding(purl="pkg:npm/a@1", category="vulnerabilities",
                          finding_id="CVE-1", status="fail", count=1,
                          title="t", score=None)
        assert write_baseline(path, [finding], "m", {"tool": "1.0"}, stats,
                              set(), previous=previous) is True


LODASH = ("pkg:npm/lodash", "hardening", "hardening")
NEW_CVE = ("pkg:npm/ua-parser-js", "vulnerabilities", "CVE-2022-25927")


def write_schema_1_baseline(tmp_path, alerted_entries):
    """Rewrite the baseline in the pre-2 shape: a parallel list of alerted
    keys beside the counters, and no per-record flags."""
    path = tmp_path / ".rl-protect" / "baseline.json"
    data = json.loads(path.read_text())
    data["schema"] = 1
    for record in data["findings"]:
        record.pop("alerted", None)
    data["stats"]["standard"]["alerted"] = alerted_entries
    path.write_text(json.dumps(data))


def test_a_schema_1_baseline_keeps_what_had_already_alerted(env):
    """Losing the alerted set on upgrade would zero "outstanding" and stop
    counting resolutions for every finding reported before it."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json", extra=["--alert-on-first-run"],
           out_dir="out1")
    write_schema_1_baseline(tmp_path, [list(LODASH)])

    assert invoke(tmp_path, "report_new_cve.json", out_dir="out2") == 0
    assert baseline_payload(tmp_path)["schema"] == 2
    assert LODASH in alerted_keys(tmp_path)
    body = (tmp_path / "out2" / "issue_standard.md").read_text()
    assert "**Currently outstanding:** 2" in body  # carried-over + the new CVE


def test_malformed_alerted_entries_are_dropped_instead_of_crashing(env):
    """Every entry here is a list, so a shape check that stops there passes
    them through — where an unhashable or unsortable one raises and kills the
    run before any output is written, dropping a live alert."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json", extra=["--alert-on-first-run"],
           out_dir="out1")
    write_schema_1_baseline(tmp_path, [
        list(LODASH),
        [1, 2, 3],          # ints: unsortable against the string keys
        [["x"], "b", "c"],  # nested list: unhashable as a set element
        ["too", "short"],   # wrong arity: could never match, never pruned
    ])

    assert invoke(tmp_path, "report_new_cve.json", out_dir="out2") == 0
    # the valid legacy key survived; the new CVE alerted this run
    assert alerted_keys(tmp_path) == sorted([LODASH, NEW_CVE])


def test_backlog_resolution_is_not_counted_as_resolved(env):
    """A fixed backlog finding never alerted — its resolution must not
    inflate "Resolved since then" past what was ever alerted."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json")
    invoke(tmp_path, "report_resolved.json")
    assert baseline_stats(tmp_path)["standard"]["resolved"] == 0


def test_pre_stats_baseline_adopts_stats_once(env):
    """A 1.x baseline without stats gets exactly one adoption rewrite."""
    tmp_path, _ = env
    baseline = tmp_path / ".rl-protect" / "baseline.json"
    invoke(tmp_path, "report_baseline.json")
    data = json.loads(baseline.read_text())
    del data["stats"]
    baseline.write_text(json.dumps(data))

    invoke(tmp_path, "report_baseline.json")
    assert "stats" in json.loads(baseline.read_text())
    before = baseline.read_text()
    invoke(tmp_path, "report_baseline.json")
    assert baseline.read_text() == before


def test_stats_initialized_note_appears_only_on_adoption(env, capsys):
    """This note repeating on every run is the visible symptom of a
    never-persisted baseline (commit-baseline: false without a custom
    persist step): the "cumulative" stats are resetting each time."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json")
    assert "Cumulative stats initialized" in capsys.readouterr().err
    invoke(tmp_path, "report_new_malware.json")
    assert "Cumulative stats initialized" not in capsys.readouterr().err

import json
from pathlib import Path

import pytest

from monitor.main import run

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


def invoke(tmp_path, report, extra=()):
    return run([
        "--report", str(FIXTURES / report),
        "--baseline", str(tmp_path / ".rl-protect" / "baseline.json"),
        "--manifest", "package-lock.json",
        "--out-dir", str(tmp_path / "out"),
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


def baseline_stats(tmp_path):
    return json.loads(
        (tmp_path / ".rl-protect" / "baseline.json").read_text())["stats"]


def test_first_run_absorbs_backlog_without_counting_it(env):
    """Stats count alerts since monitoring started, not the standing backlog."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json")
    stats = baseline_stats(tmp_path)
    assert stats["standard"] == {"runs": 0, "new": 0, "changed": 0,
                                 "resolved": 0, "alerted": []}
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
                                 "resolved": 1, "alerted": []}
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

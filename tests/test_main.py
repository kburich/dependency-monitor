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
    critical_body = Path(out["issue-critical-body"]).read_text()
    assert "ua-parser-js" in critical_body
    assert "malware" in critical_body
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


def test_new_cve_goes_to_standard_issue(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json")
    gh_out.write_text("")
    invoke(tmp_path, "report_new_cve.json")
    out = outputs(gh_out)
    assert out["has-alerts"] == "true"
    assert out["has-critical-alerts"] == "false"
    assert out["issue-critical-body"] == ""
    assert "CVE-2022-25927" in Path(out["issue-standard-body"]).read_text()


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

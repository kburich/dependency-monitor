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


def baseline_payload(tmp_path):
    return json.loads((tmp_path / ".rl-protect" / "baseline.json").read_text())


def test_first_run_creates_baseline_without_alert(env, capsys):
    tmp_path, gh_out = env
    assert invoke(tmp_path, "report_baseline.json") == 0
    out = outputs(gh_out)
    assert out["first-run"] == "true"
    assert out["has-alerts"] == "false"
    baseline = baseline_payload(tmp_path)
    assert len(baseline["findings"]) == 2
    assert baseline["manifest"] == "package-lock.json"
    assert "stats" not in baseline
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
    assert out["issue-critical-alerts"] == "true"
    comment = Path(out["issue-critical-comment"]).read_text()
    assert "ua-parser-js" in comment
    assert "malware" in comment
    assert "<details>" in comment
    title = (tmp_path / "out" / "issue_critical.title").read_text()
    assert title.startswith("🚨")
    # no stats body exists any more: the comment doubles as the creation body
    assert not (tmp_path / "out" / "issue_critical.md").exists()
    # baseline updated to include the malware finding
    baseline = baseline_payload(tmp_path)
    assert any(f["category"] == "malware" for f in baseline["findings"])


def test_no_change_produces_no_issue_files(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json")
    gh_out.write_text("")
    invoke(tmp_path, "report_baseline.json")
    out = outputs(gh_out)
    assert out["has-alerts"] == "false"
    assert out["has-updates"] == "false"
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
    assert out["issue-critical-comment"] == ""
    assert out["issue-standard-alerts"] == "true"
    assert "CVE-2022-25927" in Path(out["issue-standard-comment"]).read_text()


def test_resolved_only_is_not_alert(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json")
    gh_out.write_text("")
    invoke(tmp_path, "report_resolved.json")
    out = outputs(gh_out)
    assert out["has-alerts"] == "false"
    assert out["resolved-count"] == "1"


def test_a_resolution_only_run_posts_a_resolution_comment(env):
    """A resolution is a delta like any other and is reported as a comment —
    the thread stays a complete changelog and subscribers hear the
    stand-down. The alerts flag stays false, which is what keeps the notify
    step from ever *opening* an issue for it (--no-create)."""
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json", out_dir="out1")
    invoke(tmp_path, "report_new_malware.json", out_dir="out2")
    gh_out.write_text("")  # reset outputs between runs
    invoke(tmp_path, "report_baseline.json", out_dir="out3")
    out = outputs(gh_out)

    assert out["has-alerts"] == "false"     # nothing to page anyone about
    assert out["has-updates"] == "true"     # but the resolution is reported
    assert out["issue-critical-alerts"] == "false"
    comment = Path(out["issue-critical-comment"]).read_text()
    assert comment.startswith("**Malware/tampering: 1 resolved**")
    assert "### Resolved findings" in comment
    assert "ua-parser-js" in comment
    assert "🚨" not in comment


def test_a_mixed_delta_reports_alerts_and_resolutions_in_one_comment(env):
    """New CVE appears while the malware clears: one comment carries both,
    and the bucket flags still differ — the standard bucket alerts, the
    critical one only resolves."""
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json", out_dir="out1")
    invoke(tmp_path, "report_new_malware.json", out_dir="out2")
    gh_out.write_text("")
    invoke(tmp_path, "report_new_cve.json", out_dir="out3")
    out = outputs(gh_out)

    assert out["issue-critical-alerts"] == "false"
    assert out["issue-standard-alerts"] == "true"
    critical = Path(out["issue-critical-comment"]).read_text()
    assert "1 resolved" in critical
    standard = Path(out["issue-standard-comment"]).read_text()
    assert "CVE-2022-25927" in standard


def test_a_quiet_run_renders_no_issue_files_at_all(env):
    tmp_path, gh_out = env
    invoke(tmp_path, "report_baseline.json", out_dir="out1")
    gh_out.write_text("")
    invoke(tmp_path, "report_baseline.json", out_dir="out2")
    out_dir = tmp_path / "out2"
    assert not (out_dir / "issue_critical_comment.md").exists()
    assert not (out_dir / "issue_standard_comment.md").exists()
    assert outputs(gh_out)["has-updates"] == "false"


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


class TestRewriteContract:
    """Only a durable change justifies rewriting the baseline — the workflow
    commits and pushes it, so a field that moves on quiet runs re-commits a
    multi-hundred-KB file after every scheduled scan."""

    def seed(self, tmp_path):
        path = tmp_path / "baseline.json"
        write_baseline(path, [], "m", {"tool": "1.0"})
        return path

    def test_a_field_added_later_participates_without_being_named(self):
        """The whole point of comparing by exclusion. Listing the fields that
        count works today and silently stops working the moment someone adds
        one."""
        payload = {"schema": 3, "generated": "t", "manifest": "m", "scan": {},
                   "findings": [], "added_later": 1}
        assert _durable(payload) == {"schema": 3, "manifest": "m",
                                     "findings": [], "added_later": 1}

    def test_volatile_fields_alone_do_not_rewrite(self, tmp_path):
        """`generated` and `scan` move every run by construction."""
        path = self.seed(tmp_path)
        previous = load_baseline(path)
        assert write_baseline(path, [], "m", {"tool": "2.0"},
                              previous=previous) is False

    def test_a_field_that_moves_on_quiet_runs_is_reported(self, tmp_path,
                                                          capsys):
        """The regression this guard exists to catch: a durable field that
        differs between runs whether or not any finding changed."""
        path = self.seed(tmp_path)
        data = json.loads(path.read_text())
        data["stray"] = 1
        path.write_text(json.dumps(data))
        previous = load_baseline(path)
        assert write_baseline(path, [], "m", {"tool": "1.0"},
                              previous=previous) is True
        assert "moves on quiet runs" in capsys.readouterr().err

    def test_a_findings_change_rewrites_without_complaint(self, tmp_path,
                                                          capsys):
        path = self.seed(tmp_path)
        previous = load_baseline(path)
        finding = Finding(purl="pkg:npm/a@1", category="vulnerabilities",
                          finding_id="CVE-1", status="fail", count=1,
                          title="t", score=None)
        assert write_baseline(path, [finding], "m", {"tool": "1.0"},
                              previous=previous) is True
        assert "moves on quiet runs" not in capsys.readouterr().err


LODASH = ("pkg:npm/lodash", "hardening", "hardening")
NEW_CVE = ("pkg:npm/ua-parser-js", "vulnerabilities", "CVE-2022-25927")
OLD_CVE = ("pkg:npm/ua-parser-js", "vulnerabilities", "CVE-2021-27292")


def baseline_keys(tmp_path):
    return sorted({Finding.from_dict(r).key
                   for r in baseline_payload(tmp_path)["findings"]})


def test_a_pre_3_baseline_sheds_its_stats_in_one_rewrite(env, capsys):
    """Schema 3 dropped the cumulative stats block and the per-record
    `alerted` flags; nothing consumes them any more. An older baseline is
    read as-is — only its findings matter — and migrates in exactly one
    rewrite, without tripping the quiet-run churn guard."""
    tmp_path, _ = env
    baseline = tmp_path / ".rl-protect" / "baseline.json"
    invoke(tmp_path, "report_baseline.json")
    data = json.loads(baseline.read_text())
    data["schema"] = 2
    data["stats"] = {"since": "2026-01-01",
                     "critical": {"runs": 1, "new": 1, "changed": 0,
                                  "resolved": 0},
                     "standard": {"runs": 3, "new": 4, "changed": 0,
                                  "resolved": 2}}
    for record in data["findings"]:
        record["alerted"] = True
    baseline.write_text(json.dumps(data))
    capsys.readouterr()

    invoke(tmp_path, "report_baseline.json")
    data = baseline_payload(tmp_path)
    assert data["schema"] == 3
    assert "stats" not in data
    assert all("alerted" not in r for r in data["findings"])
    assert "moves on quiet runs" not in capsys.readouterr().err

    # exactly one migration rewrite: the next quiet run leaves it untouched
    before = baseline.read_text()
    invoke(tmp_path, "report_baseline.json")
    assert baseline.read_text() == before


def test_migration_alone_does_not_alert(env):
    """Shedding the stats must not look like a finding delta."""
    tmp_path, gh_out = env
    baseline = tmp_path / ".rl-protect" / "baseline.json"
    invoke(tmp_path, "report_baseline.json")
    data = json.loads(baseline.read_text())
    data["schema"] = 2
    data["stats"] = {"since": "2026-01-01"}
    baseline.write_text(json.dumps(data))
    gh_out.write_text("")

    invoke(tmp_path, "report_baseline.json")
    assert outputs(gh_out)["has-updates"] == "false"


def test_malformed_finding_records_are_dropped_instead_of_crashing(env, capsys):
    """A record missing a key field, or holding a non-string one, used to
    raise straight out of load_baseline — killing the run before any output
    was written, on a file the monitor writes itself and a human may edit."""
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json", out_dir="out1")
    path = tmp_path / ".rl-protect" / "baseline.json"
    data = json.loads(path.read_text())
    data["findings"] += [
        {"category": "hardening", "id": "hardening"},        # no purl
        {"purl": 42, "category": "hardening", "id": "x"},    # purl not a str
        {"purl": "pkg:npm/a@1", "category": "hardening"},    # no id
        "not a record",                                      # not even a dict
    ]
    path.write_text(json.dumps(data))

    assert invoke(tmp_path, "report_new_cve.json", out_dir="out2") == 0
    assert "Dropped 4 unreadable finding record(s)" in capsys.readouterr().err
    # The intact records survive and the new CVE joins them.
    assert baseline_keys(tmp_path) == sorted([LODASH, OLD_CVE, NEW_CVE])


def test_a_baseline_that_is_not_an_object_is_treated_as_empty(env):
    tmp_path, _ = env
    invoke(tmp_path, "report_baseline.json", out_dir="out1")
    path = tmp_path / ".rl-protect" / "baseline.json"
    path.write_text(json.dumps(["not", "an", "object"]))

    assert invoke(tmp_path, "report_baseline.json", out_dir="out2") == 0
    assert baseline_payload(tmp_path)["schema"] == 3

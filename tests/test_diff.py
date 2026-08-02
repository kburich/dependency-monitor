import json
from copy import deepcopy
from pathlib import Path

import pytest

from monitor.diff import diff
from monitor.normalize import Finding, normalize, scan_metadata, split_purl

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    with open(FIXTURES / name) as fh:
        return json.load(fh)


def findings(name):
    return normalize(load(name))


class TestNormalize:
    def test_clean_report_has_no_findings(self):
        assert findings("report_clean.json") == []

    def test_baseline_report_findings(self):
        result = findings("report_baseline.json")
        keys = {f.key for f in result}
        assert keys == {
            ("pkg:npm/lodash", "hardening", "hardening"),
            ("pkg:npm/ua-parser-js", "vulnerabilities", "CVE-2021-27292"),
        }
        assert {f.purl for f in result} == {
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/ua-parser-js@0.7.28",
        }

    def test_warning_status_normalized_to_warn(self):
        result = findings("report_baseline.json")
        hardening = next(f for f in result if f.category == "hardening")
        assert hardening.status == "warn"
        assert hardening.count == 2

    def test_cve_finding_carries_score_and_title(self):
        result = findings("report_baseline.json")
        cve = next(f for f in result if f.finding_id == "CVE-2021-27292")
        assert cve.score == 7.5
        assert "ReDoS" in cve.title
        assert cve.severity == "standard"

    def test_malware_finding_is_critical(self):
        result = findings("report_new_malware.json")
        malware = next(f for f in result if f.category == "malware")
        assert malware.severity == "critical"
        assert malware.status == "fail"

    def test_empty_report_tolerated(self):
        assert normalize({}) == []
        assert normalize({"analysis": {"report": {}}}) == []

    def test_roundtrip_serialization(self):
        for f in findings("report_new_malware.json"):
            assert Finding.from_dict(f.to_dict()) == f

    def test_scan_metadata(self):
        meta = scan_metadata(load("report_baseline.json"))
        assert meta["catalogue"] == "2026-07-31"
        assert meta["profile"] == "baseline"


class TestSplitPurl:
    @pytest.mark.parametrize("purl,base,version", [
        ("pkg:npm/lodash@4.17.21", "pkg:npm/lodash", "4.17.21"),
        # scoped npm names are percent-encoded, so "%40" is not a separator
        ("pkg:npm/%40esbuild/linux-x64@0.21.5", "pkg:npm/%40esbuild/linux-x64", "0.21.5"),
        ("pkg:pypi/requests@2.31.0", "pkg:pypi/requests", "2.31.0"),
        ("pkg:npm/lodash", "pkg:npm/lodash", ""),
        ("pkg:npm/foo@1.0.0?arch=x64", "pkg:npm/foo?arch=x64", "1.0.0"),
        ("pkg:golang/github.com/x/y@v1.2.3", "pkg:golang/github.com/x/y", "v1.2.3"),
    ])
    def test_split(self, purl, base, version):
        assert split_purl(purl) == (base, version)

    def test_finding_exposes_base_and_version(self):
        f = Finding(purl="pkg:npm/lodash@4.17.21", category="hardening",
                    finding_id="hardening", status="warn")
        assert f.base_purl == "pkg:npm/lodash"
        assert f.version == "4.17.21"


class TestDiff:
    def test_identical_reports_empty_delta(self):
        delta = diff(findings("report_baseline.json"), findings("report_baseline.json"))
        assert delta.is_empty
        assert not delta.has_alerts

    def test_new_cve_detected(self):
        delta = diff(findings("report_baseline.json"), findings("report_new_cve.json"))
        assert [f.finding_id for f in delta.new] == ["CVE-2022-25927"]
        assert delta.new[0].severity == "standard"
        assert delta.resolved == []
        assert not delta.has_critical_alerts

    def test_new_malware_is_critical_alert(self):
        delta = diff(findings("report_baseline.json"), findings("report_new_malware.json"))
        assert len(delta.new) == 1
        assert delta.new[0].category == "malware"
        assert delta.has_critical_alerts
        assert delta.to_dict()["counts"]["new_critical"] == 1

    def test_resolved_finding_detected(self):
        delta = diff(findings("report_baseline.json"), findings("report_resolved.json"))
        assert delta.new == []
        assert [f.key for f in delta.resolved] == [
            ("pkg:npm/lodash", "hardening", "hardening")
        ]
        assert not delta.has_alerts  # resolved alone should not alert

    def test_count_increase_is_changed(self):
        report = load("report_baseline.json")
        bumped = deepcopy(report)
        pkg = next(p for p in bumped["analysis"]["report"]["packages"]
                   if p["purl"] == "pkg:npm/lodash@4.17.21")
        pkg["analysis"]["assessment"]["hardening"]["count"] = 4
        delta = diff(normalize(report), normalize(bumped))
        assert delta.new == []
        assert len(delta.changed) == 1
        assert delta.changed[0].after.count == 4
        assert not delta.changed[0].escalated
        assert delta.has_alerts

    def test_status_escalation_is_changed(self):
        report = load("report_baseline.json")
        escalated = deepcopy(report)
        pkg = next(p for p in escalated["analysis"]["report"]["packages"]
                   if p["purl"] == "pkg:npm/lodash@4.17.21")
        pkg["analysis"]["assessment"]["hardening"]["status"] = "fail"
        delta = diff(normalize(report), normalize(escalated))
        assert len(delta.changed) == 1
        assert delta.changed[0].escalated

    def test_count_decrease_is_not_alert(self):
        report = load("report_baseline.json")
        lowered = deepcopy(report)
        pkg = next(p for p in lowered["analysis"]["report"]["packages"]
                   if p["purl"] == "pkg:npm/lodash@4.17.21")
        pkg["analysis"]["assessment"]["hardening"]["count"] = 1
        delta = diff(normalize(report), normalize(lowered))
        assert delta.is_empty

    def test_empty_baseline_everything_new(self):
        delta = diff([], findings("report_baseline.json"))
        assert len(delta.new) == 2
        assert delta.resolved == []

    def test_version_bump_alone_is_not_an_alert(self):
        report = load("report_baseline.json")
        bumped = deepcopy(report)
        for pkg in bumped["analysis"]["report"]["packages"]:
            pkg["purl"] = pkg["purl"].replace("@4.17.21", "@4.17.22") \
                                     .replace("@0.7.28", "@0.7.29")
        delta = diff(normalize(report), normalize(bumped))
        assert delta.is_empty, "an upgrade that carries findings forward must be silent"

    def test_version_bump_with_escalation_is_annotated(self):
        report = load("report_baseline.json")
        bumped = deepcopy(report)
        pkg = next(p for p in bumped["analysis"]["report"]["packages"]
                   if p["purl"] == "pkg:npm/lodash@4.17.21")
        pkg["purl"] = "pkg:npm/lodash@4.17.22"
        pkg["analysis"]["assessment"]["hardening"]["status"] = "fail"
        delta = diff(normalize(report), normalize(bumped))
        assert len(delta.changed) == 1
        assert delta.changed[0].escalated
        assert delta.changed[0].version_changed
        assert delta.changed[0].to_dict()["version_changed"] is True

    def test_two_versions_of_one_package_keep_the_worse(self):
        shared = dict(category="hardening", finding_id="hardening")
        old = Finding(purl="pkg:npm/lodash@3.0.0", status="warn", count=1, **shared)
        new = Finding(purl="pkg:npm/lodash@4.17.21", status="fail", count=5, **shared)
        delta = diff([Finding(purl="pkg:npm/lodash@3.0.0", status="warn",
                              count=1, **shared)], [old, new])
        assert delta.new == []
        assert len(delta.changed) == 1
        assert delta.changed[0].after.status == "fail"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

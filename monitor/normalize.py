"""Normalize an rl-protect report (rl-protect.report.json) into Finding records.

The report shape (schema 1, see https://docs.secure.software/cli/rl-protect-schema):

    analysis.report.packages[] -> {
        purl,
        analysis.assessment.{secrets,licenses,vulnerabilities,
                             hardening,tampering,malware}
            -> { status: pass|warning|fail, label, count },
        analysis.vulnerabilities -> { "CVE-...": { summary, cvss.baseScore } },
    }

A Finding is identified by (purl, category, finding_id). For vulnerabilities
we use the per-CVE ids when present; for count-only categories the finding_id
is the category name itself (status/count changes are then detected as
"changed" by the diff, not as new identities).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

CATEGORIES = (
    "secrets",
    "licenses",
    "vulnerabilities",
    "hardening",
    "tampering",
    "malware",
)

#: Categories whose findings warrant the loud notification path.
CRITICAL_CATEGORIES = frozenset({"malware", "tampering"})

#: Ordering used to decide whether a status change is an escalation.
STATUS_RANK = {"warn": 1, "fail": 2}


def _normalize_status(raw: Any) -> str:
    s = str(raw or "pass").strip().lower()
    if s in ("warning", "warn"):
        return "warn"
    if s in ("fail", "failed", "error"):
        return "fail"
    return "pass"


@dataclass(frozen=True)
class Finding:
    purl: str
    category: str
    finding_id: str
    status: str
    count: int = 0
    title: str = ""
    score: Optional[float] = field(default=None, compare=False)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.purl, self.category, self.finding_id)

    @property
    def severity(self) -> str:
        return "critical" if self.category in CRITICAL_CATEGORIES else "standard"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "purl": self.purl,
            "category": self.category,
            "id": self.finding_id,
            "status": self.status,
            "count": self.count,
            "title": self.title,
            "severity": self.severity,
        }
        if self.score is not None:
            d["score"] = self.score
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        return cls(
            purl=d["purl"],
            category=d["category"],
            finding_id=d["id"],
            status=_normalize_status(d.get("status")),
            count=int(d.get("count", 0) or 0),
            title=d.get("title", ""),
            score=d.get("score"),
        )


def normalize(report: Dict[str, Any]) -> List[Finding]:
    """Extract all warn/fail findings from a parsed rl-protect report."""
    analysis = report.get("analysis") or {}
    packages = (analysis.get("report") or {}).get("packages") or []
    findings: List[Finding] = []

    for pkg in packages:
        purl = pkg.get("purl")
        if not purl:
            continue
        pkg_analysis = pkg.get("analysis") or {}
        assessment = pkg_analysis.get("assessment") or {}

        for category in CATEGORIES:
            entry = assessment.get(category)
            if not isinstance(entry, dict):
                continue
            status = _normalize_status(entry.get("status"))
            if status == "pass":
                continue
            count = int(entry.get("count", 0) or 0)
            label = str(entry.get("label", "") or "")

            if category == "vulnerabilities":
                details = pkg_analysis.get("vulnerabilities") or {}
                if isinstance(details, dict) and details:
                    for vuln_id, vd in sorted(details.items()):
                        vd = vd if isinstance(vd, dict) else {}
                        score = ((vd.get("cvss") or {}).get("baseScore")
                                 if isinstance(vd.get("cvss"), dict) else None)
                        findings.append(Finding(
                            purl=purl,
                            category=category,
                            finding_id=vuln_id,
                            status=status,
                            count=1,
                            title=str(vd.get("summary") or vd.get("name") or vuln_id),
                            score=score,
                        ))
                    continue

            # Count-only category: identity is the category itself.
            findings.append(Finding(
                purl=purl,
                category=category,
                finding_id=category,
                status=status,
                count=count,
                title=label,
            ))

    return findings


def scan_metadata(report: Dict[str, Any]) -> Dict[str, Any]:
    """Pull scan-level metadata worth keeping in the baseline for audit."""
    analysis = report.get("analysis") or {}
    profile = analysis.get("profile")
    return {
        "timestamp": analysis.get("timestamp"),
        "catalogue": analysis.get("catalogue"),
        "profile": (profile.get("name") if isinstance(profile, dict) else profile),
        "schema": analysis.get("schema"),
    }

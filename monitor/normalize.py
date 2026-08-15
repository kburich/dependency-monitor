"""Normalize an rl-protect report (rl-protect.report.json) into Finding records.

The report shape (schema 1, see https://docs.secure.software/cli/rl-protect-schema):

    analysis.report.packages[] -> {
        purl,
        analysis.assessment.{secrets,licenses,vulnerabilities,
                             hardening,tampering,malware}
            -> { status: pass|warning|fail, label, count },
        analysis.vulnerabilities -> { "CVE-...": { summary, cvss.baseScore } },
    }

A Finding is identified by (base_purl, category, finding_id), where base_purl
is the purl with its version stripped. Identity deliberately ignores the
version: a lockfile bump re-keys every purl in the report, and a version-pinned
identity would report the same CVE as one "resolved" plus one "new" finding --
turning routine upgrades into mass alerts. For vulnerabilities we use the
per-CVE ids when present; for count-only categories the finding_id is the
category name itself (status/count changes are then detected as "changed" by
the diff, not as new identities).
"""

from __future__ import annotations

import math
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


def split_purl(purl: str) -> Tuple[str, str]:
    """Split a purl into (base, version). Returns version "" if unversioned.

    Scoped npm names arrive percent-encoded ("pkg:npm/%40scope/name@1.2.3"),
    so the only literal "@" is the version separator. Qualifiers ("?arch=x64")
    and subpaths ("#sub") stay attached to the base.
    """
    head, sep, tail = purl.partition("?")
    suffix = sep + tail
    if not sep:
        head, sep, tail = purl.partition("#")
        suffix = sep + tail
    base, at, version = head.rpartition("@")
    if not at or "/" in version:
        return purl, ""
    return base + suffix, version


def coerce_count(value: Any) -> int:
    """Coerce any JSON-supplied counter to an int, healing junk to 0.

    Every counter this action reads — finding counts in the vendor's report,
    and both finding counts and cumulative stats in a baseline on disk —
    arrives as arbitrary JSON, so a bare int() turns one mangled value into a
    crashed alerting run. 0 is the safe heal: a mangled cosmetic counter must
    not take down the run, and 0 can never read as an escalation, so a
    corrupt count under-alerts rather than pages falsely. OverflowError
    included: json.load accepts the non-standard `Infinity` literal, and
    int() on the resulting float raises it, not ValueError.
    """
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def coerce_score(value: Any) -> Optional[float]:
    """Coerce a CVSS base score to a float, or None if it is not usable.

    Unlike a count, a corrupt score must not heal to 0.0 — that renders as a
    reassuring 0.0 beside a real CVE. None is the honest heal: it renders as
    "—", exactly like a finding the report gave no score for. Unknown, not
    benign. `bool` is rejected before float() would turn JSON's `true` into
    1.0, and non-finite values are dropped because json.load accepts the
    non-standard `Infinity` and `NaN` literals, which format as "inf"/"nan".
    """
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if math.isfinite(score) else None


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
    def base_purl(self) -> str:
        """Purl with the version stripped — the version-stable package identity."""
        return split_purl(self.purl)[0]

    @property
    def version(self) -> str:
        return split_purl(self.purl)[1]

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.base_purl, self.category, self.finding_id)

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
            count=coerce_count(d.get("count")),
            title=d.get("title", ""),
            score=coerce_score(d.get("score")),
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
            count = coerce_count(entry.get("count"))
            label = str(entry.get("label", "") or "")

            if category == "vulnerabilities":
                details = pkg_analysis.get("vulnerabilities") or {}
                if isinstance(details, dict) and details:
                    for vuln_id, vd in sorted(details.items()):
                        vd = vd if isinstance(vd, dict) else {}
                        score = coerce_score(
                            vd["cvss"].get("baseScore")
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

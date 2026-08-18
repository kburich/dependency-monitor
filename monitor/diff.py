"""Diff two sets of findings (baseline vs current scan).

Delta classes:
  - new:      finding key present now, absent in baseline  -> alert
  - resolved: finding key in baseline, absent now          -> informational
  - changed:  same key, but status escalated (warn->fail) or count grew -> alert

Keys are version-independent (see normalize.Finding.key), so a dependency
upgrade that carries a finding forward is silent rather than a resolved/new
pair. A package version change on its own is never an alert; it is annotated
on the row when it accompanies a real escalation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from .normalize import Finding, STATUS_RANK


@dataclass
class Change:
    before: Finding
    after: Finding

    @property
    def escalated(self) -> bool:
        return STATUS_RANK.get(self.after.status, 0) > STATUS_RANK.get(self.before.status, 0)

    @property
    def version_changed(self) -> bool:
        return self.before.version != self.after.version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "escalated": self.escalated,
            "version_changed": self.version_changed,
        }


@dataclass
class Delta:
    new: List[Finding] = field(default_factory=list)
    resolved: List[Finding] = field(default_factory=list)
    changed: List[Change] = field(default_factory=list)

    @property
    def new_critical(self) -> List[Finding]:
        return [f for f in self.new if f.severity == "critical"]

    @property
    def new_standard(self) -> List[Finding]:
        return [f for f in self.new if f.severity == "standard"]

    @property
    def changed_critical(self) -> List[Change]:
        return [c for c in self.changed if c.after.severity == "critical"]

    @property
    def changed_standard(self) -> List[Change]:
        return [c for c in self.changed if c.after.severity == "standard"]

    @property
    def resolved_critical(self) -> List[Finding]:
        return [f for f in self.resolved if f.severity == "critical"]

    @property
    def resolved_standard(self) -> List[Finding]:
        return [f for f in self.resolved if f.severity == "standard"]

    def alerts(self, critical: bool) -> Tuple[List[Finding], List[Change]]:
        """The (new, changed) pair a severity bucket alerts on.

        The single selection point for every consumer that renders or counts
        one bucket — body headline, comment tables, stats counters, and the
        should-render guard must all agree on it.
        """
        if critical:
            return self.new_critical, self.changed_critical
        return self.new_standard, self.changed_standard

    @property
    def has_alerts(self) -> bool:
        return bool(self.new or self.changed)

    @property
    def has_critical_alerts(self) -> bool:
        return bool(self.new_critical or self.changed_critical)

    @property
    def is_empty(self) -> bool:
        return not (self.new or self.resolved or self.changed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "new": [f.to_dict() for f in self.new],
            "resolved": [f.to_dict() for f in self.resolved],
            "changed": [c.to_dict() for c in self.changed],
            "counts": {
                "new": len(self.new),
                "new_critical": len(self.new_critical) + len(self.changed_critical),
                "resolved": len(self.resolved),
                "changed": len(self.changed),
            },
        }


def _rank(f: Finding) -> tuple:
    # purl breaks ties so the retained finding does not depend on report order
    return (STATUS_RANK.get(f.status, 0), f.count, f.purl)


def _worse(a: Finding, b: Finding) -> Finding:
    return b if _rank(b) > _rank(a) else a


def _index(findings: Iterable[Finding]) -> Dict[Any, Finding]:
    """Map key -> finding, keeping the worst on collision.

    Two versions of the same package routinely coexist in one lockfile (a real
    pnpm scan had 20 packages present at two versions), and they now share a
    key; reporting the more severe of the two is the conservative choice.
    """
    indexed: Dict[Any, Finding] = {}
    for f in findings:
        existing = indexed.get(f.key)
        indexed[f.key] = _worse(existing, f) if existing else f
    return indexed


def diff(baseline: Iterable[Finding], current: Iterable[Finding]) -> Delta:
    base_by_key = _index(baseline)
    curr_by_key = _index(current)

    delta = Delta()
    for key, finding in sorted(curr_by_key.items()):
        if key not in base_by_key:
            delta.new.append(finding)
            continue
        before = base_by_key[key]
        change = Change(before=before, after=finding)
        if change.escalated or finding.count > before.count:
            delta.changed.append(change)

    for key, finding in sorted(base_by_key.items()):
        if key not in curr_by_key:
            delta.resolved.append(finding)

    return delta

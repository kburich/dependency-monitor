"""Diff two sets of findings (baseline vs current scan).

Delta classes:
  - new:      finding key present now, absent in baseline  -> alert
  - resolved: finding key in baseline, absent now          -> informational
  - changed:  same key, but status escalated (warn->fail) or count grew -> alert
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from .normalize import Finding, STATUS_RANK


@dataclass
class Change:
    before: Finding
    after: Finding

    @property
    def escalated(self) -> bool:
        return STATUS_RANK.get(self.after.status, 0) > STATUS_RANK.get(self.before.status, 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "escalated": self.escalated,
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


def diff(baseline: Iterable[Finding], current: Iterable[Finding]) -> Delta:
    base_by_key = {f.key: f for f in baseline}
    curr_by_key = {f.key: f for f in current}

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

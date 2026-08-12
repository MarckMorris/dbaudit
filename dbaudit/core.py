"""Core data model and check registry for dbaudit."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator


class Severity(str, Enum):
    """Severity of a finding, ordered from most to least serious."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher rank means more serious."""
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @property
    def penalty(self) -> int:
        """Points deducted from the score when a check of this severity fails."""
        return {"info": 0, "low": 3, "medium": 10, "high": 20, "critical": 40}[self.value]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank < other.rank


@dataclass(frozen=True)
class Finding:
    """The outcome of a single check."""

    check_id: str
    title: str
    severity: Severity
    passed: bool
    detail: str = ""
    remediation: str = ""
    category: str = "general"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "passed": self.passed,
            "detail": self.detail,
            "remediation": self.remediation,
            "category": self.category,
        }


@dataclass
class Report:
    """A collection of findings with scoring and threshold helpers."""

    target: str = ""
    engine: str = ""
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    @property
    def failures(self) -> list[Finding]:
        return [f for f in self.findings if not f.passed]

    @property
    def passes(self) -> list[Finding]:
        return [f for f in self.findings if f.passed]

    @property
    def score(self) -> int:
        """A 0-100 readiness score. Starts at 100, deducts per failed check."""
        penalty = sum(f.severity.penalty for f in self.failures)
        return max(0, 100 - penalty)

    @property
    def worst(self) -> Severity | None:
        """The most serious severity among failures, or None if all passed."""
        if not self.failures:
            return None
        return max((f.severity for f in self.failures), key=lambda s: s.rank)

    def exceeds(self, threshold: Severity) -> bool:
        """True when any failure is at or above the given severity."""
        worst = self.worst
        return worst is not None and worst.rank >= threshold.rank

    def by_category(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(f.category, []).append(f)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "engine": self.engine,
            "score": self.score,
            "worst_severity": self.worst.value if self.worst else None,
            "total": len(self.findings),
            "passed": len(self.passes),
            "failed": len(self.failures),
            "findings": [f.to_dict() for f in self.findings],
        }


class Check:
    """Base class for a check. Subclass it and implement run()."""

    id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    category: str = "general"
    engines: tuple[str, ...] = ()

    def run(self, conn: Any) -> Finding:
        raise NotImplementedError

    def _finding(self, passed: bool, detail: str = "", remediation: str = "") -> Finding:
        return Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            passed=passed,
            detail=detail,
            remediation=remediation,
            category=self.category,
        )


REGISTRY: list[type[Check]] = []


def register(cls: type[Check]) -> type[Check]:
    """Class decorator that adds a check to the global registry."""
    if not cls.id:
        raise ValueError(f"{cls.__name__} must define an id")
    if any(existing.id == cls.id for existing in REGISTRY):
        raise ValueError(f"duplicate check id: {cls.id}")
    REGISTRY.append(cls)
    return cls


def checks_for(engine: str) -> list[type[Check]]:
    """Every registered check that applies to the given engine."""
    return [c for c in REGISTRY if not c.engines or engine in c.engines]


def run_checks(conn: Any, engine: str, target: str = "") -> Report:
    """Run every applicable check against a live connection."""
    report = Report(target=target, engine=engine)
    for cls in checks_for(engine):
        check = cls()
        try:
            report.add(check.run(conn))
        except Exception as exc:  # a broken check must not abort the audit
            report.add(
                Finding(
                    check_id=cls.id,
                    title=cls.title,
                    severity=Severity.INFO,
                    passed=True,
                    detail=f"check could not run: {exc}",
                    category=cls.category,
                )
            )
    return report

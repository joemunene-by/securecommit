"""Data models for SecureCommit findings and scan results."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) >= order.index(other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) > order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) <= order.index(other)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = list(Severity)
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    """A single security finding."""

    detector: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: str
    line_number: int
    snippet: str
    remediation: str
    end_line: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ScanStats:
    """Statistics for a scan run."""

    files_scanned: int = 0
    findings_total: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    detectors_run: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Aggregated result of a full scan."""

    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    passed: bool = True

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.stats.findings_total += 1
        sev = finding.severity.value
        self.stats.findings_by_severity[sev] = (
            self.stats.findings_by_severity.get(sev, 0) + 1
        )

    def evaluate(self, threshold: Severity) -> bool:
        """Determine pass/fail based on severity threshold."""
        for finding in self.findings:
            if finding.severity >= threshold:
                self.passed = False
                return False
        self.passed = True
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "stats": asdict(self.stats),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

from __future__ import annotations

from collections import Counter

from portwise.core.models import Finding


def finding_counts(findings: list[Finding]) -> dict[str, dict[str, int]]:
    return {
        "by_severity": dict(Counter(f.severity.value for f in findings)),
        "by_status": dict(Counter(f.status for f in findings)),
        "by_type": dict(Counter(f.type for f in findings)),
        "by_confidence": dict(Counter(f.confidence.value for f in findings)),
    }


def assign_priority(finding: Finding, *, context: str = "unknown", internet_facing: bool = False) -> Finding:
    severity = finding.severity.value
    confidence = finding.confidence.value
    external = context == "external" or internet_facing
    if finding.kev and confidence in {"Confirmed", "Likely", "Needs Manual Validation"}:
        finding.priority = "P1"
    elif severity == "critical" and confidence in {"Confirmed", "Likely"}:
        finding.priority = "P1"
    elif (
        finding.exploit_available
        and severity in {"critical", "high"}
        and confidence in {"Confirmed", "Likely", "Needs Manual Validation"}
    ):
        finding.priority = "P1"
    elif (
        finding.epss is not None
        and finding.epss >= 0.5
        and severity in {"critical", "high", "medium"}
    ):
        finding.priority = "P2"
    elif finding.exploit_available and confidence in {"Confirmed", "Likely", "Needs Manual Validation"}:
        finding.priority = "P2"
    elif severity in {"critical", "high"} and confidence in {"Confirmed", "Likely"}:
        finding.priority = "P2"
    elif severity in {"high", "medium"}:
        finding.priority = "P3"
    elif severity in {"medium", "low"}:
        finding.priority = "P4"
    else:
        finding.priority = "P5"
    return finding

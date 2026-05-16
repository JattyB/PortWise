from __future__ import annotations

from portwise.core.models import Confidence, Finding


def confidence_from_strength(strength: int, *, safe_active: bool = False, informational: bool = False) -> Confidence:
    if informational:
        return Confidence.INFORMATIONAL
    if safe_active or strength >= 5:
        return Confidence.CONFIRMED
    if strength == 4:
        return Confidence.LIKELY
    if strength == 3:
        return Confidence.POSSIBLE
    return Confidence.NEEDS_MANUAL_VALIDATION


def apply_confidence(finding: Finding, *, safe_active: bool = False) -> Finding:
    finding.evidence_strength = max([finding.evidence_strength, *[item.strength for item in finding.evidence]])
    finding.confidence = confidence_from_strength(
        finding.evidence_strength,
        safe_active=safe_active or "safe-active" in finding.tags,
        informational=finding.severity.value == "informational",
    )
    return finding

from __future__ import annotations

from portwise.core.models import Confidence, Finding, Severity


BACKPORT_HINTS = ("openssh", "apache", "nginx", "linux")


def apply_false_positive_rules(finding: Finding, context: str = "unknown") -> Finding:
    text = " ".join([finding.title, finding.description, " ".join(finding.tags)]).lower()

    if "banner-only" in finding.tags or "version-only" in finding.tags:
        finding.confidence = Confidence.NEEDS_MANUAL_VALIDATION
        if "Needs Manual Validation" not in finding.tags:
            finding.tags.append("Needs Manual Validation")

    if any(hint in text for hint in BACKPORT_HINTS) and ("version" in text or "cpe" in text):
        finding.confidence = Confidence.NEEDS_MANUAL_VALIDATION
        if "backport-sensitive" not in finding.tags:
            finding.tags.append("backport-sensitive")

    if "hsts" in text and context in {"internal", "unknown"}:
        finding.severity = Severity.LOW
        if "contextual" not in finding.tags:
            finding.tags.append("contextual")

    if "udp open|filtered" in text:
        finding.confidence = Confidence.NEEDS_MANUAL_VALIDATION
        if "udp-open-filtered" not in finding.tags:
            finding.tags.append("udp-open-filtered")

    if "nmap-guessed" in finding.tags and finding.confidence == Confidence.LIKELY:
        finding.confidence = Confidence.POSSIBLE

    if "exact-cpe" in finding.tags and finding.evidence_strength < 3:
        finding.evidence_strength = 3
        if finding.confidence == Confidence.NEEDS_MANUAL_VALIDATION:
            finding.confidence = Confidence.POSSIBLE

    if "safe-active" in finding.tags:
        finding.confidence = Confidence.CONFIRMED

    return finding

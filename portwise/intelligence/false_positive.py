from __future__ import annotations

from portwise.core.models import Confidence, Finding, FindingCategory, Severity
from portwise.intelligence.constants import BACKPORT_SENSITIVE

BACKPORT_HINTS = BACKPORT_SENSITIVE

_ABOVE_LOW = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def apply_category_rules(finding: Finding) -> Finding:
    """Enforce severity caps based on finding category (detection-confidence axis is separate)."""
    if finding.category == FindingCategory.INFORMATION:
        finding.severity = Severity.INFO
    elif finding.category in {FindingCategory.BEST_PRACTICE, FindingCategory.HYGIENE}:
        if finding.severity in _ABOVE_LOW:
            finding.severity = Severity.LOW
    return finding


_CONFIDENCE_RANK = {
    "Confirmed": 0,
    "Likely": 1,
    "Possible": 2,
    "Needs Manual Validation": 3,
    "Informational": 4,
    "False Positive Candidate": 5,
}


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse exact duplicate findings (same endpoint + title), keeping the
    strongest one. Real scans frequently produce the same finding from more than
    one code path (e.g. an exposure keyword and a module probe); without this the
    user sees the same row several times."""
    best: dict[tuple[str, int, str, str], Finding] = {}
    order: list[tuple[str, int, str, str]] = []
    for finding in findings:
        key = (
            str(finding.asset),
            int(finding.port or 0),
            str(finding.protocol or ""),
            str(finding.title).strip().lower(),
        )
        existing = best.get(key)
        if existing is None:
            best[key] = finding
            order.append(key)
            continue
        # Prefer higher detection confidence, then higher evidence strength.
        new_rank = _CONFIDENCE_RANK.get(str(finding.confidence), 9)
        old_rank = _CONFIDENCE_RANK.get(str(existing.confidence), 9)
        if (new_rank, -finding.evidence_strength) < (old_rank, -existing.evidence_strength):
            best[key] = finding
    return [best[key] for key in order]


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

    # NOTE: The blanket "safe-active → CONFIRMED" rule was removed.
    # safe-active raises *detection* confidence (handled in confidence.py),
    # but category and severity are set independently by the module.

    return finding

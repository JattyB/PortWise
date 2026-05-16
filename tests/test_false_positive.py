from portwise.core.models import Confidence, Finding, Severity
from portwise.intelligence.false_positive import apply_false_positive_rules


def test_banner_only_version_needs_manual_validation() -> None:
    finding = Finding(
        title="Apache Version Finding",
        severity=Severity.MEDIUM,
        asset="192.0.2.10",
        description="Apache version from banner-only evidence.",
        confidence=Confidence.LIKELY,
        tags=["banner-only"],
    )
    apply_false_positive_rules(finding, context="external")
    assert finding.confidence == Confidence.NEEDS_MANUAL_VALIDATION
    assert "backport-sensitive" in finding.tags


def test_hsts_internal_lowers_severity() -> None:
    finding = Finding(
        title="Missing HSTS Header",
        severity=Severity.MEDIUM,
        asset="192.0.2.10",
        confidence=Confidence.CONFIRMED,
    )
    apply_false_positive_rules(finding, context="internal")
    assert finding.severity == Severity.LOW

from portwise.core.models import Confidence, Finding, FindingCategory, Severity
from portwise.intelligence.confidence import apply_confidence
from portwise.intelligence.false_positive import apply_category_rules, apply_false_positive_rules


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


def test_missing_header_is_best_practice_not_confirmed_vuln() -> None:
    finding = Finding(
        title="Missing HSTS Header",
        severity=Severity.LOW,
        asset="192.0.2.10",
        evidence_strength=5,
        tags=["safe-active"],
        category=FindingCategory.BEST_PRACTICE,
    )
    apply_category_rules(finding)
    apply_confidence(finding, safe_active=True)
    apply_false_positive_rules(finding)
    assert finding.category == FindingCategory.BEST_PRACTICE
    assert finding.severity not in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
    # Detection confidence may still be CONFIRMED (we observed the absence), that is correct.
    assert finding.confidence == Confidence.CONFIRMED


def test_safe_active_no_longer_forces_confirmed_vuln_severity() -> None:
    # A best_practice finding with safe-active tag must not end up as a HIGH/MEDIUM vuln.
    finding = Finding(
        title="Missing X-Frame-Options",
        severity=Severity.HIGH,  # intentionally wrong starting severity
        asset="192.0.2.10",
        evidence_strength=5,
        tags=["safe-active"],
        category=FindingCategory.BEST_PRACTICE,
    )
    apply_category_rules(finding)
    assert finding.severity not in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def test_information_category_forced_to_info_severity() -> None:
    finding = Finding(
        title="HTTP Server Version Disclosure",
        severity=Severity.MEDIUM,  # intentionally wrong starting severity
        asset="192.0.2.10",
        evidence_strength=5,
        tags=["safe-active"],
        category=FindingCategory.INFORMATION,
    )
    apply_category_rules(finding)
    assert finding.severity == Severity.INFO


def test_backport_sensitive_needs_manual_validation() -> None:
    finding = Finding(
        title="OpenSSH Version Detected",
        severity=Severity.MEDIUM,
        asset="192.0.2.10",
        description="openssh version from banner.",
        confidence=Confidence.LIKELY,
        tags=["version-only"],
    )
    apply_false_positive_rules(finding, context="external")
    assert finding.confidence == Confidence.NEEDS_MANUAL_VALIDATION
    assert "backport-sensitive" in finding.tags

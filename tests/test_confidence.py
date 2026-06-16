from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.intelligence.confidence import apply_confidence, confidence_from_strength
from portwise.intelligence.false_positive import apply_category_rules


def test_confidence_from_strength() -> None:
    assert confidence_from_strength(5) == Confidence.CONFIRMED
    assert confidence_from_strength(4) == Confidence.LIKELY
    assert confidence_from_strength(3) == Confidence.POSSIBLE
    assert confidence_from_strength(2) == Confidence.NEEDS_MANUAL_VALIDATION


def test_safe_active_confirms_finding() -> None:
    # safe-active still raises *detection* confidence — that axis is correct.
    finding = Finding(
        title="HTTP TRACE Method Appears Enabled",
        severity=Severity.LOW,
        asset="192.0.2.10",
        evidence=[Evidence("http-options", "TRACE advertised.", 5)],
        tags=["safe-active"],
    )
    apply_confidence(finding)
    assert finding.confidence == Confidence.CONFIRMED


def test_expired_cert_stays_vulnerability_high() -> None:
    finding = Finding(
        title="Expired TLS Certificate",
        severity=Severity.HIGH,
        asset="192.0.2.10",
        evidence_strength=5,
        tags=["safe-active"],
        category=FindingCategory.VULNERABILITY,
    )
    apply_category_rules(finding)
    apply_confidence(finding, safe_active=True)
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.CONFIRMED


def test_tls12_supported_is_information_not_finding() -> None:
    finding = Finding(
        title="TLS 1.2 Supported",
        severity=Severity.INFO,
        asset="192.0.2.10",
        evidence_strength=5,
        tags=["safe-active"],
        category=FindingCategory.INFORMATION,
    )
    apply_category_rules(finding)
    apply_confidence(finding, safe_active=True)
    assert finding.category == FindingCategory.INFORMATION
    assert finding.severity == Severity.INFO
    assert finding.confidence == Confidence.INFORMATIONAL

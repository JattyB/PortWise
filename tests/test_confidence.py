from portwise.core.models import Evidence, Finding, Severity
from portwise.intelligence.confidence import apply_confidence, confidence_from_strength
from portwise.core.models import Confidence


def test_confidence_from_strength() -> None:
    assert confidence_from_strength(5) == Confidence.CONFIRMED
    assert confidence_from_strength(4) == Confidence.LIKELY
    assert confidence_from_strength(3) == Confidence.POSSIBLE
    assert confidence_from_strength(2) == Confidence.NEEDS_MANUAL_VALIDATION


def test_safe_active_confirms_finding() -> None:
    finding = Finding(
        title="HTTP TRACE Method Appears Enabled",
        severity=Severity.LOW,
        asset="192.0.2.10",
        evidence=[Evidence("http-options", "TRACE advertised.", 5)],
        tags=["safe-active"],
    )
    apply_confidence(finding)
    assert finding.confidence == Confidence.CONFIRMED

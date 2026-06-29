from __future__ import annotations

from portwise.core.models import Confidence, Evidence, Finding, Severity
from portwise.intelligence.risk_scoring import assign_priority
from portwise.intelligence.threat_intel import enrich_findings_with_local_threat_intel


def _finding(cve_id: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        title="Known Vulnerable Component Detected",
        severity=severity,
        asset="192.0.2.1",
        port=80,
        confidence=Confidence.LIKELY,
        cve_id=cve_id,
        evidence=[Evidence(
            "cve-enrichment", "matched", 3,
            {"match_status": "version_matched"},
        )],
    )


def test_packaged_epss_enrichment_uses_probability_and_percentile():
    finding = _finding("CVE-2011-2523", Severity.CRITICAL)
    notes = enrich_findings_with_local_threat_intel([finding])
    assert finding.epss == 0.96184
    assert finding.epss_percentile == 0.9987
    assert finding.priority == "P1"
    assert "epss-enriched" in finding.tags
    assert any("enriched 1" in note for note in notes)


def test_packaged_cisa_kev_sets_known_exploited_and_top_priority():
    finding = _finding("CVE-2021-44228")
    enrich_findings_with_local_threat_intel([finding])
    assert finding.kev is True
    assert finding.epss == 0.99999
    assert finding.priority == "P1"
    assert "cisa-kev" in finding.tags


def test_exploit_available_outranks_cleartext_finding():
    exploit = _finding("CVE-2099-0001")
    exploit.exploit_available = True
    cleartext = Finding(
        title="Cleartext Protocol Exposed — Telnet",
        severity=Severity.HIGH,
        asset="192.0.2.1",
        port=23,
        confidence=Confidence.CONFIRMED,
    )
    assign_priority(exploit)
    assign_priority(cleartext)
    assert exploit.priority == "P1"
    assert cleartext.priority == "P2"

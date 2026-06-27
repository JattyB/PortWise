from portwise.core.models import Evidence, Finding, Severity
from portwise.intelligence.correlation import correlate_findings


def _finding(host, kind, evidence, tags=None):
    return Finding("fixture", Severity.HIGH, host, type=kind, evidence=[Evidence("fixture", "", 5, evidence)], tags=tags or [])


def test_unlinked_secret_does_not_create_attack_path():
    findings = [
        _finding("a.test", "authenticated", {"credential_id": "abc", "url": "/admin"}),
        _finding("a.test", "js-secret", {"url": "/api/one"}, ["secret"]),
    ]
    assert correlate_findings(findings) == []


def test_explicit_secret_endpoint_chain_is_detected():
    findings = [
        _finding("a.test", "js-secret", {"endpoint": "/api/private"}, ["secret"]),
        _finding("a.test", "authenticated", {"credential_id": "abc", "endpoint": "/api/private"}),
    ]
    result = correlate_findings(findings)
    assert len(result) == 1
    assert result[0].type == "attack-path"

from portwise.core.models import Evidence, Finding, Severity
from portwise.intelligence.correlation import credential_reuse_findings


def _accepted(host, credential_id):
    return Finding(
        "fixture", Severity.HIGH, host, type="authenticated",
        evidence=[Evidence("fixture", "", 5, {"credential_id": credential_id, "user": "alice"})],
    )


def test_multi_host_credential_reuse_is_detected_without_secret_material():
    result = credential_reuse_findings([_accepted("a.test", "abc"), _accepted("b.test", "abc")])
    assert len(result) == 1
    assert result[0].evidence[0].data["hosts"] == ["a.test", "b.test"]
    assert "password" not in repr(result[0].evidence).lower()


def test_distinct_credentials_are_not_reuse():
    assert credential_reuse_findings([_accepted("a.test", "abc"), _accepted("b.test", "def")]) == []

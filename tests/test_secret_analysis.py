from __future__ import annotations

from portwise.modules.http.secret_analysis import load_secret_rules, scan_secret_texts, secret_findings


def test_secret_rules_packaged_and_fixture_precision_recall():
    samples = [
        {"source": "main.js", "kind": "js", "text": 'const awsKey = "AKIAABCDEFGHIJKLMNOP";'},
        {"source": "auth.js", "kind": "js", "text": 'const github = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";'},
        {"source": "keys.pem", "kind": "html", "text": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----"},
        {"source": "secrets.js", "kind": "js", "text": 'const slack = "xoxb-123456789012-123456789012-123456789012-AbCdEfGhIjKlMnOp";'},
        {"source": "example.js", "kind": "js", "text": 'const awsKey = "AKIAEXAMPLE12345678";'},
        {"source": "noise.js", "kind": "js", "text": 'const nonce = "v9X7Q2m8K1p4R6s3T0u1";'},
        {"source": "doc.js", "kind": "html", "text": 'const token = "eyJhbGciOiJIUzI1NiJ9.example.example"; // example token'},
        {"source": "vendor.min.js", "kind": "js", "text": "function a(b){return b+'x'.repeat(200);}"},
    ]

    rules = load_secret_rules()
    assert rules

    scan = scan_secret_texts(samples, rules=rules)
    flagged_sources = {match.source for match in scan.matches}

    must_flag = {"main.js", "auth.js", "keys.pem", "secrets.js"}
    must_not_flag = {"example.js", "noise.js", "doc.js", "vendor.min.js"}

    tp = len(flagged_sources & must_flag)
    fp = len(flagged_sources & must_not_flag)
    fn = len(must_flag - flagged_sources)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    assert fp == 0, f"must-not-flag samples were flagged: {flagged_sources & must_not_flag}"
    assert precision >= 0.95, (precision, flagged_sources)
    assert recall >= 0.95, (recall, flagged_sources)

    findings = secret_findings(
        samples,
        asset="fixture.test",
        port=443,
        protocol="tcp",
        service="https",
    )
    assert findings
    for finding in findings:
        assert finding.manual_validation
        assert finding.evidence[0].data["value_redacted"]
        assert "AKIAABCDEFGHIJKLMNOP" not in finding.description

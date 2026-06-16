from __future__ import annotations

from pathlib import Path


from portwise.core.models import Evidence
from portwise.utils.sanitize import (
    build_transcript,
    sanitize_body,
    sanitize_headers,
    sanitize_url,
)
from portwise.utils.http_client import PoliteResponse


# ---------------------------------------------------------------------------
# Sanitization unit tests
# ---------------------------------------------------------------------------

def test_secrets_redacted_in_headers():
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer super-secret-token",
        "Cookie": "session=abc123; token=xyz",
        "Set-Cookie": "auth=secret; HttpOnly",
        "X-Custom": "safe-value",
    }
    result = sanitize_headers(headers)
    assert result["Authorization"] == "<redacted>"
    assert result["Cookie"] == "<redacted>"
    assert result["Set-Cookie"] == "<redacted>"
    assert result["Content-Type"] == "application/json"
    assert result["X-Custom"] == "safe-value"


def test_secret_patterns_redacted_in_body_and_url():
    body = "POST /login?api_key=MYSECRET&user=test"
    result = sanitize_body(body)
    assert "MYSECRET" not in result
    assert "api_key=<redacted>" in result
    assert "user=test" in result

    url = "https://example.com/api?token=abc123&q=search"
    result_url = sanitize_url(url)
    assert "abc123" not in result_url
    assert "token=<redacted>" in result_url
    assert "q=search" in result_url


def test_body_excerpt_capped():
    large_body = "A" * 10000
    result = sanitize_body(large_body, cap=2048)
    assert len(result) <= 2048


# ---------------------------------------------------------------------------
# Evidence.with_transcript
# ---------------------------------------------------------------------------

def test_transcript_attached_to_http_finding():
    evidence = Evidence.with_transcript(
        source="test:source",
        description="HTTP 200 on /.env",
        strength=4,
        method="GET",
        url="http://10.0.0.1:80/.env",
        request_headers={"User-Agent": "PortWise/1.0"},
        response_status=200,
        response_headers=[("content-type", "text/plain"), ("server", "nginx")],
        response_body=b"DB_PASSWORD=secret123\nAPP_KEY=abc",
        timing_ms=45,
    )
    assert "transcript" in evidence.data
    t = evidence.data["transcript"]
    assert t["request"]["method"] == "GET"
    assert t["request"]["url"] == "http://10.0.0.1:80/.env"
    assert t["response"]["status"] == 200
    assert t["timing_ms"] == 45
    # Secret in body must be redacted
    body_excerpt = t["response"]["body_excerpt"]
    assert "secret123" not in body_excerpt
    assert "<redacted>" in body_excerpt


def test_transcript_request_headers_sanitized():
    evidence = Evidence.with_transcript(
        source="test",
        description="probe",
        strength=3,
        method="GET",
        url="http://example.com/api",
        request_headers={"Authorization": "Bearer tok123", "User-Agent": "PortWise"},
        response_status=401,
        response_headers=[],
        response_body=b"Unauthorized",
        timing_ms=10,
    )
    req_hdrs = evidence.data["transcript"]["request"]["headers"]
    assert req_hdrs["Authorization"] == "<redacted>"
    assert req_hdrs["User-Agent"] == "PortWise"


# ---------------------------------------------------------------------------
# PoliteResponse.to_evidence
# ---------------------------------------------------------------------------

def test_polite_response_to_evidence():
    meta = {
        "method": "GET",
        "url": "http://10.0.0.1:80/admin/",
        "headers_sent": {"User-Agent": "PortWise"},
        "timing_ms": 23,
        "observed_at": "2026-05-23T10:00:00+00:00",
    }
    resp = PoliteResponse(200, [("server", "Apache")], b"Admin Panel", request_meta=meta)
    ev = resp.to_evidence("module:http", "Admin panel accessible", 4)
    assert "transcript" in ev.data
    t = ev.data["transcript"]
    assert t["request"]["method"] == "GET"
    assert t["response"]["status"] == 200
    assert "Apache" in str(t["response"]["headers"])


# ---------------------------------------------------------------------------
# build_transcript helper
# ---------------------------------------------------------------------------

def test_build_transcript_structure():
    t = build_transcript(
        method="POST",
        url="http://example.com/login",
        request_headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": "sess=abc"},
        request_body="username=admin&password=secret",
        response_status=302,
        response_reason="Found",
        response_headers={"location": "/dashboard", "set-cookie": "auth=tok123"},
        response_body=b"Redirecting...",
        timing_ms=88,
        observed_at="2026-05-23T10:00:00Z",
    )
    assert t["request"]["headers"]["Cookie"] == "<redacted>"
    assert t["response"]["headers"]["set-cookie"] == "<redacted>"
    # password in body should be redacted
    assert "secret" not in t["request"]["body_sent"]
    assert t["timing_ms"] == 88
    assert t["observed_at"] == "2026-05-23T10:00:00Z"


# ---------------------------------------------------------------------------
# Evidence export to files
# ---------------------------------------------------------------------------

def test_evidence_export_writes_sanitized_files(tmp_path):
    report = {
        "findings": [
            {
                "id": "finding-abc-123",
                "title": "Sensitive File Found",
                "asset": "10.0.0.1",
                "port": 80,
                "evidence": [
                    {
                        "source": "test",
                        "description": "Found /.env",
                        "strength": 4,
                        "data": {
                            "transcript": {
                                "request": {
                                    "method": "GET",
                                    "url": "http://10.0.0.1:80/.env",
                                    "headers": {"Authorization": "<redacted>"},
                                    "body_sent": None,
                                },
                                "response": {
                                    "status": 200,
                                    "reason": "OK",
                                    "headers": {"server": "nginx"},
                                    "body_excerpt": "APP_KEY=safe-value",
                                    "body_bytes_len": 18,
                                },
                                "timing_ms": 35,
                                "observed_at": "2026-05-23T10:00:00Z",
                            }
                        },
                    }
                ],
            }
        ]
    }
    from portwise.cli import _export_evidence_transcripts
    written: list[str] = []
    errors: list[str] = []
    _export_evidence_transcripts(report, tmp_path / "evidence", written, errors)
    assert not errors, f"Unexpected errors: {errors}"
    assert written, "Expected at least one transcript file"
    transcript_file = Path(written[0])
    assert transcript_file.exists()
    content = transcript_file.read_text(encoding="utf-8")
    assert "Sensitive File Found" in content
    assert "GET http://10.0.0.1:80/.env" in content
    assert "HTTP 200" in content


# ---------------------------------------------------------------------------
# Non-HTTP module transcripts (PT5 Step 3)
# ---------------------------------------------------------------------------

def test_non_http_module_transcript():
    """SNMP community accepted finding should carry a probe transcript in evidence."""
    from unittest.mock import patch
    from portwise.modules.registry import SnmpSafeModule

    target = {
        "host": "10.0.0.1", "port": 161, "protocol": "udp", "service": "snmp",
        "product": "", "version": "", "cpe": [], "routing_reason": "",
        "scripts": {},
    }
    with patch("portwise.modules.registry._snmp_get", return_value="Linux server01 4.15.0"):
        result = SnmpSafeModule().run(target, {"snmp": {"default_community_check": True, "communities": ["public"]}})

    community_findings = [f for f in result.findings if "Default SNMP Community" in f.title]
    assert community_findings, "Expected SNMP community finding"
    f = community_findings[0]
    transcripts = [e for e in f.evidence if isinstance((e.data or {}).get("transcript"), dict)]
    assert transcripts, "Expected a probe transcript on SNMP community finding"
    t = transcripts[0].data["transcript"]
    assert "request" in t and "response" in t
    assert "SNMP" in t["request"].get("probe", "")
    assert "Linux" in t["response"].get("body_excerpt", "")


# ---------------------------------------------------------------------------
# Evidence appendix in pentest report (PT5 Step 4b)
# ---------------------------------------------------------------------------

def test_evidence_appendix_lists_all_transcripts(tmp_path):
    """Pentest report must contain A.5 Evidence Appendix when transcripts are present."""
    from portwise.reporting.pentest_report import write_pentest_report

    report = {
        "project": "Test",
        "findings": [
            {
                "id": "find-001",
                "title": "SNMP Community Accepted",
                "severity": "high",
                "confidence": "confirmed",
                "category": "vulnerability",
                "asset": "10.0.0.1",
                "port": 161,
                "evidence": [
                    {
                        "source": "module:snmp",
                        "description": "SNMP probe response",
                        "strength": 5,
                        "data": {
                            "transcript": {
                                "request": {"probe": "SNMP GET sysDescr", "target": "udp://10.0.0.1:161"},
                                "response": {"status": "ok", "body_excerpt": "Linux server01 4.15.0"},
                                "timing_ms": 0,
                                "observed_at": "2026-05-23T10:00:00+00:00",
                            }
                        },
                    }
                ],
            }
        ],
    }
    out = tmp_path / "report.html"
    write_pentest_report(report, out)
    html = out.read_text(encoding="utf-8")
    assert "A.5 Evidence Appendix" in html
    assert "find-001" in html
    assert "SNMP GET sysDescr" in html

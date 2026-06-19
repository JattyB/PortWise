from __future__ import annotations

import hashlib
from http.client import HTTPResponse
from io import BytesIO
from unittest.mock import MagicMock, patch

from portwise.core.models import Service
from portwise.modules.http.http_engine import HttpEngine
from portwise.modules.tls.tls_engine import TlsEngine


def _make_service(host: str = "203.0.113.10", port: int = 443) -> Service:
    return Service(host=host, port=port, protocol="tcp", state="open", service_name="https")


def _fake_response(status: int = 200, headers: list[tuple[str, str]] | None = None, body: bytes = b"") -> HTTPResponse:
    raw = BytesIO(
        b"HTTP/1.1 "
        + str(status).encode()
        + b" OK\r\n"
        + b"".join(f"{k}: {v}\r\n".encode() for k, v in (headers or []))
        + b"\r\n"
        + body
    )
    resp = HTTPResponse(MagicMock())
    resp.fp = raw
    resp.chunked = False
    resp.length = len(body)
    resp._headers_read = False
    return resp


# ---------------------------------------------------------------------------
# Task A — No OCSP finding
# ---------------------------------------------------------------------------

def test_no_ocsp_finding_emitted():
    engine = TlsEngine()
    with (
        patch.object(engine, "_fetch_certificate", return_value=None),
        patch.object(engine, "_protocol_findings", return_value=[]),
        patch.object(engine, "_hsts_findings", return_value=[]),
    ):
        findings = engine.run(_make_service())
    titles = [f.title for f in findings]
    assert not any("OCSP" in t for t in titles), f"OCSP finding should not exist, got: {titles}"


# ---------------------------------------------------------------------------
# Task B — TLS "Not Tested" noise suppressed
# ---------------------------------------------------------------------------

def test_tls_not_tested_noise_suppressed():
    engine = TlsEngine()
    service = _make_service()

    def raise_value_error(*args, **kwargs):
        raise ValueError("unsupported protocol version")

    with patch.object(engine, "_test_protocol", side_effect=raise_value_error):
        findings = engine._protocol_findings(service)

    not_tested = [f for f in findings if "Not Tested" in f.title]
    assert not_tested == [], f"Per-host 'Not Tested' findings must be suppressed, got: {not_tested}"
    # Capability note should be recorded on the engine instance
    notes = engine.get_capability_notes()
    assert notes, "Engine should record at least one capability note"
    assert any("unsupported" in n.lower() or "limited" in n.lower() for n in notes)


# ---------------------------------------------------------------------------
# Task C — Cache key stability across processes (SHA-256 based)
# ---------------------------------------------------------------------------

def test_cache_key_is_stable_across_processes():
    from portwise.intelligence.cve_enrichment import _sha_key
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx+1.22.0"
    key1 = _sha_key(url)
    key2 = _sha_key(url)
    expected = hashlib.sha256(url.encode()).hexdigest()[:32]
    assert key1 == key2 == expected, "Cache key must be deterministic (not process-salted)"
    assert len(key1) == 32


# ---------------------------------------------------------------------------
# Task D — TRACE method detection still works after refactor
# ---------------------------------------------------------------------------

def test_trace_method_detection_still_works():
    engine = HttpEngine()
    service = _make_service(port=80)

    allow_response = MagicMock()
    allow_response.getheader.return_value = "GET, POST, TRACE, HEAD"

    findings = engine._method_findings(service, allow_response)
    titles = [f.title for f in findings]
    assert "HTTP TRACE Method Enabled" in titles


def test_no_trace_finding_when_trace_absent():
    engine = HttpEngine()
    service = _make_service(port=80)

    allow_response = MagicMock()
    allow_response.getheader.return_value = "GET, POST, HEAD"

    findings = engine._method_findings(service, allow_response)
    assert not any("TRACE" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Task E — All TLS and HTTP findings carry explicit module field
# ---------------------------------------------------------------------------

def test_all_tls_findings_have_module_set():
    engine = TlsEngine()
    service = _make_service()

    # Findings returned without a real TLS connection
    with (
        patch.object(engine, "_fetch_certificate", return_value=None),
        patch.object(engine, "_test_protocol", return_value=False),
        patch.object(engine, "_hsts_findings", return_value=[]),
    ):
        findings = engine.run(service)

    for f in findings:
        assert f.module == "tls", f"Finding '{f.title}' has module={f.module!r}, expected 'tls'"


def test_tls_hostname_matching_uses_san_and_one_label_wildcards():
    cert = {
        "subject": ((("commonName", "fallback.example.test"),),),
        "subjectAltName": (("DNS", "*.example.test"),),
    }

    assert TlsEngine._hostname_matches_certificate("app.example.test", cert)[0] is True
    assert TlsEngine._hostname_matches_certificate("deep.app.example.test", cert)[0] is False
    cn_only_cert = {"subject": ((("commonName", "fallback.example.test"),),)}
    assert TlsEngine._hostname_matches_certificate("fallback.example.test", cn_only_cert)[0] is True


def test_tls_certificate_findings_include_chain_failure_without_match_hostname():
    engine = TlsEngine()
    service = Service(
        host="wrong.host.badssl.com",
        hostname="wrong.host.badssl.com",
        port=443,
        protocol="tcp",
        state="open",
        service_name="https",
    )
    cert = {
        "subject": ((("commonName", "*.badssl.com"),),),
        "issuer": ((("commonName", "BadSSL Intermediate Certificate Authority"),),),
        "subjectAltName": (("DNS", "*.badssl.com"),),
        "notAfter": "Dec 31 23:59:59 2099 GMT",
        "_portwise_chain_valid": False,
        "_portwise_chain_error": "self-signed certificate in certificate chain",
    }

    findings = engine._certificate_findings(service, cert)
    titles = [finding.title for finding in findings]

    assert "Untrusted Certificate Chain" in titles
    assert "TLS Hostname Mismatch" in titles


def test_all_http_findings_have_module_set():
    engine = HttpEngine()
    service = _make_service(port=80)

    head_mock = MagicMock()
    head_mock.status = 200
    head_mock.getheaders.return_value = []

    get_mock = MagicMock()
    get_mock.status = 200
    get_mock.getheaders.return_value = [("Server", "nginx/1.22.0")]
    get_mock.read.return_value = b"<html><title>Test</title></html>"

    options_mock = MagicMock()
    options_mock.getheader.return_value = ""
    options_mock.getheaders.return_value = []

    with (
        patch.object(engine, "_request", side_effect=[head_mock, get_mock, options_mock]),
        patch.object(engine, "_safe_path_findings", return_value=[]),
    ):
        findings = engine.run(service)

    for f in findings:
        assert f.module == "http", f"Finding '{f.title}' has module={f.module!r}, expected 'http'"


# ---------------------------------------------------------------------------
# Task E — Browser UA replaces scanner signature
# ---------------------------------------------------------------------------

def test_default_user_agent_is_not_scanner_signature():
    from portwise.modules.http.http_engine import _BROWSER_UA as http_ua
    from portwise.modules.tls.tls_engine import _BROWSER_UA as tls_ua
    assert "safe-validation" not in http_ua
    assert "safe-validation" not in tls_ua
    assert "Mozilla" in http_ua
    assert "Mozilla" in tls_ua

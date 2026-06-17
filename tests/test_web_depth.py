from __future__ import annotations

import re
from typing import Any
from unittest.mock import MagicMock, patch


from portwise.modules.http.cms_fingerprint import run_cms_fingerprint
from portwise.modules.http.content_discovery import run_content_discovery
from portwise.modules.http.injection_indicators import run_injection_indicators
from portwise.utils.http_client import PoliteHttpClient

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_client(responses: dict[str, tuple[int, dict, str]] | None = None) -> PoliteHttpClient:
    """Build a PoliteHttpClient whose .request() is mocked."""
    client = PoliteHttpClient.__new__(PoliteHttpClient)
    client._budget = {}  # type: ignore[attr-defined]
    client._tripped = set()  # type: ignore[attr-defined]
    client._delay = 0.0  # type: ignore[attr-defined]
    client._mode = "polite"  # type: ignore[attr-defined]
    client._max_requests = 9999  # type: ignore[attr-defined]
    client._request_counts = {}  # type: ignore[attr-defined]
    responses = responses or {}

    def _fake_request(host, port, method, path, tls, timeout):
        key = path.split("?")[0]
        status, headers, body = responses.get(key, (404, {}, "Not Found"))
        resp = MagicMock()
        resp.status = status
        resp.read = MagicMock(side_effect=lambda n=None: body[:n].encode() if n else body.encode())
        resp.getheaders = MagicMock(return_value=list(headers.items()))
        return resp

    client.request = _fake_request  # type: ignore[method-assign]
    client.throttle = lambda host: None  # type: ignore[method-assign]
    client.is_tripped = lambda host: False  # type: ignore[method-assign]
    return client


_TARGET: dict[str, Any] = {
    "host": "10.0.0.1", "port": 80, "protocol": "tcp", "service": "http",
    "product": "", "version": "", "routing_reason": "", "cpe": [],
}


# ---------------------------------------------------------------------------
# Content discovery
# ---------------------------------------------------------------------------

def test_soft_404_detection_suppresses_false_hits():
    # Soft-404: site always returns 200 with the same body for unknown paths
    soft_body = "Page not found - Our website"
    client = _make_client({
        # The random soft-404 probe path is unknown, match first
        "/.env": (200, {}, soft_body),  # same body as soft-404 → should be suppressed
    })
    # Patch _soft_404_fingerprint to return a known pattern
    with patch("portwise.modules.http.content_discovery._soft_404_fingerprint", return_value=(200, soft_body)):
        findings = run_content_discovery(
            "10.0.0.1", 80, False, 3.0, client, _TARGET, {}, validation_level="full"
        )
    # .env returns 200 but body matches soft-404, so no finding emitted
    env_findings = [f for f in findings if ".env" in f.title.lower()]
    assert not env_findings, "Soft-404 hit should have been suppressed"


def test_backup_file_discovery_reports_high():
    db_body = "-- MySQL dump 10.13\n-- Host: localhost\nCREATE TABLE users"
    client = _make_client({"/db.sql": (200, {}, db_body)})
    with patch("portwise.modules.http.content_discovery._soft_404_fingerprint", return_value=(404, "")):
        findings = run_content_discovery(
            "10.0.0.1", 80, False, 3.0, client, _TARGET, {}, validation_level="full"
        )
    sql_findings = [f for f in findings if "db.sql" in f.title.lower() or "database dump" in f.title.lower()]
    assert sql_findings, "Should find database dump"
    assert sql_findings[0].severity.value in ("high", "critical")


def test_content_discovery_recon_level_only_fetches_recon_paths():
    requested_paths: list[str] = []
    client = _make_client()

    def _capturing_request(host, port, method, path, tls, timeout):
        requested_paths.append(path.split("?")[0])
        resp = MagicMock()
        resp.status = 404
        resp.read = MagicMock(return_value=b"")
        resp.getheaders = MagicMock(return_value=[])
        return resp

    client.request = _capturing_request  # type: ignore[method-assign]
    with patch("portwise.modules.http.content_discovery._soft_404_fingerprint", return_value=(404, "")):
        run_content_discovery("10.0.0.1", 80, False, 3.0, client, _TARGET, {}, validation_level="recon")

    recon_only = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}
    for path in requested_paths:
        assert path in recon_only or path.startswith("/portwise-nonexistent"), f"Non-recon path requested at recon depth: {path}"


def test_content_discovery_respects_budget():
    call_count = 0
    client = _make_client()

    def _counter(host, port, method, path, tls, timeout):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.status = 404
        resp.read = MagicMock(return_value=b"")
        resp.getheaders = MagicMock(return_value=[])
        return resp

    client.request = _counter  # type: ignore[method-assign]
    config = {"web_content_discovery": {"max_requests": 5}}
    with patch("portwise.modules.http.content_discovery._soft_404_fingerprint", return_value=(404, "")):
        run_content_discovery("10.0.0.1", 80, False, 3.0, client, _TARGET, config, validation_level="full")
    # soft-404 probe + up to max_requests
    assert call_count <= 6, f"Budget exceeded: {call_count} requests made"


# ---------------------------------------------------------------------------
# CMS fingerprinting
# ---------------------------------------------------------------------------

def test_wordpress_version_detected_and_cpe_built():
    body = '<meta name="generator" content="WordPress 6.2.1" /><link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">'
    client = _make_client({"/wp-login.php": (200, {}, "WordPress Login"), "/wp-admin/": (302, {}, "")})
    findings = run_cms_fingerprint(
        "10.0.0.1", 80, False, 3.0, client, _TARGET,
        homepage_headers={}, homepage_cookies={}, homepage_body=body
    )
    wp_findings = [f for f in findings if "WordPress" in f.title]
    assert wp_findings, "WordPress should be detected"
    assert "6.2.1" in wp_findings[0].title or "6.2.1" in wp_findings[0].description
    cpe_findings = [f for f in findings if "cpe" in f.title.lower() or "cpe" in str(f.tags)]
    assert cpe_findings, "CPE finding should be emitted for WordPress with version"


def test_cms_eol_version_flagged_as_best_practice():
    body = '<meta name="generator" content="WordPress 4.9.8" />'
    client = _make_client({"/wp-login.php": (200, {}, "")})
    findings = run_cms_fingerprint(
        "10.0.0.1", 80, False, 3.0, client, _TARGET,
        homepage_headers={}, homepage_cookies={}, homepage_body=body
    )
    wp = [f for f in findings if "WordPress" in f.title and "4.9" in (f.title + f.description)]
    assert wp, "WordPress 4.9 (EOL) should be detected"
    # EOL → best_practice or medium severity
    assert any(f.severity.value in ("medium", "high") or f.category.value == "best_practice" for f in wp)


# ---------------------------------------------------------------------------
# Injection indicators
# ---------------------------------------------------------------------------

def test_reflected_token_indicator_possible_only():
    body_with_links = '<a href="/search?q=test">Search</a>'
    token_re = re.compile(r"pwxss[a-f0-9]{8}")

    def _reflecting_request(host, port, method, path, tls, timeout):
        resp = MagicMock()
        resp.status = 200
        m = token_re.search(path)
        body = (m.group(0) if m else "no-reflect").encode()
        resp.read = MagicMock(side_effect=lambda n=None: body[:n] if n else body)
        resp.getheaders = MagicMock(return_value=[])
        return resp

    client = _make_client()
    client.request = _reflecting_request  # type: ignore[method-assign]
    findings = run_injection_indicators(
        "10.0.0.1", 80, False, 3.0, client, _TARGET,
        homepage_body=body_with_links, validation_level="full"
    )
    xss = [f for f in findings if "Reflected" in f.title or "XSS" in f.title]
    assert xss, "Reflected token should produce a finding"
    assert all(f.confidence.value == "Possible" for f in xss), "Must be POSSIBLE, not confirmed"
    assert all(f.manual_validation for f in xss)


def test_sql_error_signature_indicator():
    body_with_links = '<a href="/item?id=1">Item</a>'

    def _sql_error_request(host, port, method, path, tls, timeout):
        resp = MagicMock()
        resp.status = 500
        body = b"You have an error in your SQL syntax near ''"
        resp.read = MagicMock(side_effect=lambda n=None: body[:n] if n else body)
        resp.getheaders = MagicMock(return_value=[])
        return resp

    client = _make_client()
    client.request = _sql_error_request  # type: ignore[method-assign]
    findings = run_injection_indicators(
        "10.0.0.1", 80, False, 3.0, client, _TARGET,
        homepage_body=body_with_links, validation_level="full"
    )
    sql = [f for f in findings if "SQL" in f.title]
    assert sql, "SQL error pattern should produce a finding"
    assert sql[0].confidence.value == "Possible"
    assert sql[0].manual_validation


def test_open_redirect_indicator():
    body_with_links = '<a href="/auth?next=/home">Login</a>'
    sentinel = "https://portwise-redirect-test.invalid"

    def _redirect_request(host, port, method, path, tls, timeout):
        resp = MagicMock()
        resp.status = 302
        # The sentinel may be URL-encoded in the path; echo it back if present
        location = sentinel if ("portwise-redirect-test" in path) else ""
        resp.read = MagicMock(return_value=b"")
        resp.getheaders = MagicMock(return_value=[("location", location)])
        return resp

    client = _make_client()
    client.request = _redirect_request  # type: ignore[method-assign]
    findings = run_injection_indicators(
        "10.0.0.1", 80, False, 3.0, client, _TARGET,
        homepage_body=body_with_links, validation_level="full"
    )
    redir = [f for f in findings if "Redirect" in f.title]
    assert redir, "Open redirect indicator should be emitted"
    assert redir[0].confidence.value == "Possible"


def test_injection_checks_disabled_at_recon_level():
    body_with_links = '<a href="/search?q=test">Search</a>'
    client = _make_client()
    findings = run_injection_indicators(
        "10.0.0.1", 80, False, 3.0, client, _TARGET,
        homepage_body=body_with_links, validation_level="recon"
    )
    assert findings == [], "Injection checks must not run at recon depth"

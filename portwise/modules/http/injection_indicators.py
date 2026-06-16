from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.utils.http_client import PoliteHttpClient

# ---------------------------------------------------------------------------
# CRITICAL: These checks are INDICATORS ONLY.
# GET-only, single request per param, no destructive payloads, no exploitation.
# All findings are POSSIBLE confidence with manual_validation=True.
# Runs in every mode except the lightweight "safe" mode.
# ---------------------------------------------------------------------------

_SQL_ERROR_PATTERNS = re.compile(
    r"(sql syntax|syntax error|unclosed quotation mark|"
    r"ORA-[0-9]{5}|mysql_fetch|mysql_num_rows|"
    r"SQLSTATE\[|pg_query|pdo exception|"
    r"invalid query|you have an error in your sql|"
    r"warning: mysql_|supplied argument is not a valid mysql)",
    re.IGNORECASE,
)

_REDIRECT_PARAM_NAMES = frozenset({"next", "url", "redirect", "redirect_url", "return", "return_url", "goto", "redir", "location"})


def _extract_params_from_body(body: str, base_url: str) -> list[str]:
    """Extract URLs with query params from homepage body."""
    urls = re.findall(r'href=["\']([^"\']+)["\']', body)
    params_seen: set[str] = set()
    result: list[str] = []
    for url in urls[:30]:  # cap at 30 links
        if not url.startswith("/") and not url.startswith("http"):
            continue
        parsed = urlparse(url)
        if parsed.query:
            for param in parse_qs(parsed.query):
                if param not in params_seen:
                    params_seen.add(param)
                    result.append(url)
                    break
    return result[:10]  # hard cap: 10 parameterised URLs


def run_injection_indicators(
    host: str,
    port: int,
    tls: bool,
    timeout: float,
    client: PoliteHttpClient,
    target: dict[str, Any],
    homepage_body: str,
    validation_level: str = "safe",
    module: str = "http",
) -> list[Finding]:
    """
    Injection indicator checks. NEVER runs at 'safe' level.
    GET-only, single request per param, POSSIBLE confidence only.
    """
    if validation_level == "safe":
        return []

    findings: list[Finding] = []
    param_urls = _extract_params_from_body(homepage_body, f"{'https' if tls else 'http'}://{host}:{port}/")

    for param_url in param_urls:
        if client.is_tripped(host):
            break
        parsed = urlparse(param_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name, values in list(params.items())[:3]:  # cap: 3 params per URL
            if client.is_tripped(host):
                break
            original_value = values[0] if values else ""

            # --- Reflected token check ---
            token = f"pwxss{uuid.uuid4().hex[:8]}"
            test_params = dict(params)
            test_params[param_name] = [original_value + token]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            path_with_qs = test_url.replace(f"{'https' if tls else 'http'}://{host}:{port}", "")
            client.throttle(host)
            try:
                resp = client.request(host, port, "GET", path_with_qs, tls, timeout)
                body = resp.read(4096).decode("utf-8", errors="replace")
                if token in body:
                    evidence = Evidence(
                        f"module:{module}:injection",
                        f"Token {token} reflected in response for param '{param_name}'.",
                        2,
                        {"param": param_name, "url": param_url, "token": token},
                    )
                    findings.append(Finding(
                        title="Potential Reflected Input (XSS Candidate)",
                        severity=Severity.MEDIUM,
                        asset=str(target.get("host", host)),
                        port=port,
                        protocol=str(target.get("protocol", "tcp")),
                        service=str(target.get("service", "")),
                        description=f"Parameter '{param_name}' at {param_url} reflects input unencoded in the response. This is a POSSIBLE XSS indicator requiring manual confirmation. No script payload was sent.",
                        recommendation="Verify manually under authorization. Apply context-aware output encoding. Implement Content-Security-Policy.",
                        confidence=Confidence.POSSIBLE,
                        evidence_strength=2,
                        type="Injection Indicator",
                        module=module,
                        false_positive_risk="medium",
                        manual_validation=True,
                        evidence=[evidence],
                        category=FindingCategory.VULNERABILITY,
                        tags=["xss-indicator", "manual-required"],
                    ))
            except Exception:
                pass

            # --- SQL error indicator ---
            client.throttle(host)
            sql_params = dict(params)
            sql_params[param_name] = [original_value + "'"]
            sql_url = urlunparse(parsed._replace(query=urlencode(sql_params, doseq=True)))
            sql_path = sql_url.replace(f"{'https' if tls else 'http'}://{host}:{port}", "")
            try:
                resp = client.request(host, port, "GET", sql_path, tls, timeout)
                body = resp.read(4096).decode("utf-8", errors="replace")
                if _SQL_ERROR_PATTERNS.search(body):
                    evidence = Evidence(
                        f"module:{module}:injection",
                        f"SQL error pattern found in response for param '{param_name}' with single-quote appended.",
                        2,
                        {"param": param_name, "url": param_url},
                    )
                    findings.append(Finding(
                        title="Potential SQL Error Disclosure",
                        severity=Severity.MEDIUM,
                        asset=str(target.get("host", host)),
                        port=port,
                        protocol=str(target.get("protocol", "tcp")),
                        service=str(target.get("service", "")),
                        description=f"Parameter '{param_name}' at {param_url} produced a database error signature when a single-quote was appended. This is a POSSIBLE SQL injection indicator requiring manual confirmation.",
                        recommendation="Verify manually under authorization. Use parameterised queries and disable verbose database errors in production.",
                        confidence=Confidence.POSSIBLE,
                        evidence_strength=2,
                        type="Injection Indicator",
                        module=module,
                        false_positive_risk="medium",
                        manual_validation=True,
                        evidence=[evidence],
                        category=FindingCategory.VULNERABILITY,
                        tags=["sqli-indicator", "manual-required"],
                    ))
            except Exception:
                pass

            # --- Open redirect indicator ---
            if param_name.lower() in _REDIRECT_PARAM_NAMES:
                sentinel = "https://portwise-redirect-test.invalid"
                redir_params = dict(params)
                redir_params[param_name] = [sentinel]
                redir_url = urlunparse(parsed._replace(query=urlencode(redir_params, doseq=True)))
                redir_path = redir_url.replace(f"{'https' if tls else 'http'}://{host}:{port}", "")
                client.throttle(host)
                try:
                    resp = client.request(host, port, "GET", redir_path, tls, timeout)
                    resp.read(256)
                    location = dict(resp.getheaders()).get("location", "")
                    if sentinel in location:
                        evidence = Evidence(
                            f"module:{module}:injection",
                            f"Location header echoed sentinel URL for param '{param_name}'.",
                            2,
                            {"param": param_name, "url": param_url, "location": location},
                        )
                        findings.append(Finding(
                            title="Potential Open Redirect",
                            severity=Severity.LOW,
                            asset=str(target.get("host", host)),
                            port=port,
                            protocol=str(target.get("protocol", "tcp")),
                            service=str(target.get("service", "")),
                            description=f"Parameter '{param_name}' at {param_url} echoed a sentinel URL in the Location header. This is a POSSIBLE open redirect indicator requiring manual confirmation.",
                            recommendation="Validate redirect targets against an allowlist. Reject absolute URLs for untrusted user input.",
                            confidence=Confidence.POSSIBLE,
                            evidence_strength=2,
                            type="Injection Indicator",
                            module=module,
                            false_positive_risk="medium",
                            manual_validation=True,
                            evidence=[evidence],
                            category=FindingCategory.VULNERABILITY,
                            tags=["open-redirect-indicator", "manual-required"],
                        ))
                except Exception:
                    pass

    return findings

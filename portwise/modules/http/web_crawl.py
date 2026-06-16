"""Lightweight, safe web crawler.

GET-only, same-origin, capped request budget, uses the polite client (browser
headers). It pulls the homepage + a few linked pages and same-origin JS files,
then surfaces:

* interesting endpoints / API paths,
* JavaScript source files,
* high-signal secrets (API keys, tokens, private keys) found in HTML/JS.

It deliberately does NOT follow off-origin redirects (per the operator's note),
submit forms, or send any payloads. Findings are conservative: secrets are
reported with their match redacted, endpoints are informational.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.utils.http_client import PoliteHttpClient

_HREF_RE = re.compile(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_JS_URL_RE = re.compile(r'["\'](/[^"\']*?\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
_ENDPOINT_RE = re.compile(r'["\'`](/(?:api|v\d|rest|graphql|admin|internal|auth|oauth|user|users|account)[^"\'`\s]*)["\'`]', re.IGNORECASE)
_FETCH_RE = re.compile(r'(?:fetch|axios\.(?:get|post|put|delete)|\.open)\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE)

# High-signal secret patterns. Kept tight to avoid false positives.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Stripe Live Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Generic API Key Assignment", re.compile(r"""(?i)\b(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)\b["'\s]*[:=]["'\s]*([0-9a-zA-Z\-_]{16,})""")),
]


def _redact(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:4] + "***" + value[-4:]


def _same_origin(url: str, host: str, port: int) -> bool:
    p = urlparse(url)
    if not p.netloc:
        return True  # relative
    target_host = p.hostname or ""
    return target_host == host or target_host == f"{host}:{port}"


def run_web_crawl(
    host: str,
    port: int,
    tls: bool,
    timeout: float,
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
    homepage_body: str,
    validation_level: str = "safe",
    module: str = "http",
) -> list[Finding]:
    crawl_cfg = config.get("web_crawl", {}) if isinstance(config.get("web_crawl"), dict) else {}
    if not bool(crawl_cfg.get("enabled", True)):
        return []
    # Active by nature (multiple GETs); run only when active web checks are allowed.
    if validation_level == "safe" and not bool(crawl_cfg.get("force", False)):
        return []

    max_pages = int(crawl_cfg.get("max_pages", 8))
    max_js = int(crawl_cfg.get("max_js", 10))
    scheme = "https" if tls else "http"
    base = f"{scheme}://{host}:{port}"

    findings: list[Finding] = []
    secrets_seen: set[tuple[str, str]] = set()
    endpoints: set[str] = set()
    js_files: set[str] = set()

    bodies: list[tuple[str, str]] = [("/", homepage_body)]

    # Collect same-origin links from homepage.
    links: list[str] = []
    for raw in _HREF_RE.findall(homepage_body)[:80]:
        if raw.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            continue
        absolute = urljoin(base + "/", raw)
        if not _same_origin(absolute, host, port):
            continue
        path = urlparse(absolute).path or "/"
        if path.lower().endswith(".js"):
            js_files.add(path)
        elif path not in [l for l in links] and path != "/":
            links.append(path)

    for m in _JS_URL_RE.findall(homepage_body):
        js_files.add(m)

    # Fetch a few same-origin pages.
    for path in links[: max_pages - 1]:
        if client.is_tripped(host):
            break
        client.throttle(host)
        try:
            resp = client.request(host, port, "GET", path, tls, timeout)
            if 300 <= resp.status < 400:
                loc = resp.getheader("Location", "")
                if loc and not _same_origin(urljoin(base, loc), host, port):
                    continue  # off-origin redirect → skip per policy
            body = resp.read(20000).decode("utf-8", errors="replace")
            bodies.append((path, body))
            for m in _JS_URL_RE.findall(body):
                js_files.add(m)
        except Exception:
            continue

    # Fetch same-origin JS files.
    for js in list(js_files)[:max_js]:
        if client.is_tripped(host):
            break
        client.throttle(host)
        try:
            resp = client.request(host, port, "GET", js, tls, timeout)
            body = resp.read(60000).decode("utf-8", errors="replace")
            bodies.append((js, body))
        except Exception:
            continue

    # Analyse all collected bodies.
    for path, body in bodies:
        for ep in _ENDPOINT_RE.findall(body):
            endpoints.add(ep)
        for ep in _FETCH_RE.findall(body):
            if ep.startswith("/") and len(ep) < 120:
                endpoints.add(ep)
        for label, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1) if match.groups() else match.group(0)
                key = (label, value)
                if key in secrets_seen:
                    continue
                secrets_seen.add(key)
                findings.append(Finding(
                    title=f"Potential Secret Exposed in Web Content ({label})",
                    severity=Severity.HIGH,
                    asset=str(target.get("host", host)),
                    port=port,
                    protocol=str(target.get("protocol", "tcp")),
                    service=str(target.get("service", "")),
                    description=f"A {label} pattern was found in {base}{path}: {_redact(value)}. Verify whether this is a live credential.",
                    recommendation="Rotate the credential if valid, remove it from client-delivered code, and move secrets server-side.",
                    confidence=Confidence.NEEDS_MANUAL_VALIDATION,
                    evidence_strength=3,
                    type="Secret Exposure",
                    module=module,
                    false_positive_risk="medium",
                    manual_validation=True,
                    evidence=[Evidence(f"module:{module}:web-crawl", f"{label} pattern matched in {path}.", 3,
                                       {"url": f"{base}{path}", "match_redacted": _redact(value), "label": label})],
                    category=FindingCategory.VULNERABILITY,
                    tags=["web-crawl", "secret", "manual-required"],
                ))

    if js_files:
        js_list = sorted(js_files)[:25]
        findings.append(Finding(
            title="JavaScript Files Discovered (Review for Secrets/Endpoints)",
            severity=Severity.INFO,
            asset=str(target.get("host", host)), port=port,
            protocol=str(target.get("protocol", "tcp")), service=str(target.get("service", "")),
            description=f"{len(js_files)} same-origin JS file(s) found at {base}. Worth manual review (e.g. with LinkFinder/SecretFinder): {', '.join(js_list)}.",
            recommendation="Review client-side JS for embedded secrets, internal endpoints, and commented-out code.",
            confidence=Confidence.CONFIRMED, evidence_strength=3, type="Information", module=module,
            false_positive_risk="low", manual_validation=False,
            evidence=[Evidence(f"module:{module}:web-crawl", "Same-origin JS inventory.", 3, {"js_files": js_list})],
            category=FindingCategory.INFORMATION, tags=["web-crawl", "javascript"],
        ))

    if endpoints:
        ep_list = sorted(endpoints)[:40]
        findings.append(Finding(
            title="Interesting Endpoints Discovered via Crawl",
            severity=Severity.LOW,
            asset=str(target.get("host", host)), port=port,
            protocol=str(target.get("protocol", "tcp")), service=str(target.get("service", "")),
            description=f"{len(endpoints)} interesting endpoint(s)/API path(s) referenced in {base} content: {', '.join(ep_list)}.",
            recommendation="Manually probe these endpoints for authentication, authorization, and information-disclosure issues.",
            confidence=Confidence.CONFIRMED, evidence_strength=3, type="Information", module=module,
            false_positive_risk="low", manual_validation=False,
            evidence=[Evidence(f"module:{module}:web-crawl", "Endpoints extracted from HTML/JS.", 3, {"endpoints": ep_list})],
            category=FindingCategory.INFORMATION, tags=["web-crawl", "endpoints"],
        ))

    return findings

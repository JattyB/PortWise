from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.modules.http.secret_analysis import secret_findings
from portwise.modules.http.surface import DiscoveredSurface, normalize_url, surface_key
from portwise.utils.http_client import PoliteHttpClient

_ABSOLUTE_URL_RE = re.compile(r"""(?<![\w-])(https?://[^\s'"<>()]+)""", re.IGNORECASE)
_URL_LITERAL_RE = re.compile(r"""(?<![\w-])(['"])(/[^'"`<>\s]{2,200}|(?:\.\./|\.\/)?(?:api|v\d|rest|graphql|auth|oauth|admin|internal|users|user|account|search|comments|files)[^'"`<>\s]{0,200})\1""", re.IGNORECASE)
_FETCH_CALL_RE = re.compile(
    r"""(?:(?:fetch|axios\.(?:get|post|put|delete|patch|request)|\$\.(?:ajax|get|post|put|delete)|XMLHttpRequest\.prototype\.open|XMLHttpRequest\.open)\s*\(\s*(?:['"](?:(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS))['"]\s*,\s*)?['"]([^'"]{2,300})['"])""",
    re.IGNORECASE | re.DOTALL,
)
_NEW_URL_RE = re.compile(r"""new\s+URL\(\s*['"]([^'"]{2,300})['"]""", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)


@dataclass(slots=True)
class JsEndpoint:
    url: str
    source: str
    reason: str
    file_url: str


@dataclass(slots=True)
class JsAnalysisResult:
    endpoints: list[JsEndpoint] = field(default_factory=list)
    secret_findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    requests: int = 0
    elapsed_s: float = 0.0

    @property
    def req_s(self) -> float:
        return self.requests / self.elapsed_s if self.elapsed_s > 0 else 0.0


async def run_js_analysis_async(
    *,
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
    surface: DiscoveredSurface,
    homepage_body: str = "",
    module: str = "http",
) -> list[Finding]:
    cfg = config.get("js_analysis", {}) if isinstance(config.get("js_analysis"), dict) else {}
    if not bool(cfg.get("enabled", True)):
        return []

    started = time.perf_counter()
    base_url = _base_url(target, surface)
    candidate_urls = _candidate_js_urls(surface)
    endpoint_hits: list[JsEndpoint] = []
    texts_for_secret_scan: list[dict[str, Any]] = []

    if homepage_body:
        surface.add_body(base_url, homepage_body)
        texts_for_secret_scan.append({"source": base_url, "text": homepage_body, "kind": "html"})
        endpoint_hits.extend(_extract_js_endpoints(homepage_body, base_url, base_url))

    for url, body in list(surface.bodies.items()):
        if body and _looks_html(body):
            texts_for_secret_scan.append({"source": url, "text": body, "kind": "html"})

    semaphore = asyncio.Semaphore(int(cfg.get("concurrency", 8)))

    async def fetch_js(url: str) -> tuple[str, str] | None:
        async with semaphore:
            response = await client.request_url_async(url, timeout=float(cfg.get("timeout", 8.0)))
            body = response.read(int(cfg.get("body_limit", 200_000))).decode("utf-8", errors="replace")
            return url, body

    fetched = await asyncio.gather(*(fetch_js(url) for url in candidate_urls), return_exceptions=True)
    js_bodies: list[tuple[str, str]] = []
    for item in fetched:
        if isinstance(item, tuple):
            js_bodies.append(item)

    for url, body in js_bodies:
        surface.add_body(url, body)
        texts_for_secret_scan.append({"source": url, "text": body, "kind": "js"})
        endpoint_hits.extend(_extract_js_endpoints(body, url, base_url))

    for hit in endpoint_hits:
        surface.add_url(hit.url, "js-analysis")

    findings: list[Finding] = []
    if endpoint_hits:
        findings.append(_endpoint_finding(target, endpoint_hits, module=module, scanned=len(candidate_urls), req_s=len(endpoint_hits) / max(time.perf_counter() - started, 0.001)))

    findings.extend(
        secret_findings(
            texts_for_secret_scan,
            asset=str(target.get("host", "")),
            port=target.get("port"),
            protocol=str(target.get("protocol", "tcp")),
            service=str(target.get("service", "http")),
            module=module,
        )
    )
    return findings


def extract_js_endpoints(body: str, file_url: str, base_url: str) -> list[JsEndpoint]:
    return _extract_js_endpoints(body, file_url, base_url)


def _extract_js_endpoints(body: str, file_url: str, base_url: str) -> list[JsEndpoint]:
    endpoints: list[JsEndpoint] = []
    seen: set[str] = set()
    for match in _FETCH_CALL_RE.finditer(body):
        candidate = match.group(1).strip()
        url = _normalize_endpoint(candidate, base_url)
        if url and url not in seen:
            seen.add(url)
            endpoints.append(JsEndpoint(url=url, source=match.group(0)[:120], reason="fetch/xhr/axios", file_url=file_url))
    for regex, reason, group_index in (
        (_ABSOLUTE_URL_RE, "absolute-url", 1),
        (_URL_LITERAL_RE, "string-literal", 2),
        (_NEW_URL_RE, "new-url", 1),
    ):
        for match in regex.finditer(body):
            candidate = match.group(group_index).strip()
            url = _normalize_endpoint(candidate, base_url)
            if url and url not in seen:
                seen.add(url)
                endpoints.append(JsEndpoint(url=url, source=match.group(0)[:120], reason=reason, file_url=file_url))
    for match in _SCRIPT_SRC_RE.finditer(body):
        candidate = match.group(1).strip()
        url = _normalize_endpoint(candidate, base_url)
        if url and url not in seen:
            seen.add(url)
            endpoints.append(JsEndpoint(url=url, source=match.group(0)[:120], reason="script-src", file_url=file_url))
    return endpoints


def _endpoint_finding(target: dict[str, Any], endpoints: list[JsEndpoint], module: str, scanned: int, req_s: float) -> Finding:
    data = [
        {"url": item.url, "reason": item.reason, "file_url": item.file_url, "source": item.source[:120]}
        for item in endpoints[:100]
    ]
    evidence = Evidence(
        f"module:{module}:js-endpoints",
        "JavaScript endpoint extraction identified same-origin API paths and URLs.",
        3,
        {"endpoints": data, "scanned_files": scanned, "req_s": round(req_s, 2)},
    )
    return Finding(
        title="JavaScript Endpoints Discovered",
        severity=Severity.INFO,
        asset=str(target.get("host", "")),
        port=target.get("port"),
        protocol=str(target.get("protocol", "tcp")),
        service=str(target.get("service", "http")),
        description=f"Extracted {len(endpoints)} endpoint(s)/URL(s) from JavaScript sources.",
        recommendation="Use discovered JS endpoints as input to content fuzzing and parameter discovery.",
        confidence=Confidence.CONFIRMED,
        evidence_strength=3,
        type="Information",
        module=module,
        false_positive_risk="low",
        evidence=[evidence],
        category=FindingCategory.INFORMATION,
        tags=["js-analysis", "endpoints"],
    )


def _candidate_js_urls(surface: DiscoveredSurface) -> list[str]:
    candidates = set(surface.js_files)
    for url in surface.endpoints:
        if url.lower().split("?", 1)[0].endswith(".js"):
            candidates.add(url)
    return sorted(candidates)


def _normalize_endpoint(candidate: str, base_url: str) -> str | None:
    candidate = candidate.strip().strip("`'\"")
    if not candidate or candidate.startswith(("data:", "javascript:", "#", "mailto:", "tel:")):
        return None
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    if candidate.startswith(("http://", "https://")):
        normalized = normalize_url(candidate)
        return normalized if _same_origin(normalized, base_url) and _interesting_path(normalized) else None
    if candidate.startswith(("/", "./", "../")) or "/" in candidate:
        joined = normalize_url(urljoin(base_url, candidate))
        if _same_origin(joined, base_url) and _interesting_path(joined):
            return joined
    return None


def _interesting_path(url: str) -> bool:
    path = urlsplit(url).path.lower()
    ignored = (
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".map",
    )
    return not path.endswith(ignored)


def _same_origin(url: str, base_url: str) -> bool:
    left = urlsplit(normalize_url(url))
    right = urlsplit(normalize_url(base_url))
    return (left.scheme, left.hostname, left.port or _default_port(left.scheme)) == (
        right.scheme,
        right.hostname,
        right.port or _default_port(right.scheme),
    )


def _base_url(target: dict[str, Any], surface: DiscoveredSurface) -> str:
    if surface.endpoints:
        first = next(iter(surface.endpoints))
        parsed = urlsplit(first)
        return f"{parsed.scheme}://{parsed.hostname}:{parsed.port or _default_port(parsed.scheme)}/"
    scheme = "https" if str(target.get("protocol", "tcp")) == "ssl" or int(target.get("port") or 0) in {443, 8443, 9443} else "http"
    host = str(target.get("host", "localhost"))
    port = int(target.get("port") or (443 if scheme == "https" else 80))
    return f"{scheme}://{host}:{port}/"


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _looks_html(text: str) -> bool:
    head = text[:512].lower()
    return "<html" in head or "<!doctype html" in head or "<head" in head

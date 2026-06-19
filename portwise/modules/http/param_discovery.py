from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.modules.http.surface import DiscoveredSurface, strip_query
from portwise.utils.http_client import PoliteHttpClient

DEFAULT_CANDIDATE_PARAMS = (
    "id", "q", "search", "query", "page", "cat", "category", "type", "sort",
    "view", "lang", "debug", "test", "callback", "returnUrl", "url", "redirect",
    "NewsAd", "tfSearch",
)


@dataclass(frozen=True, slots=True)
class ActiveParameterHit:
    endpoint: str
    parameter: str
    reason: str
    status: int
    baseline_status: int


@dataclass(slots=True)
class ActiveParameterResult:
    hits: list[ActiveParameterHit] = field(default_factory=list)
    tested: int = 0
    elapsed_s: float = 0.0

    @property
    def req_s(self) -> float:
        return self.tested / self.elapsed_s if self.elapsed_s > 0 else 0.0


class ActiveParameterDiscovery:
    def __init__(
        self,
        client: PoliteHttpClient,
        timeout: float = 8.0,
        concurrency: int = 5,
        max_tests: int = 80,
    ) -> None:
        self.client = client
        self.timeout = timeout
        self.concurrency = concurrency
        self.max_tests = max_tests

    async def discover(
        self,
        endpoints: list[str],
        candidate_params: list[str] | tuple[str, ...] = DEFAULT_CANDIDATE_PARAMS,
    ) -> ActiveParameterResult:
        started = time.perf_counter()
        result = ActiveParameterResult()
        tests: list[tuple[str, str]] = []
        for endpoint in endpoints:
            base = strip_query(endpoint)
            existing = {name for name, _ in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True)}
            for param in candidate_params:
                if param in existing:
                    continue
                tests.append((base, param))
                if len(tests) >= self.max_tests:
                    break
            if len(tests) >= self.max_tests:
                break

        semaphore = asyncio.Semaphore(max(1, self.concurrency))
        baselines: dict[str, tuple[int, int, str]] = {}

        async def baseline(endpoint: str) -> tuple[int, int, str]:
            if endpoint in baselines:
                return baselines[endpoint]
            response = await self.client.request_url_async(endpoint, timeout=self.timeout)
            body = response.read(120_000)
            shape = (response.status, len(body), hashlib.sha256(body[:4096]).hexdigest())
            baselines[endpoint] = shape
            return shape

        async def probe(endpoint: str, param: str) -> ActiveParameterHit | None:
            async with semaphore:
                baseline_status, baseline_len, baseline_hash = await baseline(endpoint)
                sentinel = f"pwx{hashlib.sha1((endpoint + param).encode()).hexdigest()[:12]}"
                target = _with_param(endpoint, param, sentinel)
                response = await self.client.request_url_async(target, timeout=self.timeout)
                body = response.read(120_000)
                result.tested += 1
                text = body.decode("utf-8", errors="ignore")
                if _meaningful_reflection(text, sentinel):
                    return ActiveParameterHit(endpoint, param, "reflected", response.status, baseline_status)
                if response.status != baseline_status:
                    return ActiveParameterHit(endpoint, param, "status-change", response.status, baseline_status)
                length_delta = abs(len(body) - baseline_len)
                if baseline_len and length_delta / max(baseline_len, 1) >= 0.20:
                    return ActiveParameterHit(endpoint, param, "response-size-change", response.status, baseline_status)
                if hashlib.sha256(body[:4096]).hexdigest() != baseline_hash and length_delta > 256:
                    return ActiveParameterHit(endpoint, param, "response-shape-change", response.status, baseline_status)
                return None

        for output in await asyncio.gather(*(probe(endpoint, param) for endpoint, param in tests), return_exceptions=True):
            if isinstance(output, ActiveParameterHit):
                result.hits.append(output)
        result.elapsed_s = time.perf_counter() - started
        return result


def extract_archive_parameters(surface: DiscoveredSurface) -> dict[str, set[str]]:
    params: dict[str, set[str]] = {}
    for url in surface.archive_urls | set(surface.endpoints):
        parsed = urlsplit(url)
        names = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        if names:
            params.setdefault(strip_query(url), set()).update(names)
    return params


def paramspider_finding(surface: DiscoveredSurface, target: dict[str, Any], module: str = "http") -> Finding | None:
    params = extract_archive_parameters(surface)
    if not params:
        return None
    for endpoint, names in params.items():
        for name in names:
            surface.add_param(endpoint, name)
    evidence = Evidence(
        f"module:{module}:archive-parameters",
        "Parameterized URLs and parameter names extracted from discovered archive URLs.",
        3,
        {"parameters": {endpoint: sorted(names) for endpoint, names in sorted(params.items())[:100]}},
    )
    total = sum(len(names) for names in params.values())
    return Finding(
        title="Parameters Discovered from Historical URLs",
        severity=Severity.INFO,
        asset=str(target.get("host", "")),
        port=target.get("port"),
        protocol=str(target.get("protocol", "tcp")),
        service=str(target.get("service", "http")),
        description=f"Found {total} parameter name occurrence(s) across {len(params)} archived endpoint(s).",
        recommendation="Use these parameters for bounded active probing and template checks.",
        confidence=Confidence.CONFIRMED,
        evidence_strength=3,
        type="Information",
        module=module,
        false_positive_risk="low",
        evidence=[evidence],
        category=FindingCategory.INFORMATION,
        tags=["param-discovery", "archive"],
    )


async def run_active_parameter_discovery_async(
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
    surface: DiscoveredSurface,
    module: str = "http",
) -> list[Finding]:
    cfg = config.get("web_param_discovery", {}) if isinstance(config.get("web_param_discovery"), dict) else {}
    endpoints = sorted({strip_query(url) for url in surface.endpoints if _active_probe_candidate(url)})
    if not endpoints:
        return []
    candidates = cfg.get("candidate_params") or DEFAULT_CANDIDATE_PARAMS
    discovery = ActiveParameterDiscovery(
        client=client,
        timeout=float(cfg.get("timeout", 8.0)),
        concurrency=int(cfg.get("concurrency", 5)),
        max_tests=int(cfg.get("max_tests", 80)),
    )
    result = await discovery.discover(endpoints, list(candidates))
    for hit in result.hits:
        surface.add_param(hit.endpoint, hit.parameter)
    if not result.hits:
        return []
    evidence = Evidence(
        f"module:{module}:active-parameters",
        "Candidate parameters changed response shape or reflected a sentinel value.",
        4,
        {
            "hits": [
                {
                    "endpoint": hit.endpoint,
                    "parameter": hit.parameter,
                    "reason": hit.reason,
                    "status": hit.status,
                    "baseline_status": hit.baseline_status,
                }
                for hit in result.hits
            ],
            "tested": result.tested,
            "req_s": round(result.req_s, 2),
        },
    )
    return [Finding(
        title="Active Parameter Discovery Found Responsive Parameters",
        severity=Severity.INFO,
        asset=str(target.get("host", "")),
        port=target.get("port"),
        protocol=str(target.get("protocol", "tcp")),
        service=str(target.get("service", "http")),
        description=f"Found {len(result.hits)} responsive parameter(s) after {result.tested} bounded active probe(s).",
        recommendation="Use discovered parameters for focused validation of injection, access-control, and business-logic issues.",
        confidence=Confidence.CONFIRMED,
        evidence_strength=4,
        type="Information",
        module=module,
        false_positive_risk="low",
        evidence=[evidence],
        category=FindingCategory.INFORMATION,
        tags=["param-discovery", "active"],
    )]


def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(pairs), ""))


def _active_probe_candidate(url: str) -> bool:
    path = urlsplit(url).path.lower()
    static_ext = (
        ".js", ".css", ".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz",
    )
    return not path.endswith(static_ext)


def _meaningful_reflection(text: str, sentinel: str) -> bool:
    if sentinel not in text:
        return False
    scrubbed = re.sub(
        r"""(?is)<form\b[^>]*\baction=["'][^"']*"""
        + re.escape(sentinel)
        + r"""[^"']*["'][^>]*>""",
        "",
        text,
    )
    return sentinel in scrubbed

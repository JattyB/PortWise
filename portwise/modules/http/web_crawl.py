"""Async same-origin crawler and web surface extractor."""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.modules.http.surface import DiscoveredSurface, normalize_url, surface_from_config, surface_key
from portwise.utils.http_client import PoliteHttpClient, PoliteResponse, _run_sync

_JS_URL_RE = re.compile(r'["\'](/[^"\']*?\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
_ENDPOINT_RE = re.compile(r'["\'`](/(?:api|v\d|rest|graphql|admin|internal|auth|oauth|user|users|account)[^"\'`\s]*)["\'`]', re.IGNORECASE)
_FETCH_RE = re.compile(r'(?:fetch|axios\.(?:get|post|put|delete)|\.open)\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE)


@dataclass(slots=True)
class CrawledPage:
    url: str
    status: int
    depth: int
    body: str


@dataclass(slots=True)
class CrawlResult:
    base_url: str
    pages: list[CrawledPage] = field(default_factory=list)
    endpoints: set[str] = field(default_factory=set)
    js_files: set[str] = field(default_factory=set)
    forms: list[dict[str, Any]] = field(default_factory=list)
    skipped_off_origin_redirects: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    requests: int = 0

    @property
    def req_s(self) -> float:
        return self.requests / self.elapsed_s if self.elapsed_s > 0 else 0.0


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.js_files: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag in {"a", "link"} and attrs_dict.get("href"):
            self.links.append(attrs_dict["href"])
        if tag in {"script", "img", "iframe"} and attrs_dict.get("src"):
            src = attrs_dict["src"]
            self.links.append(src)
            if src.lower().split("?", 1)[0].endswith(".js"):
                self.js_files.append(src)
        if tag == "form":
            self._form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }
        if tag in {"input", "select", "textarea", "button"} and self._form is not None:
            name = attrs_dict.get("name")
            if name:
                self._form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


class AsyncWebCrawler:
    def __init__(
        self,
        client: PoliteHttpClient,
        timeout: float = 5.0,
        max_pages: int = 20,
        max_depth: int = 2,
        concurrency: int = 5,
        max_js: int = 20,
        body_limit: int = 120_000,
    ) -> None:
        self.client = client
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.max_js = max_js
        self.body_limit = body_limit

    async def crawl(self, base_url: str, homepage_body: str = "") -> CrawlResult:
        started = time.perf_counter()
        result = CrawlResult(base_url=normalize_url(base_url))
        robots = await self._robots_disallow(result.base_url)
        queue: asyncio.Queue[tuple[str, int, str | None]] = asyncio.Queue()
        seen: set[str] = set()
        await queue.put((result.base_url, 0, homepage_body or None))
        semaphore = asyncio.Semaphore(max(1, self.concurrency))

        async def worker() -> None:
            while len(result.pages) < self.max_pages:
                try:
                    url, depth, preloaded = await asyncio.wait_for(queue.get(), timeout=0.1)
                except asyncio.TimeoutError:
                    return
                normalized = normalize_url(url)
                if normalized in seen or depth > self.max_depth or _blocked_by_robots(normalized, robots):
                    queue.task_done()
                    continue
                seen.add(normalized)
                try:
                    async with semaphore:
                        status, body, final_url = await self._fetch_page(normalized, preloaded)
                    result.requests += 0 if preloaded is not None else 1
                    if final_url and not _same_origin(final_url, result.base_url):
                        result.skipped_off_origin_redirects.append(final_url)
                        queue.task_done()
                        continue
                    page = CrawledPage(normalized, status, depth, body)
                    result.pages.append(page)
                    self._extract_page(page, result)
                    if depth < self.max_depth:
                        for link in _extract_links(body):
                            absolute = normalize_url(urljoin(normalized, link))
                            if _same_origin(absolute, result.base_url) and _crawlable_url(absolute) and absolute not in seen:
                                await queue.put((absolute, depth + 1, None))
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(max(1, self.concurrency))]
        await queue.join()
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        js_to_fetch = [js for js in sorted(result.js_files) if _same_origin(js, result.base_url)]
        for js_url in js_to_fetch[: self.max_js]:
            if len(result.pages) >= self.max_pages + self.max_js:
                break
            try:
                status, body, _ = await self._fetch_page(js_url, None)
            except Exception:
                continue
            result.requests += 1
            page = CrawledPage(js_url, status, self.max_depth + 1, body)
            result.pages.append(page)
            self._extract_body_signals(js_url, body, result)

        result.elapsed_s = time.perf_counter() - started
        return result

    async def _fetch_page(self, url: str, preloaded: str | None) -> tuple[int, str, str]:
        if preloaded is not None:
            return 200, preloaded, url
        response = await _request_url_compat(self.client, url, timeout=self.timeout, allow_redirects=False)
        if 300 <= response.status < 400:
            location = response.getheader("Location", "")
            if location:
                redirect = normalize_url(urljoin(url, location))
                if not _same_origin(redirect, url):
                    return response.status, "", redirect
                response = await _request_url_compat(self.client, redirect, timeout=self.timeout, allow_redirects=False)
                url = redirect
        body = response.read(self.body_limit).decode("utf-8", errors="replace")
        return response.status, body, url

    async def _robots_disallow(self, base_url: str) -> set[str]:
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            response = await _request_url_compat(self.client, robots_url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return set()
        if response.status >= 400:
            return set()
        text = response.read(20_000).decode("utf-8", errors="replace")
        return _parse_robots_disallow(text)

    def _extract_page(self, page: CrawledPage, result: CrawlResult) -> None:
        result.endpoints.add(page.url)
        parser = _parse_links(page.body)
        for form in parser.forms:
            action = normalize_url(urljoin(page.url, form["action"] or page.url))
            result.forms.append({"page": page.url, "action": action, "method": form["method"], "inputs": form["inputs"]})
        for js in parser.js_files:
            result.js_files.add(normalize_url(urljoin(page.url, js)))
        for raw in _JS_URL_RE.findall(page.body):
            result.js_files.add(normalize_url(urljoin(page.url, raw)))
        self._extract_body_signals(page.url, page.body, result)

    def _extract_body_signals(self, url: str, body: str, result: CrawlResult) -> None:
        for endpoint in _ENDPOINT_RE.findall(body):
            result.endpoints.add(normalize_url(urljoin(url, endpoint)))
        for endpoint in _FETCH_RE.findall(body):
            if endpoint.startswith("/") and len(endpoint) < 160:
                result.endpoints.add(normalize_url(urljoin(url, endpoint)))


async def run_web_crawl_async(
    host: str,
    port: int,
    tls: bool,
    timeout: float,
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
    homepage_body: str,
    validation_level: str = "recon",
    module: str = "http",
) -> list[Finding]:
    crawl_cfg = config.get("web_crawl", {}) if isinstance(config.get("web_crawl"), dict) else {}
    if not bool(crawl_cfg.get("enabled", True)):
        return []
    if validation_level == "recon" and not bool(crawl_cfg.get("force", False)):
        return []

    scheme = "https" if tls else "http"
    base = f"{scheme}://{host}:{port}/"
    crawler = AsyncWebCrawler(
        client=client,
        timeout=timeout,
        max_pages=int(crawl_cfg.get("max_pages", 20)),
        max_depth=int(crawl_cfg.get("max_depth", 2)),
        concurrency=int(crawl_cfg.get("concurrency", 5)),
        max_js=int(crawl_cfg.get("max_js", 20)),
    )
    result = await crawler.crawl(base, homepage_body=homepage_body)
    surface = surface_from_config(config, surface_key(host, port))
    _merge_crawl_surface(result, surface)
    return _crawl_findings(result, target, module)


def run_web_crawl(
    host: str,
    port: int,
    tls: bool,
    timeout: float,
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
    homepage_body: str,
    validation_level: str = "recon",
    module: str = "http",
) -> list[Finding]:
    return _run_sync(run_web_crawl_async(
        host, port, tls, timeout, client, target, config, homepage_body,
        validation_level=validation_level, module=module,
    ))


def _merge_crawl_surface(result: CrawlResult, surface: DiscoveredSurface) -> None:
    for page in result.pages:
        surface.add_url(page.url, "crawler", status=page.status, depth=page.depth)
        surface.add_body(page.url, page.body)
    for endpoint in result.endpoints:
        surface.add_url(endpoint, "crawler")
    for js in result.js_files:
        surface.js_files.add(js)
        surface.add_url(js, "crawler-js")
    for form in result.forms:
        surface.add_form(form["page"], form["action"], form["method"], list(form["inputs"]))


def _crawl_findings(result: CrawlResult, target: dict[str, Any], module: str) -> list[Finding]:
    host = str(target.get("host", ""))
    port = target.get("port")
    protocol = str(target.get("protocol", "tcp"))
    service = str(target.get("service", ""))
    findings: list[Finding] = []

    if result.js_files:
        js_list = sorted(result.js_files)[:25]
        findings.append(Finding(
            title="JavaScript Files Discovered (Review for Secrets/Endpoints)",
            severity=Severity.INFO,
            asset=host,
            port=port,
            protocol=protocol,
            service=service,
            description=f"{len(result.js_files)} same-origin JS file(s) found. Worth manual review: {', '.join(js_list)}.",
            recommendation="Review client-side JS for embedded secrets, internal endpoints, and commented-out code.",
            confidence=Confidence.CONFIRMED,
            evidence_strength=3,
            type="Information",
            module=module,
            false_positive_risk="low",
            evidence=[Evidence(f"module:{module}:web-crawl", "Same-origin JS inventory.", 3, {"js_files": js_list})],
            category=FindingCategory.INFORMATION,
            tags=["web-crawl", "javascript"],
        ))

    endpoints = sorted(result.endpoints)
    if endpoints:
        findings.append(Finding(
            title="Interesting Endpoints Discovered via Crawl",
            severity=Severity.LOW,
            asset=host,
            port=port,
            protocol=protocol,
            service=service,
            description=f"{len(endpoints)} endpoint(s)/API path(s) referenced in crawled content.",
            recommendation="Use discovered endpoints for content fuzzing, parameter discovery, and template checks.",
            confidence=Confidence.CONFIRMED,
            evidence_strength=3,
            type="Information",
            module=module,
            false_positive_risk="low",
            evidence=[Evidence(
                f"module:{module}:web-crawl",
                "Endpoints extracted from HTML/JS.",
                3,
                {"endpoints": endpoints[:80], "pages": len(result.pages), "req_s": round(result.req_s, 2)},
            )],
            category=FindingCategory.INFORMATION,
            tags=["web-crawl", "endpoints"],
        ))

    if result.forms:
        findings.append(Finding(
            title="Forms and Parameters Discovered via Crawl",
            severity=Severity.INFO,
            asset=host,
            port=port,
            protocol=protocol,
            service=service,
            description=f"{len(result.forms)} form(s) discovered with input names.",
            recommendation="Use form actions and input names as parameter-discovery seed material.",
            confidence=Confidence.CONFIRMED,
            evidence_strength=3,
            type="Information",
            module=module,
            false_positive_risk="low",
            evidence=[Evidence(f"module:{module}:web-crawl", "Forms extracted from HTML.", 3, {"forms": result.forms[:50]})],
            category=FindingCategory.INFORMATION,
            tags=["web-crawl", "forms", "param-discovery"],
        ))

    return findings


async def _request_url_compat(client: PoliteHttpClient, url: str, timeout: float, allow_redirects: bool) -> PoliteResponse:
    request_url_async = getattr(client, "request_url_async", None)
    if request_url_async:
        return await request_url_async(url, timeout=timeout, allow_redirects=allow_redirects)
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    response = client.request(parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80), "GET", path, parsed.scheme == "https", timeout)
    return response


def _extract_links(body: str) -> list[str]:
    parser = _parse_links(body)
    links = list(parser.links)
    for js in _JS_URL_RE.findall(body):
        links.append(js)
    return [link for link in links if _valid_link(link)]


def _parse_links(body: str) -> _LinkParser:
    parser = _LinkParser()
    try:
        parser.feed(body[:1_000_000])
    except Exception:
        pass
    return parser


def _valid_link(link: str) -> bool:
    lower = link.strip().lower()
    return bool(lower) and not lower.startswith(("mailto:", "tel:", "javascript:", "#", "data:"))


def _crawlable_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    static_ext = (
        ".css", ".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz",
    )
    return not path.endswith(static_ext)


def _parse_robots_disallow(text: str) -> set[str]:
    disallow: set[str] = set()
    applies = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key = key.lower()
        if key == "user-agent":
            applies = value == "*"
        elif key == "disallow" and applies and value:
            disallow.add(value)
    return disallow


def _blocked_by_robots(url: str, disallow: set[str]) -> bool:
    path = urlparse(url).path or "/"
    return any(path.startswith(rule) for rule in disallow if rule != "/")


def _same_origin(url: str, host_or_base: str, port: int | None = None) -> bool:
    parsed = urlparse(url)
    if not parsed.netloc:
        return True
    if port is not None:
        target_host = parsed.hostname or ""
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return target_host == host_or_base and target_port == port
    base = urlparse(host_or_base)
    if not base.netloc:
        return parsed.hostname == host_or_base
    return (parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)) == (
        base.hostname,
        base.port or (443 if base.scheme == "https" else 80),
    )


def _redact(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:4] + "***" + value[-4:]

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.modules.http.surface import DiscoveredSurface, normalize_url
from portwise.utils.http_client import PoliteHttpClient


@dataclass(slots=True)
class ArchiveDiscoveryResult:
    domain: str
    urls: set[str] = field(default_factory=set)
    by_source: dict[str, set[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    elapsed_s: float = 0.0

    @property
    def req_s(self) -> float:
        total = sum(len(v) for v in self.by_source.values())
        return total / self.elapsed_s if self.elapsed_s > 0 else 0.0


class ArchiveUrlDiscovery:
    def __init__(
        self,
        client: PoliteHttpClient | None = None,
        timeout: float = 12.0,
        max_urls: int = 500,
        max_commoncrawl_indexes: int = 2,
    ) -> None:
        self.client = client or PoliteHttpClient()
        self.timeout = timeout
        self.max_urls = max_urls
        self.max_commoncrawl_indexes = max_commoncrawl_indexes

    async def discover(self, domain: str) -> ArchiveDiscoveryResult:
        started = time.perf_counter()
        result = ArchiveDiscoveryResult(domain=domain)
        tasks = [
            self._wayback(domain),
            self._commoncrawl(domain),
            self._otx(domain),
            self._urlscan(domain),
        ]
        names = ["wayback", "commoncrawl", "otx", "urlscan"]
        outputs = await asyncio.gather(*tasks, return_exceptions=True)
        for name, output in zip(names, outputs):
            if isinstance(output, Exception):
                result.errors[name] = str(output)
                continue
            result.by_source[name] = set(list(output)[: self.max_urls])
            result.urls.update(result.by_source[name])
        result.elapsed_s = time.perf_counter() - started
        return result

    async def _fetch_text(self, url: str) -> str:
        response = await self.client.request_url_async(url, timeout=self.timeout)
        if response.status >= 400:
            raise OSError(f"HTTP {response.status} from {url}")
        return response.read().decode("utf-8", errors="replace")

    async def _wayback(self, domain: str) -> set[str]:
        params = urlencode({
            "url": domain,
            "matchType": "host",
            "output": "json",
            "fl": "original,statuscode,mimetype,timestamp",
            "collapse": "urlkey",
            "filter": "statuscode:200",
            "limit": str(self.max_urls),
        })
        text = await self._fetch_text(f"https://web.archive.org/cdx/search/cdx?{params}")
        data = json.loads(text)
        rows = data[1:] if data and isinstance(data[0], list) else data
        urls = set()
        for row in rows:
            if isinstance(row, list) and row:
                urls.add(normalize_url(str(row[0])))
        return urls

    async def _commoncrawl(self, domain: str) -> set[str]:
        indexes_text = await self._fetch_text("https://index.commoncrawl.org/collinfo.json")
        indexes = json.loads(indexes_text)
        urls: set[str] = set()
        for index in indexes[: self.max_commoncrawl_indexes]:
            api = index.get("cdx-api")
            if not api:
                continue
            params = urlencode({
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "url,status,mime,timestamp",
                "filter": "status:200",
                "limit": str(max(1, self.max_urls // self.max_commoncrawl_indexes)),
            })
            try:
                text = await self._fetch_text(f"{api}?{params}")
            except Exception:
                continue
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = item.get("url")
                if url:
                    urls.add(normalize_url(str(url)))
        return urls

    async def _otx(self, domain: str) -> set[str]:
        params = urlencode({"limit": str(self.max_urls), "page": "1"})
        text = await self._fetch_text(f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?{params}")
        data = json.loads(text)
        urls: set[str] = set()
        for item in data.get("url_list", []):
            url = item.get("url") if isinstance(item, dict) else item
            if url:
                urls.add(normalize_url(str(url)))
        return urls

    async def _urlscan(self, domain: str) -> set[str]:
        params = urlencode({"q": f"domain:{domain}", "size": str(min(self.max_urls, 100))})
        text = await self._fetch_text(f"https://urlscan.io/api/v1/search/?{params}")
        data = json.loads(text)
        urls: set[str] = set()
        for item in data.get("results", []):
            page = item.get("page") if isinstance(item, dict) else {}
            task = item.get("task") if isinstance(item, dict) else {}
            page = page if isinstance(page, dict) else {}
            task = task if isinstance(task, dict) else {}
            for url in (page.get("url"), task.get("url")):
                if url:
                    urls.add(normalize_url(str(url)))
        return urls


def archive_finding(domain: str, result: ArchiveDiscoveryResult, target: dict[str, Any], module: str = "http") -> Finding | None:
    if not result.urls:
        return None
    evidence = Evidence(
        f"module:{module}:archive-discovery",
        "Historical URLs collected from public archives.",
        3,
        {
            "domain": domain,
            "count": len(result.urls),
            "sources": {source: len(urls) for source, urls in result.by_source.items()},
            "sample": sorted(result.urls)[:100],
            "errors": result.errors,
            "req_s": round(result.req_s, 2),
        },
    )
    return Finding(
        title="Historical URLs Discovered from Public Archives",
        severity=Severity.INFO,
        asset=str(target.get("host", domain)),
        port=target.get("port"),
        protocol=str(target.get("protocol", "tcp")),
        service=str(target.get("service", "http")),
        description=f"Found {len(result.urls)} historical URL(s) for {domain} across public archives.",
        recommendation="Use archived endpoints as input to content fuzzing, parameter testing, and template checks.",
        confidence=Confidence.CONFIRMED,
        evidence_strength=3,
        type="Information",
        module=module,
        false_positive_risk="low",
        manual_validation=False,
        evidence=[evidence],
        category=FindingCategory.INFORMATION,
        tags=["archive-discovery", "url-discovery"],
    )


async def run_archive_url_discovery_async(
    domain: str,
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
    surface: DiscoveredSurface,
    module: str = "http",
) -> list[Finding]:
    cfg = config.get("web_archive_discovery", {}) if isinstance(config.get("web_archive_discovery"), dict) else {}
    discovery = ArchiveUrlDiscovery(
        client=client,
        timeout=float(cfg.get("timeout", 12.0)),
        max_urls=int(cfg.get("max_urls", 500)),
        max_commoncrawl_indexes=int(cfg.get("max_commoncrawl_indexes", 2)),
    )
    result = await discovery.discover(domain)
    for url in result.urls:
        surface.archive_urls.add(url)
        surface.add_url(url, "archive")
    finding = archive_finding(domain, result, target, module=module)
    return [finding] if finding else []

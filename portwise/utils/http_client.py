from __future__ import annotations

import asyncio
import inspect
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

_CHROME_146_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)

_CHROME_BROWSER_HEADERS: tuple[tuple[str, str], ...] = (
    ("Sec-CH-UA", '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"'),
    ("Sec-CH-UA-Mobile", "?0"),
    ("Sec-CH-UA-Platform", '"macOS"'),
    ("Upgrade-Insecure-Requests", "1"),
    ("User-Agent", _CHROME_146_UA),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br, zstd"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Priority", "u=0, i"),
)

_RATE_LIMIT_HEADERS = {
    "retry-after",
    "x-ratelimit-reset",
    "x-rate-limit-reset",
    "x-ratelimit-remaining",
    "x-rate-limit-remaining",
}

_RATE_LIMIT_BODY_MARKERS = (
    "rate limit",
    "too many requests",
    "temporarily blocked",
    "slow down",
)

_JS_CHALLENGE_MARKERS = (
    "just a moment",
    "__cf_chl",
    "cf-browser-verification",
    "cf-challenge",
    "checking your browser",
    "ddos protection by cloudflare",
)

_ACCESS_BLOCK_MARKERS = (
    "access denied",
    "forbidden",
    "request blocked",
    "waf",
    "cloudflare",
    "akamai",
    "imperva",
    "distil",
)


@dataclass
class PolitenessConfig:
    min_delay: float = 0.5
    jitter_min: float = 0.1
    jitter_max: float = 0.4
    max_retries: int = 2
    backoff_base: float = 1.0
    backoff_max: float = 30.0
    circuit_breaker_threshold: int = 3
    max_requests_per_host: int = 30
    respect_retry_after: bool = True
    max_concurrency: int = 10
    impersonate: str = "chrome"
    browser_profiles: tuple[str, ...] = ("chrome",)
    rotate_profiles: bool = False
    proxy: str | None = None
    proxies: dict[str, str] | None = None
    proxy_auth: tuple[str, str] | None = None
    max_redirects: int = 5
    max_body_bytes: int = 1_048_576
    verify_tls: bool = False
    playwright_fallback: bool = True
    user_agent: str = field(default_factory=lambda: _CHROME_146_UA)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolitenessConfig:
        jitter = data.get("jitter_seconds", [0.1, 0.4])
        j_min = float(jitter[0]) if isinstance(jitter, (list, tuple)) else 0.1
        j_max = float(jitter[1]) if isinstance(jitter, (list, tuple)) and len(jitter) > 1 else 0.4
        proxy_auth = data.get("proxy_auth")
        auth_tuple = tuple(proxy_auth) if isinstance(proxy_auth, (list, tuple)) and len(proxy_auth) == 2 else None
        profiles = data.get("browser_profiles", data.get("impersonate_profiles", ["chrome"]))
        if isinstance(profiles, str):
            profile_tuple = (profiles,)
        elif isinstance(profiles, (list, tuple)) and profiles:
            profile_tuple = tuple(str(item) for item in profiles)
        else:
            profile_tuple = ("chrome",)
        impersonate = str(data.get("impersonate", data.get("browser_profile", profile_tuple[0])))
        return cls(
            min_delay=float(data.get("min_delay_seconds", 0.5)),
            jitter_min=j_min,
            jitter_max=j_max,
            max_retries=int(data.get("max_retries", 2)),
            backoff_base=float(data.get("backoff_base_seconds", 1.0)),
            backoff_max=float(data.get("backoff_max_seconds", 30.0)),
            circuit_breaker_threshold=int(data.get("circuit_breaker_threshold", 3)),
            max_requests_per_host=int(data.get("max_requests_per_host", 30)),
            respect_retry_after=bool(data.get("respect_retry_after", True)),
            max_concurrency=int(data.get("max_concurrency", data.get("concurrency", 10))),
            impersonate=impersonate,
            browser_profiles=profile_tuple,
            rotate_profiles=bool(data.get("rotate_profiles", False)),
            proxy=str(data.get("proxy") or "") or None,
            proxies=dict(data.get("proxies") or {}) or None,
            proxy_auth=auth_tuple,
            max_redirects=int(data.get("max_redirects", 5)),
            max_body_bytes=int(data.get("max_body_bytes", 1_048_576)),
            verify_tls=bool(data.get("verify_tls", False)),
            playwright_fallback=bool(data.get("playwright_fallback", True)),
            user_agent=str(data.get("user_agent", _CHROME_146_UA)),
        )

    def for_polite_mode(self) -> PolitenessConfig:
        return PolitenessConfig(
            min_delay=self.min_delay * 4,
            jitter_min=self.jitter_min * 4,
            jitter_max=self.jitter_max * 4,
            max_retries=self.max_retries,
            backoff_base=self.backoff_base,
            backoff_max=self.backoff_max,
            circuit_breaker_threshold=self.circuit_breaker_threshold,
            max_requests_per_host=max(5, self.max_requests_per_host // 2),
            respect_retry_after=self.respect_retry_after,
            max_concurrency=max(1, self.max_concurrency // 2),
            impersonate=self.impersonate,
            browser_profiles=self.browser_profiles,
            rotate_profiles=self.rotate_profiles,
            proxy=self.proxy,
            proxies=self.proxies,
            proxy_auth=self.proxy_auth,
            max_redirects=self.max_redirects,
            max_body_bytes=self.max_body_bytes,
            verify_tls=self.verify_tls,
            playwright_fallback=self.playwright_fallback,
            user_agent=self.user_agent,
        )

    def for_aggressive_mode(self) -> PolitenessConfig:
        return PolitenessConfig(
            min_delay=0.05,
            jitter_min=0.0,
            jitter_max=0.05,
            max_retries=1,
            backoff_base=0.5,
            backoff_max=5.0,
            circuit_breaker_threshold=self.circuit_breaker_threshold,
            max_requests_per_host=self.max_requests_per_host * 2,
            respect_retry_after=False,
            max_concurrency=max(10, self.max_concurrency),
            impersonate=self.impersonate,
            browser_profiles=self.browser_profiles,
            rotate_profiles=self.rotate_profiles,
            proxy=self.proxy,
            proxies=self.proxies,
            proxy_auth=self.proxy_auth,
            max_redirects=self.max_redirects,
            max_body_bytes=self.max_body_bytes,
            verify_tls=self.verify_tls,
            playwright_fallback=self.playwright_fallback,
            user_agent=self.user_agent,
        )


class PoliteResponse:
    """Drop-in replacement for http.client.HTTPResponse with pre-buffered body."""

    __slots__ = ("status", "_raw_headers", "_body", "_headers_lower", "request_meta")

    def __init__(
        self,
        status: int,
        raw_headers: list[tuple[str, str]],
        body: bytes,
        request_meta: dict | None = None,
    ) -> None:
        self.status = status
        self._raw_headers = list(raw_headers)
        self._body = body
        self._headers_lower = {k.lower(): v for k, v in raw_headers}
        self.request_meta: dict = request_meta or {}

    def getheaders(self) -> list[tuple[str, str]]:
        return self._raw_headers

    def getheader(self, name: str, default: str = "") -> str:
        return self._headers_lower.get(name.lower(), default)

    def read(self, n: int = -1) -> bytes:
        return self._body[:n] if n >= 0 else self._body

    def to_evidence(self, source: str, description: str, strength: int, body_cap: int = 2048):
        from portwise.core.models import Evidence

        meta = self.request_meta
        return Evidence.with_transcript(
            source=source,
            description=description,
            strength=strength,
            method=meta.get("method", "GET"),
            url=meta.get("url", ""),
            request_headers=meta.get("headers_sent", {}),
            response_status=self.status,
            response_headers=self._raw_headers,
            response_body=self._body,
            timing_ms=meta.get("timing_ms", 0),
            observed_at=meta.get("observed_at"),
            body_cap=body_cap,
        )


@dataclass(slots=True)
class TransportResult:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    url: str
    profile: str
    used_playwright: bool = False
    blocked: bool = False


class CurlCffiTransport:
    """Shared async HTTP transport: curl_cffi impersonation, pool, cookies, proxy."""

    def __init__(self, config: PolitenessConfig) -> None:
        self.config = config
        self._session: Any | None = None
        self._session_loop: asyncio.AbstractEventLoop | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._profile_index = 0
        self._playwright_cookies: dict[str, dict[str, str]] = {}

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
            self._session_loop = None
            self._semaphore = None

    async def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        timeout: float = 10.0,
        connect_host: str | None = None,
        resolve_host: str | None = None,
        host_key: str | None = None,
        allow_playwright: bool = True,
    ) -> TransportResult:
        semaphore = self._semaphore or asyncio.Semaphore(self.config.max_concurrency)
        self._semaphore = semaphore
        profile = self._next_profile()
        curl_options = self._curl_options(url, connect_host, resolve_host)
        session = await self._get_session(curl_options if curl_options else None)
        close_after = bool(curl_options)
        cookies = self._playwright_cookies.get(host_key or urlsplit(url).hostname or "")
        request_headers = dict(headers or {})

        try:
            async with semaphore:
                response = await session.request(
                    method.upper(),
                    url,
                    headers=request_headers or None,
                    data=body,
                    timeout=timeout,
                    allow_redirects=True,
                    max_redirects=self.config.max_redirects,
                    impersonate=profile,
                    default_headers=True,
                    verify=self.config.verify_tls,
                    cookies=cookies or None,
                    stream=False,
                )
        finally:
            if close_after:
                await session.close()

        raw_headers = list(response.headers.items())
        content = bytes(response.content or b"")[: self.config.max_body_bytes]
        result = TransportResult(
            status=int(response.status_code),
            headers=raw_headers,
            body=content,
            url=str(getattr(response, "url", url) or url),
            profile=profile,
            blocked=_looks_access_blocked(int(response.status_code), raw_headers, content),
        )

        if (
            allow_playwright
            and self.config.playwright_fallback
            and _looks_js_challenge(result.status, result.headers, result.body)
        ):
            solved = await self._solve_with_playwright(url, request_headers, timeout, host_key or "")
            if solved:
                retry = await self.request(
                    method=method,
                    url=url,
                    headers=headers,
                    body=body,
                    timeout=timeout,
                    connect_host=connect_host,
                    resolve_host=resolve_host,
                    host_key=host_key,
                    allow_playwright=False,
                )
                retry.used_playwright = True
                return retry

        return result

    async def _get_session(self, curl_options: dict[Any, Any] | None = None) -> Any:
        if curl_options:
            from curl_cffi.requests import AsyncSession

            return AsyncSession(
                max_clients=1,
                proxy=self.config.proxy,
                proxies=self.config.proxies,
                proxy_auth=self.config.proxy_auth,
                verify=self.config.verify_tls,
                timeout=30,
                allow_redirects=True,
                max_redirects=self.config.max_redirects,
                impersonate=self.config.impersonate,
                default_headers=True,
                trust_env=True,
                curl_options=curl_options,
            )

        loop = asyncio.get_running_loop()
        if self._session is not None and self._session_loop is loop:
            return self._session

        if self._session is not None:
            await self._session.close()

        from curl_cffi.requests import AsyncSession

        self._session = AsyncSession(
            max_clients=self.config.max_concurrency,
            proxy=self.config.proxy,
            proxies=self.config.proxies,
            proxy_auth=self.config.proxy_auth,
            verify=self.config.verify_tls,
            timeout=30,
            allow_redirects=True,
            max_redirects=self.config.max_redirects,
            impersonate=self.config.impersonate,
            default_headers=True,
            trust_env=True,
        )
        self._session_loop = loop
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        return self._session

    def _next_profile(self) -> str:
        profiles = self.config.browser_profiles or (self.config.impersonate,)
        if not self.config.rotate_profiles:
            return self.config.impersonate or profiles[0]
        profile = profiles[self._profile_index % len(profiles)]
        self._profile_index += 1
        return profile

    @staticmethod
    def _curl_options(url: str, connect_host: str | None, resolve_host: str | None) -> dict[Any, Any]:
        if not connect_host or not resolve_host:
            return {}
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.hostname != resolve_host:
            return {}
        from curl_cffi import CurlOpt

        return {CurlOpt.RESOLVE: [f"{resolve_host}:{port}:{connect_host}"]}

    async def _solve_with_playwright(
        self,
        url: str,
        headers: dict[str, str],
        timeout: float,
        host_key: str,
    ) -> bool:
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return False

        proxy = self.config.proxy or (self.config.proxies or {}).get("https") or (self.config.proxies or {}).get("http")
        launch_kwargs: dict[str, Any] = {"headless": True}
        if proxy:
            launch_kwargs["proxy"] = {"server": proxy}

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(**launch_kwargs)
                context = await browser.new_context(
                    user_agent=self.config.user_agent,
                    extra_http_headers={
                        "Accept-Language": "en-US,en;q=0.9",
                    },
                    ignore_https_errors=not self.config.verify_tls,
                )
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=max(1.0, timeout) * 1000)
                await page.wait_for_load_state("networkidle", timeout=max(1.0, timeout) * 1000)
                cookies = await context.cookies()
                await browser.close()
        except Exception:
            return False

        harvested = {
            str(cookie.get("name")): str(cookie.get("value"))
            for cookie in cookies
            if cookie.get("name") and cookie.get("value") is not None
        }
        if harvested and host_key:
            self._playwright_cookies[host_key] = harvested
            return True
        return False


class PoliteHttpClient:
    """
    Shared PortWise HTTP client.

    Public sync methods remain for current modules. The execution path is an
    async curl_cffi transport with browser impersonation, pooling, cookies,
    redirects, proxies, optional Playwright challenge clearing, and per-host
    politeness/rate-limit state owned by this client instance.
    """

    def __init__(
        self,
        config: PolitenessConfig | None = None,
        transport: CurlCffiTransport | None = None,
    ) -> None:
        self.config = config or PolitenessConfig()
        self.transport = transport or CurlCffiTransport(self.config)
        self._last_request_time: dict[str, float] = {}
        self._consecutive_rate_limits: dict[str, int] = {}
        self._tripped: set[str] = set()
        self._request_count: dict[str, int] = {}
        self._host_locks: dict[str, asyncio.Lock] = {}
        self.vhost: str | None = None
        self.sni: str | None = None

    def is_tripped(self, host: str) -> bool:
        return host in self._tripped

    def budget_remaining(self, host: str) -> int:
        return max(0, self.config.max_requests_per_host - self._request_count.get(host, 0))

    def throttle(self, host: str) -> None:
        self._apply_delay(host)

    async def throttle_async(self, host: str) -> None:
        await self._apply_delay_async(host)

    def browser_headers(self) -> list[tuple[str, str]]:
        return list(_CHROME_BROWSER_HEADERS)

    def is_access_blocked(self, response: PoliteResponse) -> bool:
        return _looks_access_blocked(response.status, response.getheaders(), response.read(4096))

    def request(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        tls: bool,
        timeout: float = 10.0,
        host_header: str | None = None,
        sni: str | None = None,
        extra_headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
    ) -> PoliteResponse:
        return _run_sync(self.request_async(
            host,
            port,
            method,
            path,
            tls,
            timeout=timeout,
            host_header=host_header,
            sni=sni,
            extra_headers=extra_headers,
            body=body,
        ))

    async def request_async(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        tls: bool,
        timeout: float = 10.0,
        host_header: str | None = None,
        sni: str | None = None,
        extra_headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
    ) -> PoliteResponse:
        host_header = host_header or self.vhost
        sni = sni or self.sni
        if self.is_tripped(host):
            raise OSError(
                f"[PortWise] Circuit breaker tripped for {host}: target is returning "
                "explicit rate-limit signals; backed off to avoid disruption."
            )
        if self._request_count.get(host, 0) >= self.config.max_requests_per_host:
            raise OSError(f"[PortWise] Request budget exhausted for {host}.")

        await self._apply_delay_async(host)
        self._request_count[host] = self._request_count.get(host, 0) + 1

        url, resolve_host = self._url(host, port, path, tls, host_header, sni)
        headers_sent = dict(self.browser_headers())
        if host_header:
            headers_sent["Host"] = host_header
        if extra_headers:
            headers_sent.update(extra_headers)
        request_headers = dict(extra_headers or {})
        t_start = time.monotonic()
        last_exc: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            try:
                result = await self._execute_request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    body=body,
                    timeout=timeout,
                    connect_host=host if resolve_host else None,
                    resolve_host=resolve_host,
                    host_key=host,
                )
                timing_ms = int((time.monotonic() - t_start) * 1000)
                meta = {
                    "method": method.upper(),
                    "url": url,
                    "headers_sent": headers_sent,
                    "timing_ms": timing_ms,
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "impersonate": result.profile,
                    "used_playwright": result.used_playwright,
                    "blocked": result.blocked,
                }
                if _is_rate_limited(result.status, result.headers, result.body):
                    if attempt < self.config.max_retries:
                        await asyncio.sleep(self._compute_backoff(attempt, result.headers))
                        continue
                    if self._record_rate_limit(host):
                        raise OSError(
                            f"[PortWise] Circuit breaker tripped for {host}: "
                            "target is returning explicit rate-limit signals."
                        )
                    return PoliteResponse(result.status, result.headers, result.body, meta)

                self._reset_rate_limits(host)
                return PoliteResponse(result.status, result.headers, result.body, meta)
            except OSError as exc:
                if "[PortWise]" in str(exc):
                    raise
                last_exc = exc
                if attempt < self.config.max_retries:
                    await asyncio.sleep(self._compute_backoff(attempt, []))
                    continue
                raise

        raise last_exc or OSError("Request failed after retries.")

    def request_url(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        timeout: float = 10.0,
    ) -> PoliteResponse:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Unsupported HTTP URL: {url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        return self.request(
            parsed.hostname,
            port,
            method,
            path,
            parsed.scheme == "https",
            timeout=timeout,
            host_header=parsed.hostname,
            sni=parsed.hostname if parsed.scheme == "https" else None,
            extra_headers=headers,
            body=body,
        )

    async def _execute_request(self, **kwargs: Any) -> TransportResult:
        maybe_result = self.transport.request(**kwargs)
        if inspect.isawaitable(maybe_result):
            return await maybe_result
        return maybe_result

    def _apply_delay(self, host: str) -> None:
        now = time.monotonic()
        last = self._last_request_time.get(host, 0.0)
        elapsed = now - last
        delay = self.config.min_delay + random.uniform(self.config.jitter_min, self.config.jitter_max)
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_time[host] = time.monotonic()

    async def _apply_delay_async(self, host: str) -> None:
        lock = self._host_locks.setdefault(host, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            last = self._last_request_time.get(host, 0.0)
            elapsed = now - last
            delay = self.config.min_delay + random.uniform(self.config.jitter_min, self.config.jitter_max)
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)
            self._last_request_time[host] = time.monotonic()

    def _compute_backoff(self, attempt: int, raw_headers: list[tuple[str, str]]) -> float:
        if self.config.respect_retry_after:
            for key, value in raw_headers:
                if key.lower() == "retry-after":
                    try:
                        return max(float(value), self.config.backoff_base)
                    except ValueError:
                        pass
        return min(
            self.config.backoff_base * (2 ** attempt) + random.uniform(0.0, 1.0),
            self.config.backoff_max,
        )

    def _record_rate_limit(self, host: str) -> bool:
        count = self._consecutive_rate_limits.get(host, 0) + 1
        self._consecutive_rate_limits[host] = count
        if count >= self.config.circuit_breaker_threshold:
            self._tripped.add(host)
            return True
        return False

    def _reset_rate_limits(self, host: str) -> None:
        self._consecutive_rate_limits[host] = 0

    @staticmethod
    def _url(
        host: str,
        port: int,
        path: str,
        tls: bool,
        host_header: str | None,
        sni: str | None,
    ) -> tuple[str, str | None]:
        from portwise.utils.net import bracket_host

        scheme = "https" if tls else "http"
        url_host = sni or host_header or host
        resolve_host = url_host if url_host != host else None
        return f"{scheme}://{bracket_host(url_host)}:{port}{path}", resolve_host


def client_from_config(config: dict[str, Any]) -> PoliteHttpClient:
    """Build a PoliteHttpClient from a PortWise config dict."""
    politeness_data = config.get("http_politeness", {})
    transport_data = config.get("http_transport", {})
    merged: dict[str, Any] = {}
    if isinstance(politeness_data, dict):
        merged.update(politeness_data)
    if isinstance(transport_data, dict):
        merged.update(transport_data)
    http_cfg = config.get("http", {})
    if isinstance(http_cfg, dict):
        for key in ("max_redirects", "max_body_bytes"):
            if key in http_cfg and key not in merged:
                merged[key] = http_cfg[key]
    base = PolitenessConfig.from_dict(merged)
    mode = str(config.get("politeness_mode", "balanced"))
    if mode == "polite":
        return PoliteHttpClient(base.for_polite_mode())
    if mode == "aggressive":
        return PoliteHttpClient(base.for_aggressive_mode())
    return PoliteHttpClient(base)


def _run_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}
    error: dict[str, BaseException] = {}

    def runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:
            error["value"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error["value"]
    return result.get("value")


def _is_rate_limited(status: int, raw_headers: list[tuple[str, str]], body: bytes) -> bool:
    headers = {key.lower(): value for key, value in raw_headers}
    if status == 429:
        return True
    if status != 403:
        return False
    if any(key in headers for key in _RATE_LIMIT_HEADERS):
        return True
    text = body[:4096].decode("utf-8", errors="ignore").lower()
    return any(marker in text for marker in _RATE_LIMIT_BODY_MARKERS)


def _looks_js_challenge(status: int, raw_headers: list[tuple[str, str]], body: bytes) -> bool:
    if status not in {403, 429, 503}:
        return False
    headers = {key.lower(): value.lower() for key, value in raw_headers}
    server = headers.get("server", "")
    text = body[:8192].decode("utf-8", errors="ignore").lower()
    return "cloudflare" in server or any(marker in text for marker in _JS_CHALLENGE_MARKERS)


def _looks_access_blocked(status: int, raw_headers: list[tuple[str, str]], body: bytes) -> bool:
    if status in {401, 407}:
        return False
    if status in {403, 429}:
        return True
    if status not in {451, 503}:
        return False
    headers = {key.lower(): value.lower() for key, value in raw_headers}
    server = headers.get("server", "")
    text = body[:8192].decode("utf-8", errors="ignore").lower()
    return any(marker in server for marker in _ACCESS_BLOCK_MARKERS) or any(
        marker in text for marker in _ACCESS_BLOCK_MARKERS
    )

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/137.0.0.0 Safari/537.36"
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
    user_agent: str = field(default_factory=lambda: _BROWSER_UA)
    respect_retry_after: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolitenessConfig:
        jitter = data.get("jitter_seconds", [0.1, 0.4])
        j_min = float(jitter[0]) if isinstance(jitter, (list, tuple)) else 0.1
        j_max = float(jitter[1]) if isinstance(jitter, (list, tuple)) and len(jitter) > 1 else 0.4
        return cls(
            min_delay=float(data.get("min_delay_seconds", 0.5)),
            jitter_min=j_min,
            jitter_max=j_max,
            max_retries=int(data.get("max_retries", 2)),
            backoff_base=float(data.get("backoff_base_seconds", 1.0)),
            backoff_max=float(data.get("backoff_max_seconds", 30.0)),
            circuit_breaker_threshold=int(data.get("circuit_breaker_threshold", 3)),
            max_requests_per_host=int(data.get("max_requests_per_host", 30)),
            user_agent=str(data.get("user_agent", _BROWSER_UA)),
            respect_retry_after=bool(data.get("respect_retry_after", True)),
        )

    def for_polite_mode(self) -> PolitenessConfig:
        """4× delays, halved budget — for sensitive targets."""
        return PolitenessConfig(
            min_delay=self.min_delay * 4,
            jitter_min=self.jitter_min * 4,
            jitter_max=self.jitter_max * 4,
            max_retries=self.max_retries,
            backoff_base=self.backoff_base,
            backoff_max=self.backoff_max,
            circuit_breaker_threshold=self.circuit_breaker_threshold,
            max_requests_per_host=max(5, self.max_requests_per_host // 2),
            user_agent=self.user_agent,
            respect_retry_after=self.respect_retry_after,
        )

    def for_aggressive_mode(self) -> PolitenessConfig:
        """Minimal delays — for authorized lab/CTF use only."""
        return PolitenessConfig(
            min_delay=0.05,
            jitter_min=0.0,
            jitter_max=0.05,
            max_retries=1,
            backoff_base=0.5,
            backoff_max=5.0,
            circuit_breaker_threshold=self.circuit_breaker_threshold,
            max_requests_per_host=self.max_requests_per_host * 2,
            user_agent=self.user_agent,
            respect_retry_after=False,
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
        # Stores {method, url, headers_sent, timing_ms, observed_at}
        self.request_meta: dict = request_meta or {}

    def getheaders(self) -> list[tuple[str, str]]:
        return self._raw_headers

    def getheader(self, name: str, default: str = "") -> str:
        return self._headers_lower.get(name.lower(), default)

    def read(self, n: int = -1) -> bytes:
        return self._body[:n] if n >= 0 else self._body

    def to_evidence(self, source: str, description: str, strength: int, body_cap: int = 2048):
        """Create an Evidence object with a sanitized transcript from this response."""
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


class PoliteHttpClient:
    """
    Rate-limiting, circuit-breaking HTTP client for safe VAPT checks.

    Features:
    - Per-host min delay + random jitter between requests
    - requests.Session per host (connection reuse); urllib fallback
    - Exponential backoff + jitter on 429 / 403
    - Circuit breaker: after N consecutive blocks → raise OSError and stop
    - Per-host request budget cap
    - Configurable user-agent
    """

    def __init__(self, config: PolitenessConfig | None = None) -> None:
        self.config = config or PolitenessConfig()
        self._last_request_time: dict[str, float] = {}
        self._consecutive_errors: dict[str, int] = {}
        self._tripped: set[str] = set()
        self._request_count: dict[str, int] = {}
        self._sessions: dict[str, Any] = {}
        # Optional name-based vhost defaults. When set, every request sends this
        # Host header and uses this SNI server name (for name-based / fronted
        # vhosts) while still connecting to the target IP. Per-call overrides win.
        self.vhost: str | None = None
        self.sni: str | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_tripped(self, host: str) -> bool:
        return host in self._tripped

    def budget_remaining(self, host: str) -> int:
        return max(0, self.config.max_requests_per_host - self._request_count.get(host, 0))

    def throttle(self, host: str) -> None:
        """Apply per-host delay + jitter without counting toward the budget."""
        self._apply_delay(host)

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
        """
        Perform a polite HTTP request.
        Raises OSError when circuit breaker trips or budget is exhausted.

        ``host_header``/``sni`` override (or fall back to) the per-client vhost/SNI
        defaults so name-based and TLS-fronted vhosts can be tested while still
        connecting to the target IP. ``extra_headers``/``body`` support authenticated
        checks (Basic auth, form login).
        """
        host_header = host_header or self.vhost
        sni = sni or self.sni
        if self.is_tripped(host):
            raise OSError(
                f"[PortWise] Circuit breaker tripped for {host}: host appears to be "
                "rate-limiting or blocking; backed off to avoid disruption."
            )
        if self._request_count.get(host, 0) >= self.config.max_requests_per_host:
            raise OSError(f"[PortWise] Request budget exhausted for {host}.")

        self._apply_delay(host)
        self._request_count[host] = self._request_count.get(host, 0) + 1

        from portwise.utils.net import bracket_host
        scheme = "https" if tls else "http"
        url = f"{scheme}://{bracket_host(host)}:{port}{path}"
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Upgrade-Insecure-Requests": "1",
            "Sec-CH-UA": '"Chromium";v="137", "Not/A)Brand";v="24", "Google Chrome";v="137"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Connection": "close",
        }
        if host_header:
            headers["Host"] = host_header
        if extra_headers:
            headers.update(extra_headers)
        t_start = time.monotonic()
        last_exc: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            try:
                status, raw_headers, resp_body = self._do_request(
                    host, port, method, path, tls, headers, timeout, sni=sni, body=body
                )
                body_out = resp_body
                timing_ms = int((time.monotonic() - t_start) * 1000)
                meta = {
                    "method": method.upper(),
                    "url": url,
                    "headers_sent": dict(headers),
                    "timing_ms": timing_ms,
                    "observed_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                }

                if status in (429, 403):
                    backoff = self._compute_backoff(
                        attempt, raw_headers if status == 429 else []
                    )
                    if attempt < self.config.max_retries:
                        time.sleep(backoff)
                        continue
                    # Final attempt — record as one error
                    if self._record_error(host):
                        raise OSError(
                            f"[PortWise] Circuit breaker tripped for {host}: "
                            "host appears to be rate-limiting or blocking."
                        )
                    return PoliteResponse(status, raw_headers, body_out, meta)

                self._reset_errors(host)
                return PoliteResponse(status, raw_headers, body_out, meta)

            except OSError as exc:
                if "[PortWise]" in str(exc):
                    raise
                last_exc = exc
                if attempt < self.config.max_retries:
                    time.sleep(self._compute_backoff(attempt, []))
                    continue
                # Final attempt — record as one error
                if self._record_error(host):
                    raise OSError(
                        f"[PortWise] Circuit breaker tripped for {host}: "
                        "host appears to be rate-limiting or blocking."
                    )
                raise

        raise last_exc or OSError("Request failed after retries.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_delay(self, host: str) -> None:
        now = time.monotonic()
        last = self._last_request_time.get(host, 0.0)
        elapsed = now - last
        delay = self.config.min_delay + random.uniform(
            self.config.jitter_min, self.config.jitter_max
        )
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_time[host] = time.monotonic()

    def _compute_backoff(self, attempt: int, raw_headers: list[tuple[str, str]]) -> float:
        if self.config.respect_retry_after:
            for k, v in raw_headers:
                if k.lower() == "retry-after":
                    try:
                        return max(float(v), self.config.backoff_base)
                    except ValueError:
                        pass
        jitter = random.uniform(0.0, 1.0)
        return min(
            self.config.backoff_base * (2 ** attempt) + jitter,
            self.config.backoff_max,
        )

    def _record_error(self, host: str) -> bool:
        """Increments error counter; returns True if circuit just tripped."""
        count = self._consecutive_errors.get(host, 0) + 1
        self._consecutive_errors[host] = count
        if count >= self.config.circuit_breaker_threshold:
            self._tripped.add(host)
            return True
        return False

    def _reset_errors(self, host: str) -> None:
        self._consecutive_errors[host] = 0

    def _get_session(self, host: str) -> Any:
        if host not in self._sessions:
            try:
                import requests as _req
                import urllib3  # type: ignore[import-untyped]
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                session = _req.Session()
                session.headers["User-Agent"] = self.config.user_agent
                self._sessions[host] = session
            except ImportError:
                self._sessions[host] = None  # triggers http.client fallback
        return self._sessions[host]

    def _do_request(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        tls: bool,
        headers: dict[str, str],
        timeout: float,
        sni: str | None = None,
        body: str | bytes | None = None,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        # When an explicit SNI is requested for an HTTPS target, use the stdlib
        # path with a manually wrapped socket so we connect to the IP but present
        # the vhost server name in the TLS handshake (name-based / fronted vhosts).
        if tls and sni:
            return self._do_request_sni(host, port, method, path, headers, timeout, sni, body=body)

        session = self._get_session(host)

        if session is not None:
            from portwise.utils.net import bracket_host
            scheme = "https" if tls else "http"
            url = f"{scheme}://{bracket_host(host)}:{port}{path}"
            resp = session.request(
                method, url, headers=headers, data=body,
                timeout=timeout, verify=False, allow_redirects=False,
            )
            content = resp.content[:1_048_576]
            return resp.status_code, list(resp.headers.items()), content

        # Fallback: stdlib http.client (no external deps)
        import ssl as _ssl
        from http.client import HTTPConnection, HTTPSConnection
        conn_cls = HTTPSConnection if tls else HTTPConnection
        kwargs: dict[str, Any] = {"timeout": timeout}
        if tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            kwargs["context"] = ctx
        conn = conn_cls(host, port=port, **kwargs)
        conn.request(method, path, body=body, headers=headers)
        resp_raw = conn.getresponse()
        content = resp_raw.read(1_048_576)
        return resp_raw.status, list(resp_raw.getheaders()), content

    def _do_request_sni(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        timeout: float,
        sni: str,
        body: str | bytes | None = None,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        """HTTPS request that connects to ``host`` (IP) but presents ``sni`` as the
        TLS server name. Used for name-based / Cloudflare-fronted vhosts."""
        import socket as _socket
        import ssl as _ssl
        from http.client import HTTPSConnection

        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        raw = _socket.create_connection((host, port), timeout=timeout)
        try:
            tls_sock = ctx.wrap_socket(raw, server_hostname=sni)
        except Exception:
            raw.close()
            raise
        conn = HTTPSConnection(host, port=port, timeout=timeout)
        conn.sock = tls_sock  # pre-wrapped socket; http.client skips its own connect
        try:
            conn.request(method, path, body=body, headers=headers)
            resp_raw = conn.getresponse()
            body = resp_raw.read(1_048_576)
            return resp_raw.status, list(resp_raw.getheaders()), body
        finally:
            conn.close()


def client_from_config(config: dict[str, Any]) -> PoliteHttpClient:
    """Build a PoliteHttpClient from a PortWise config dict, respecting politeness_mode."""
    politeness_data = config.get("http_politeness", {})
    base = PolitenessConfig.from_dict(politeness_data if isinstance(politeness_data, dict) else {})
    mode = str(config.get("politeness_mode", "balanced"))
    if mode == "polite":
        return PoliteHttpClient(base.for_polite_mode())
    if mode == "aggressive":
        return PoliteHttpClient(base.for_aggressive_mode())
    return PoliteHttpClient(base)

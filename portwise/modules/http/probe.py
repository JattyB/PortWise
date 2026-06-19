from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from portwise.utils.http_client import PoliteHttpClient, PoliteResponse


@dataclass(slots=True)
class HttpRedirectHop:
    url: str
    status: int
    location: str


@dataclass(slots=True)
class HttpProbeResult:
    url: str
    final_url: str
    status: int
    title: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed_ms: int
    body_sha256: str
    redirect_chain: list[HttpRedirectHop] = field(default_factory=list)
    blocked: bool = False

    @property
    def headers_lower(self) -> dict[str, str]:
        return {key.lower(): value for key, value in self.headers}


class AsyncHttpProber:
    def __init__(
        self,
        client: PoliteHttpClient | None = None,
        timeout: float = 5.0,
        max_body: int = 262_144,
        max_redirects: int | None = None,
    ) -> None:
        self.client = client or PoliteHttpClient()
        self.timeout = timeout
        self.max_body = max_body
        self.max_redirects = max_redirects

    async def probe_url(self, url: str) -> HttpProbeResult:
        redirects: list[HttpRedirectHop] = []
        current = url
        limit = self.max_redirects if self.max_redirects is not None else self.client.config.max_redirects
        started = time.monotonic()
        response: PoliteResponse | None = None

        for _ in range(max(0, limit) + 1):
            response = await self.client.request_url_async(
                current,
                method="GET",
                timeout=self.timeout,
                allow_redirects=False,
            )
            location = response.getheader("Location")
            if response.status not in {301, 302, 303, 307, 308} or not location:
                break
            redirects.append(HttpRedirectHop(current, response.status, location))
            current = urljoin(current, location)
        else:
            current = response.request_meta.get("url", current) if response else current

        if response is None:
            raise OSError(f"HTTP probe did not receive a response for {url}")

        body = response.read(self.max_body)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return HttpProbeResult(
            url=url,
            final_url=current,
            status=response.status,
            title=extract_title(body),
            headers=response.getheaders(),
            body=body,
            elapsed_ms=elapsed_ms,
            body_sha256=hashlib.sha256(body).hexdigest(),
            redirect_chain=redirects,
            blocked=self.client.is_access_blocked(response),
        )

    async def probe_service(self, host: str, port: int, tls: bool, path: str = "/") -> HttpProbeResult:
        scheme = "https" if tls else "http"
        url = f"{scheme}://{host}:{port}{path}"
        return await self.probe_url(url)


def extract_title(body: bytes | str) -> str:
    text = body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else body
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def url_origin(url: str) -> str:
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}://{parsed.hostname}:{port}"

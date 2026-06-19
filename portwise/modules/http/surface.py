from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit, urlunsplit


@dataclass(slots=True)
class DiscoveredEndpoint:
    url: str
    source: str
    method: str = "GET"
    status: int | None = None
    depth: int = 0
    params: set[str] = field(default_factory=set)


@dataclass(slots=True)
class DiscoveredSurface:
    target_key: str
    endpoints: dict[str, DiscoveredEndpoint] = field(default_factory=dict)
    parameters: dict[str, set[str]] = field(default_factory=dict)
    forms: list[dict[str, Any]] = field(default_factory=list)
    js_files: set[str] = field(default_factory=set)
    archive_urls: set[str] = field(default_factory=set)

    def add_url(self, url: str, source: str, method: str = "GET", status: int | None = None, depth: int = 0) -> str:
        normalized = normalize_url(url)
        parsed = urlsplit(normalized)
        params = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        existing = self.endpoints.get(normalized)
        if existing:
            existing.params.update(params)
            if existing.status is None:
                existing.status = status
            existing.depth = min(existing.depth, depth)
        else:
            self.endpoints[normalized] = DiscoveredEndpoint(
                url=normalized,
                source=source,
                method=method,
                status=status,
                depth=depth,
                params=params,
            )
        if params:
            base = strip_query(normalized)
            self.parameters.setdefault(base, set()).update(params)
        return normalized

    def add_param(self, endpoint_url: str, param: str) -> None:
        normalized = strip_query(normalize_url(endpoint_url))
        self.parameters.setdefault(normalized, set()).add(param)

    def add_form(self, page_url: str, action: str, method: str, inputs: list[str]) -> None:
        form_url = normalize_url(urljoin(page_url, action or page_url))
        self.forms.append({"page": page_url, "action": form_url, "method": method.upper(), "inputs": sorted(set(inputs))})
        self.add_url(form_url, "form", method=method.upper())
        for name in inputs:
            self.add_param(form_url, name)

    def as_evidence(self) -> dict[str, Any]:
        return {
            "endpoints": sorted(self.endpoints)[:200],
            "parameters": {url: sorted(params) for url, params in sorted(self.parameters.items())[:100]},
            "forms": self.forms[:50],
            "js_files": sorted(self.js_files)[:100],
            "archive_urls": sorted(self.archive_urls)[:200],
        }


def normalize_url(url: str) -> str:
    url, _fragment = urldefrag(url.strip())
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        return url
    port = ""
    if parsed.port and not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
        port = f":{parsed.port}"
    path = parsed.path or "/"
    query = parsed.query
    return urlunsplit((scheme, f"{host}{port}", path, query, ""))


def strip_query(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def surface_key(host: str, port: int | None = None) -> str:
    return f"{host}:{port}" if port else host


def surface_from_config(config: dict[str, Any], key: str) -> DiscoveredSurface:
    bucket = config.setdefault("_discovered_surface", {})
    surface = bucket.get(key)
    if isinstance(surface, DiscoveredSurface):
        return surface
    surface = DiscoveredSurface(target_key=key)
    bucket[key] = surface
    return surface

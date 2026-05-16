from __future__ import annotations

from urllib.parse import urlparse


def endpoint_url(host: str, port: int, tls: bool = False, path: str = "/") -> str:
    scheme = "https" if tls else "http"
    default_port = 443 if tls else 80
    port_part = "" if port == default_port else f":{port}"
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{scheme}://{host}{port_part}{path}"


def hostname_from_url(url: str) -> str:
    return urlparse(url).hostname or url

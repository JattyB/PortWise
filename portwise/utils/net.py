from __future__ import annotations

from urllib.parse import urlparse


def is_ipv6(host: str) -> bool:
    """True when host is an IPv6 literal (e.g. ::1, fe80::1) rather than a name
    or IPv4 address. A bracketed literal counts too."""
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        return True
    # IPv6 literals contain multiple colons; hostnames and IPv4 never do.
    return h.count(":") >= 2


def bracket_host(host: str) -> str:
    """Wrap an IPv6 literal in [...] for use in a URL authority. Names, IPv4
    addresses, and already-bracketed literals are returned unchanged."""
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        return h
    if is_ipv6(h):
        return f"[{h}]"
    return h


def endpoint_url(host: str, port: int, tls: bool = False, path: str = "/") -> str:
    scheme = "https" if tls else "http"
    default_port = 443 if tls else 80
    port_part = "" if port == default_port else f":{port}"
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{scheme}://{bracket_host(host)}{port_part}{path}"


def hostname_from_url(url: str) -> str:
    return urlparse(url).hostname or url

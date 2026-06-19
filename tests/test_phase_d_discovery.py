from __future__ import annotations

import asyncio
import sys

from portwise.modules.http.archive_discovery import ArchiveUrlDiscovery, run_archive_url_discovery_async
from portwise.modules.http.param_discovery import ActiveParameterDiscovery, extract_archive_parameters, run_active_parameter_discovery_async
from portwise.modules.http.surface import surface_from_config
from portwise.utils.http_client import PoliteResponse


class _ArchiveClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def request_url_async(self, url, timeout=10.0, allow_redirects=True, **kwargs):
        self.calls.append(url)
        if "web.archive.org/cdx" in url:
            return PoliteResponse(200, [], b'[["original","statuscode"],["http://example.com/a?id=1","200"]]', {})
        if "collinfo.json" in url:
            return PoliteResponse(200, [], b'[{"cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-01-index"}]', {})
        if "index.commoncrawl.org" in url:
            return PoliteResponse(200, [], b'{"url":"http://example.com/b?q=x","status":"200"}\n', {})
        if "otx.alienvault.com" in url:
            return PoliteResponse(200, [], b'{"url_list":[{"url":"http://example.com/c?cat=2"}]}', {})
        if "urlscan.io" in url:
            return PoliteResponse(200, [], b'{"results":[{"page":{"url":"http://example.com/d?page=3"}}]}', {})
        return PoliteResponse(404, [], b"", {})


def test_archive_discovery_merges_sources_and_populates_surface():
    client = _ArchiveClient()
    surface = surface_from_config({}, "example.com")

    findings = asyncio.run(run_archive_url_discovery_async(
        "example.com",
        client,  # type: ignore[arg-type]
        {"host": "example.com", "port": 80, "protocol": "tcp", "service": "http"},
        {"web_archive_discovery": {"max_urls": 20, "max_commoncrawl_indexes": 1}},
        surface,
    ))

    assert len(findings) == 1
    assert len(surface.archive_urls) >= 3
    sources = findings[0].evidence[0].data["sources"]
    assert {"wayback", "commoncrawl", "otx", "urlscan"}.issubset(sources)
    params = extract_archive_parameters(surface)
    assert {"id", "q", "cat", "page"} == {name for names in params.values() for name in names}
    assert any("web.archive.org" in call for call in client.calls)


class _ParamClient:
    async def request_url_async(self, url, timeout=10.0, allow_redirects=True, **kwargs):
        if "q=pwx" in url:
            token = url.split("q=", 1)[1]
            return PoliteResponse(200, [], f"<html>{token}</html>".encode(), {"url": url})
        if "debug=pwx" in url:
            return PoliteResponse(500, [], b"debug enabled", {"url": url})
        return PoliteResponse(200, [], b"<html>baseline</html>", {"url": url})


def test_active_parameter_discovery_detects_reflection_and_status_change():
    client = _ParamClient()
    discovery = ActiveParameterDiscovery(client, concurrency=2, max_tests=4)  # type: ignore[arg-type]

    result = asyncio.run(discovery.discover(["http://example.com/search"], ["q", "debug"]))

    reasons = {(hit.parameter, hit.reason) for hit in result.hits}
    assert ("q", "reflected") in reasons
    assert ("debug", "status-change") in reasons
    assert result.tested == 2
    assert result.req_s > 0


def test_active_parameter_discovery_updates_surface_and_finding():
    client = _ParamClient()
    config = {"web_param_discovery": {"candidate_params": ["q"], "max_tests": 2, "concurrency": 1}}
    surface = surface_from_config(config, "example.com:80")
    surface.add_url("http://example.com/search", "crawler")

    findings = asyncio.run(run_active_parameter_discovery_async(
        client,  # type: ignore[arg-type]
        {"host": "example.com", "port": 80, "protocol": "tcp", "service": "http"},
        config,
        surface,
    ))

    assert findings
    assert surface.parameters["http://example.com/search"] == {"q"}


def test_windows_selector_policy_is_installed_for_curl_cffi():
    if sys.platform != "win32":
        return
    policy_name = type(asyncio.get_event_loop_policy()).__name__
    assert "Selector" in policy_name

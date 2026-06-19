from __future__ import annotations

import asyncio
from time import perf_counter

from portwise.modules.http.content_fuzzer import AsyncContentFuzzer, FuzzFilters, load_wordlist, run_content_fuzzer_async
from portwise.modules.http.surface import DiscoveredSurface
from portwise.utils.http_client import PoliteResponse


class _FuzzClient:
    def __init__(self, routes: dict[str, tuple[int, str]]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    async def request_url_async(self, url, timeout=10.0, allow_redirects=False, **kwargs):
        self.calls.append(url)
        path = "/" + url.split("/", 3)[3].split("?", 1)[0] if "/" in url.split("://", 1)[1] else "/"
        status, body = self.routes.get(path, (200, "catch-all missing page"))
        return PoliteResponse(status, [("Content-Type", "text/html")], body.encode(), {"url": url})


def test_content_fuzzer_suppresses_soft_404_catch_all_and_reports_divergence():
    client = _FuzzClient({
        "/admin/": (200, "<html><title>Admin Login</title><form><input type=password></form></html>"),
    })
    surface = DiscoveredSurface("example.test")
    fuzzer = AsyncContentFuzzer(client, concurrency=3, max_tests=10, baseline_count=2)  # type: ignore[arg-type]

    result = asyncio.run(fuzzer.fuzz("http://example.test/", ["admin/", "definitely-missing"], surface))

    assert [hit.path for hit in result.hits] == ["/admin/"]
    assert result.filtered_soft404 >= 1
    assert "http://example.test/admin/" in surface.endpoints


def test_content_fuzzer_dedups_against_discovered_surface():
    client = _FuzzClient({"/login.aspx": (200, "login page")})
    surface = DiscoveredSurface("example.test")
    surface.add_url("http://example.test/login.aspx", "crawler")
    fuzzer = AsyncContentFuzzer(client, concurrency=1, max_tests=5, baseline_count=1)  # type: ignore[arg-type]

    result = asyncio.run(fuzzer.fuzz("http://example.test/", ["login.aspx"], surface))

    assert result.hits == []
    assert result.filtered_known == 1


def test_content_fuzzer_filters_status_size_words_lines_and_regex():
    client = _FuzzClient({
        "/keep": (200, "alpha beta\nportwise"),
        "/drop-status": (403, "alpha beta\nportwise"),
        "/drop-regex": (200, "alpha beta\nblocked"),
    })
    filters = FuzzFilters.from_config({
        "status_allow": [200],
        "words_allow": [3],
        "lines_allow": [2],
        "regex_include": "portwise",
    })
    fuzzer = AsyncContentFuzzer(client, concurrency=2, max_tests=10, baseline_count=1, filters=filters)  # type: ignore[arg-type]

    result = asyncio.run(fuzzer.fuzz("http://example.test/", ["keep", "drop-status", "drop-regex"]))

    assert [hit.path for hit in result.hits] == ["/keep"]
    assert result.filtered_rules >= 2


def test_run_content_fuzzer_async_emits_finding_and_baseline_evidence():
    client = _FuzzClient({"/about.aspx": (200, "<title>about</title>")})
    surface = DiscoveredSurface("example.test")
    config = {"web_content_fuzzer": {"max_tests": 5, "baseline_count": 2, "concurrency": 2, "wordlist": ""}}

    findings = asyncio.run(run_content_fuzzer_async(
        base_url="http://example.test/",
        client=client,  # type: ignore[arg-type]
        target={"host": "example.test", "port": 80, "protocol": "tcp", "service": "http"},
        config=config,
        surface=surface,
    ))

    assert findings
    evidence = findings[0].evidence[0].data
    assert evidence["soft404_baselines"]
    assert evidence["hits"][0]["path"] == "/about.aspx"


def test_default_content_fuzz_wordlist_is_packaged():
    words = load_wordlist({})
    assert "login.aspx" in words
    assert ".env" in words


def test_content_fuzzer_benchmark_records_req_s():
    client = _FuzzClient({f"/p{i}": (200, f"body {i}") for i in range(20)})
    fuzzer = AsyncContentFuzzer(client, concurrency=10, max_tests=20, baseline_count=1)  # type: ignore[arg-type]
    words = [f"p{i}" for i in range(20)]

    started = perf_counter()
    result = asyncio.run(fuzzer.fuzz("http://example.test/", words))
    elapsed = perf_counter() - started
    req_s = result.tested / max(elapsed, 0.001)

    assert result.hits
    assert req_s >= 100.0

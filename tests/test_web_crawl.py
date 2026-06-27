import asyncio

from portwise.modules.http.web_crawl import AsyncWebCrawler, run_web_crawl, _redact, _same_origin


class _Resp:
    def __init__(self, status, body=b"", location=""):
        self.status = status; self._b = body; self._loc = location
    def read(self, n=0): return self._b
    def getheader(self, k, d=""): return self._loc if k.lower()=="location" else d


class _Client:
    def __init__(self, pages): self.pages = pages
    def is_tripped(self, host): return False
    def throttle(self, host): pass
    def request(self, host, port, method, path, tls, timeout):
        return self.pages.get(path, _Resp(404, b"not found"))


def test_redact():
    assert _redact("AKIAEXAMPLE12345678") == "AKIA***5678"
    assert _redact("short") == "sh***"


def test_same_origin():
    assert _same_origin("/api/x", "h", 80)
    assert _same_origin("http://h:80/a", "h", 80)
    assert not _same_origin("http://evil.com/a", "h", 80)


def test_crawl_finds_js_and_endpoints():
    homepage = '<a href="/app.js"></a><a href="/about">about</a>'
    js = b'fetch("/api/v1/users"); var k="AKIAABCDEFGHIJKLMNOP"; const api_key="abcdef1234567890ABCD";'
    client = _Client({
        "/app.js": _Resp(200, js),
        "/about": _Resp(200, b'<a href="/api/admin/panel">x</a>'),
    })
    target = {"host": "h", "port": 443, "protocol": "tcp", "service": "https"}
    findings = run_web_crawl("h", 443, True, 2.0, client, target, {}, homepage,
                             validation_level="full")
    titles = [f.title for f in findings]
    assert any("JavaScript Files" in t for t in titles)
    assert any("Endpoints" in t for t in titles)
    assert not any(t.startswith("Potential Secret Exposed") for t in titles)


def test_crawl_disabled_at_recon_level():
    findings = run_web_crawl("h", 443, True, 2.0, _Client({}), {"host":"h","port":443}, {}, "<html></html>",
                             validation_level="recon")
    assert findings == []


def test_discovered_links_use_real_worker_concurrency():
    class AsyncClient:
        def __init__(self):
            self.active = 0
            self.peak = 0

        async def request_url_async(self, url, **kwargs):
            self.active += 1
            self.peak = max(self.peak, self.active)
            await asyncio.sleep(0.02)
            self.active -= 1
            if url.endswith("/robots.txt"):
                return _Resp(404)
            return _Resp(200, b"ok")

    client = AsyncClient()
    homepage = "".join(f'<a href="/page-{index}">x</a>' for index in range(8))
    result = asyncio.run(AsyncWebCrawler(
        client, concurrency=4, max_pages=9, max_depth=1,
    ).crawl("http://example.test/", homepage_body=homepage))
    assert result.requests == 8
    assert client.peak >= 3


def test_failed_fetches_do_not_kill_workers_and_deadlock_queue():
    class FailingClient:
        async def request_url_async(self, url, **kwargs):
            if url.endswith("/robots.txt"):
                return _Resp(404)
            raise TimeoutError("fixture timeout")

    result = asyncio.run(asyncio.wait_for(
        AsyncWebCrawler(FailingClient(), concurrency=3).crawl("http://example.test/"),
        timeout=0.5,
    ))
    assert result.pages == []

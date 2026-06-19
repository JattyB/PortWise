from portwise.modules.http.web_crawl import run_web_crawl, _redact, _same_origin


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

from __future__ import annotations

import asyncio
from time import perf_counter

from portwise.core.models import Service
from portwise.modules.http.http_engine import HttpEngine
from portwise.modules.http.probe import AsyncHttpProber
from portwise.modules.http.tech_fingerprint import WappalyzerFingerprinter, detect_technologies
from portwise.utils.http_client import PoliteHttpClient, PoliteResponse


class _RedirectClient(PoliteHttpClient):
    def __init__(self) -> None:
        self.config = type("Cfg", (), {"max_redirects": 5})()
        self.calls: list[tuple[str, bool]] = []

    async def request_url_async(self, url, method="GET", headers=None, body=None, timeout=10.0, allow_redirects=True):
        self.calls.append((url, allow_redirects))
        if url.endswith("/start"):
            return PoliteResponse(302, [("Location", "/final")], b"", {"url": url})
        return PoliteResponse(
            200,
            [("Content-Type", "text/html"), ("Server", "nginx/1.24.0")],
            b"<html><title>Done</title></html>",
            {"url": url},
        )

    def is_access_blocked(self, response):
        return False


def test_async_http_prober_collects_redirect_chain():
    client = _RedirectClient()

    result = asyncio.run(AsyncHttpProber(client=client, timeout=1).probe_url("http://example.test/start"))

    assert result.status == 200
    assert result.title == "Done"
    assert result.final_url == "http://example.test/final"
    assert [(hop.status, hop.location) for hop in result.redirect_chain] == [(302, "/final")]
    assert all(allow is False for _, allow in client.calls)


def test_wappalyzer_fingerprint_detects_headers_meta_and_scripts():
    apps = {
        "Nginx": {
            "cats": [22],
            "headers": {"server": "nginx(?:/([\\d.]+))?\\;version:\\1"},
        },
        "WordPress": {
            "cats": [1],
            "meta": {"generator": "^WordPress ?([\\d.]+)?\\;version:\\1"},
            "scriptSrc": ["/wp-content/"],
        },
    }
    categories = {"1": {"name": "CMS"}, "22": {"name": "Web servers"}}
    fp = WappalyzerFingerprinter(apps, categories)

    matches = fp.identify(
        url="http://site.test/",
        headers={"Server": "nginx/1.24.0"},
        body='<meta name="generator" content="WordPress 6.4"><script src="/wp-content/app.js"></script>',
    )

    by_name = {match.name: match for match in matches}
    assert by_name["Nginx"].version == "1.24.0"
    assert by_name["WordPress"].version == "6.4"
    assert by_name["WordPress"].categories == ("CMS",)


def test_bundled_wappalyzer_dataset_detects_aspnet_iis():
    matches = detect_technologies(
        url="http://aspnet.test/",
        headers=[
            ("Server", "Microsoft-IIS/10.0"),
            ("X-Powered-By", "ASP.NET"),
            ("X-AspNet-Version", "4.0.30319"),
        ],
        cookies={"ASP.NET_SessionId": "abc"},
        body='<input type="hidden" name="__VIEWSTATE" value="x">',
    )

    names = {match.name for match in matches}
    assert {"IIS", "Microsoft ASP.NET"}.issubset(names)


class _HttpEngineClient:
    def request(self, host, port, method, path, tls, timeout):
        if method == "OPTIONS":
            return PoliteResponse(200, [("Allow", "GET, HEAD")], b"", {})
        return PoliteResponse(
            200,
            [
                ("Server", "Microsoft-IIS/10.0"),
                ("X-Powered-By", "ASP.NET"),
                ("Content-Type", "text/html"),
            ],
            b"<html><title>Site</title><input name=\"__VIEWSTATE\"></html>",
            {},
        )

    def is_access_blocked(self, response):
        return False

    def is_tripped(self, host):
        return False

    def throttle(self, host):
        return None


def test_http_engine_emits_technology_fingerprint_finding():
    service = Service(host="10.0.0.1", port=80, protocol="tcp", state="open", service_name="http")
    engine = HttpEngine(client=_HttpEngineClient(), paths=())

    findings = engine.run(service, {"validation_level": "recon"})

    tech = [finding for finding in findings if finding.type == "http-technology"]
    assert tech
    names = {item["name"] for item in tech[0].evidence[0].data["technologies"]}
    assert {"IIS", "Microsoft ASP.NET"}.issubset(names)


def test_http_fingerprint_benchmark_records_req_s():
    started = perf_counter()
    iterations = 25
    for _ in range(iterations):
        matches = detect_technologies(
            url="http://bench.test/",
            headers=[("Server", "nginx/1.24.0"), ("X-Powered-By", "PHP/8.2.1")],
            body='<html><title>x</title><script src="/jquery-3.7.1.min.js"></script></html>',
        )
        assert any(match.name == "Nginx" for match in matches)
        assert any(match.name == "PHP" for match in matches)
    elapsed = perf_counter() - started
    req_s = iterations / max(elapsed, 0.001)
    assert req_s >= 5.0, f"HTTP technology fingerprint benchmark too slow: {req_s:.2f} req/s"

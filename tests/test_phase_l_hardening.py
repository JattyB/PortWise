from portwise.modules.http.http_engine import HttpEngine
from portwise.core.models import Service
from portwise.utils.http_client import PoliteResponse


class _Client:
    def request(self, host, port, method, path, tls, timeout=None, **kwargs):
        headers = [("Allow", "GET, HEAD")] if method == "OPTIONS" else []
        return PoliteResponse(200, headers, b"<html><title>Fixture</title></html>", {})

    def is_access_blocked(self, response):
        return False

    def is_tripped(self, host):
        return False


def test_http_engine_records_stage_timings(monkeypatch):
    from portwise.core.models import Service
    monkeypatch.setattr("portwise.modules.http.http_engine.run_web_crawl_async", _empty_async)
    monkeypatch.setattr("portwise.modules.http.http_engine.run_content_discovery", lambda **_: [])
    monkeypatch.setattr("portwise.modules.http.http_engine.run_cms_fingerprint", lambda **_: [])
    monkeypatch.setattr("portwise.modules.http.http_engine.run_injection_indicators", lambda **_: [])
    monkeypatch.setattr("portwise.modules.http.http_engine.run_js_analysis_async", _empty_async)
    config = {
        "validation_level": "recon",
        "web_archive_discovery": {"enabled": False},
        "web_content_fuzzer": {"enabled": False},
        "web_param_discovery": {"enabled": False},
        "web_template_engine": {"enabled": False},
    }
    HttpEngine(client=_Client(), paths=()).run(
        Service("example.test", 80, "tcp", "open", "http"), config
    )
    assert [row["stage"] for row in config["_web_stage_metrics"]] == ["crawl"]
    assert config["_web_stage_metrics"][0]["seconds"] >= 0


def test_full_web_depth_raises_request_budget_before_preflight(monkeypatch):
    client = _Client()
    client.config = type("Config", (), {"max_requests_per_host": 30})()
    monkeypatch.setattr("portwise.modules.http.http_engine.run_web_crawl_async", _empty_async)
    monkeypatch.setattr("portwise.modules.http.http_engine.run_content_discovery", lambda **_: [])
    monkeypatch.setattr("portwise.modules.http.http_engine.run_cms_fingerprint", lambda **_: [])
    monkeypatch.setattr("portwise.modules.http.http_engine.run_injection_indicators", lambda **_: [])
    monkeypatch.setattr("portwise.modules.http.http_engine.run_js_analysis_async", _empty_async)
    HttpEngine(client=client).run(
        Service("example.test", 80, "tcp", "open", "http"),
        {
            "validation_level": "full",
            "web_archive_discovery": {"enabled": False},
            "web_content_fuzzer": {"enabled": False},
            "web_param_discovery": {"enabled": False},
            "web_template_engine": {"enabled": False},
        },
    )
    assert client.config.max_requests_per_host == 3000


async def _empty_async(**_):
    return []

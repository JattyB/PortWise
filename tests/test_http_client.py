from __future__ import annotations

import asyncio
import sys
import time
import types
from unittest.mock import AsyncMock, patch

import pytest

from portwise.utils.http_client import (
    CurlCffiTransport,
    PoliteHttpClient,
    PoliteResponse,
    PolitenessConfig,
    TransportResult,
    client_from_config,
)


def test_http_engine_emits_access_blocked_finding():
    from portwise.core.models import Service
    from portwise.modules.http.http_engine import HttpEngine

    class _BlockedClient:
        def request(self, *args, **kwargs):
            return PoliteResponse(
                403,
                [("Server", "cloudflare")],
                b"<html>Access denied</html>",
                {"impersonate": "chrome", "used_playwright": False},
            )

        def is_access_blocked(self, response):
            return True

    svc = Service(host="blocked.example", port=443, protocol="tcp", state="open", service_name="https", tunnel="ssl")
    findings = HttpEngine(client=_BlockedClient()).run(svc, {})

    assert [f.title for f in findings] == ["WAF / Access Blocked"]
    assert findings[0].tags == ["waf", "access-blocked"]


def _fast_config(**kwargs) -> PolitenessConfig:
    defaults = dict(
        min_delay=0.0,
        jitter_min=0.0,
        jitter_max=0.0,
        max_retries=0,
        backoff_base=0.0,
        backoff_max=0.0,
        circuit_breaker_threshold=3,
        max_requests_per_host=30,
    )
    defaults.update(kwargs)
    return PolitenessConfig(**defaults)


class _FakeTransport:
    def __init__(self, responses: list[TransportResult] | None = None) -> None:
        self.responses = responses or [_ok_result()]
        self.calls: list[dict] = []

    async def request(self, **kwargs):
        self.calls.append(kwargs)
        idx = min(len(self.calls) - 1, len(self.responses) - 1)
        return self.responses[idx]


def _client(**kwargs) -> PoliteHttpClient:
    return PoliteHttpClient(_fast_config(**kwargs), transport=_FakeTransport())  # type: ignore[arg-type]


def _ok_result() -> TransportResult:
    return TransportResult(200, [("Content-Type", "text/html")], b"<html>ok</html>", "http://host.test/", "chrome")


def _blocked_result(status: int = 403, headers: list[tuple[str, str]] | None = None) -> TransportResult:
    return TransportResult(status, headers or [], b"blocked", "http://host.test/", "chrome", blocked=status in {403, 429})


def test_per_host_delay_enforced():
    cfg = PolitenessConfig(min_delay=0.5, jitter_min=0.0, jitter_max=0.0, max_retries=0)
    client = PoliteHttpClient(cfg, transport=_FakeTransport())  # type: ignore[arg-type]

    with (
        patch("portwise.utils.http_client.time.sleep") as mock_sleep,
        patch("portwise.utils.http_client.time.monotonic") as mock_mono,
    ):
        mock_mono.return_value = 100.0
        client.throttle("example.com")
        client.throttle("example.com")

    assert mock_sleep.called
    sleep_values = [c.args[0] for c in mock_sleep.call_args_list]
    assert any(v >= 0.4 for v in sleep_values), f"Expected sleep >= 0.4s, got: {sleep_values}"


def test_jitter_applied():
    cfg = PolitenessConfig(min_delay=0.2, jitter_min=0.1, jitter_max=0.3, max_retries=0)
    client = PoliteHttpClient(cfg, transport=_FakeTransport())  # type: ignore[arg-type]
    slept: list[float] = []

    with (
        patch("portwise.utils.http_client.time.sleep", side_effect=lambda s: slept.append(s)),
        patch("portwise.utils.http_client.time.monotonic", return_value=100.0),
        patch("portwise.utils.http_client.random.uniform", return_value=0.25),
    ):
        client.throttle("host.test")
        client.throttle("host.test")

    assert slept
    assert abs(slept[-1] - 0.45) < 0.01, f"Expected jittered delay ~0.45, got {slept[-1]}"


def test_backoff_on_403_rate_limit_then_success():
    transport = _FakeTransport([
        _blocked_result(403, [("Retry-After", "1")]),
        _ok_result(),
    ])
    client = PoliteHttpClient(
        _fast_config(max_retries=1, backoff_base=1.0, respect_retry_after=True),
        transport=transport,  # type: ignore[arg-type]
    )

    with patch("portwise.utils.http_client.asyncio.sleep", new_callable=AsyncMock) as sleep_mock:
        response = client.request("host.test", 80, "GET", "/", False)

    assert response.status == 200
    sleep_mock.assert_awaited()
    assert transport.calls[0]["headers"] == {}


def test_backoff_on_429_respects_retry_after():
    transport = _FakeTransport([
        _blocked_result(429, [("Retry-After", "7")]),
        _ok_result(),
    ])
    client = PoliteHttpClient(
        _fast_config(max_retries=1, backoff_base=1.0, respect_retry_after=True),
        transport=transport,  # type: ignore[arg-type]
    )

    with patch("portwise.utils.http_client.asyncio.sleep", new_callable=AsyncMock) as sleep_mock:
        response = client.request("host.test", 80, "GET", "/", False)

    assert response.status == 200
    assert sleep_mock.await_args_list[0].args[0] >= 7.0


def test_plain_403_does_not_trip_circuit_breaker():
    client = PoliteHttpClient(
        _fast_config(max_retries=0, circuit_breaker_threshold=1, max_requests_per_host=10),
        transport=_FakeTransport([_blocked_result(403)]),  # type: ignore[arg-type]
    )

    response = client.request("host.test", 80, "GET", "/", False)

    assert response.status == 403
    assert not client.is_tripped("host.test")


def test_circuit_breaker_trips_only_on_rate_limit_signals():
    client = PoliteHttpClient(
        _fast_config(max_retries=0, circuit_breaker_threshold=2, max_requests_per_host=10),
        transport=_FakeTransport([_blocked_result(403, [("Retry-After", "1")])]),  # type: ignore[arg-type]
    )

    client.request("host.test", 80, "GET", "/a", False)
    assert not client.is_tripped("host.test")
    with pytest.raises(OSError, match="[Rr]ate-limit|Circuit breaker"):
        client.request("host.test", 80, "GET", "/b", False)
    assert client.is_tripped("host.test")


def test_per_host_budget_enforced():
    client = _client(max_requests_per_host=2)

    client.request("host.test", 80, "GET", "/a", False)
    client.request("host.test", 80, "GET", "/b", False)
    with pytest.raises(OSError, match="budget exhausted"):
        client.request("host.test", 80, "GET", "/c", False)

    assert client.budget_remaining("host.test") == 0


def test_default_transport_uses_browser_impersonation_not_scanner_signature():
    cfg = PolitenessConfig()
    assert cfg.impersonate == "chrome"
    assert "safe-validation" not in cfg.user_agent
    assert "Mozilla" in cfg.user_agent
    assert any(k == "Sec-CH-UA" for k, _ in PoliteHttpClient(cfg).browser_headers())


def test_curl_resolve_options_for_vhost_sni(monkeypatch):
    class _Opt:
        RESOLVE = object()

    fake_module = types.SimpleNamespace(CurlOpt=_Opt)
    monkeypatch.setitem(sys.modules, "curl_cffi", fake_module)
    opts = CurlCffiTransport._curl_options("https://site.example.com:443/", "203.0.113.5", "site.example.com")

    assert list(opts.values()) == [["site.example.com:443:203.0.113.5"]]


def test_client_from_config_polite_mode():
    cfg = {"politeness_mode": "polite", "http_politeness": {"min_delay_seconds": 1.0}}
    client = client_from_config(cfg)
    assert client.config.min_delay == 4.0


def test_client_from_config_aggressive_mode():
    cfg = {"politeness_mode": "aggressive"}
    client = client_from_config(cfg)
    assert client.config.min_delay < 0.1


def test_client_from_config_transport_settings():
    cfg = {"http_transport": {"browser_profile": "chrome", "proxy": "http://127.0.0.1:8080", "max_concurrency": 3}}
    client = client_from_config(cfg)
    assert client.config.impersonate == "chrome"
    assert client.config.proxy == "http://127.0.0.1:8080"
    assert client.config.max_concurrency == 3


def test_request_timeline_spacing():
    client = PoliteHttpClient(
        PolitenessConfig(min_delay=0.1, jitter_min=0.0, jitter_max=0.0, max_retries=0),
        transport=_FakeTransport(),  # type: ignore[arg-type]
    )
    real_timestamps: list[float] = []

    async def fake_execute(**kwargs):
        real_timestamps.append(time.monotonic())
        return _ok_result()

    client._execute_request = fake_execute  # type: ignore[method-assign]

    for path in ("/a", "/b", "/c"):
        client.request("timing.test", 80, "GET", path, False)

    for i in range(1, len(real_timestamps)):
        gap = real_timestamps[i] - real_timestamps[i - 1]
        assert gap >= 0.08, f"Gap between request {i-1} and {i} was only {gap:.3f}s"


def test_request_url_parses_full_url():
    transport = _FakeTransport()
    client = PoliteHttpClient(_fast_config(), transport=transport)  # type: ignore[arg-type]

    response = client.request_url("https://example.com:8443/a?b=c", headers={"X-Test": "1"})

    assert response.status == 200
    call = transport.calls[0]
    assert call["url"] == "https://example.com:8443/a?b=c"
    assert call["headers"] == {"X-Test": "1"}


def test_sync_requests_reuse_client_owned_event_loop_and_close():
    transport = _FakeTransport([_ok_result(), _ok_result()])
    client = PoliteHttpClient(_fast_config(), transport=transport)  # type: ignore[arg-type]

    client.request("host.test", 80, "GET", "/a", False)
    first_loop = client._sync_loop
    client.request("host.test", 80, "GET", "/b", False)

    assert first_loop is not None
    assert client._sync_loop is first_loop
    assert len(transport.calls) == 2

    client.close_sync()
    assert client._sync_loop is None
    assert client._sync_loop_thread is None


def test_async_request_interface():
    client = PoliteHttpClient(_fast_config(), transport=_FakeTransport())  # type: ignore[arg-type]

    response = asyncio.run(client.request_async("host.test", 80, "GET", "/", False))

    assert response.status == 200


def test_polite_response_interface():
    raw = [("Content-Type", "text/html"), ("X-Custom", "val")]
    resp = PoliteResponse(200, raw, b"hello world")

    assert resp.status == 200
    assert resp.getheader("content-type") == "text/html"
    assert resp.getheader("missing", "default") == "default"
    assert resp.getheaders() == raw
    assert resp.read(5) == b"hello"
    assert resp.read() == b"hello world"

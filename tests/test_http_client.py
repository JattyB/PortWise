from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from portwise.utils.http_client import (
    PoliteHttpClient,
    PoliteResponse,
    PolitenessConfig,
    client_from_config,
)


def _fast_config(**kwargs) -> PolitenessConfig:
    """Config with tiny delays so tests don't actually sleep."""
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


def _client(**kwargs) -> PoliteHttpClient:
    return PoliteHttpClient(_fast_config(**kwargs))


def _ok_response() -> tuple[int, list, bytes]:
    return (200, [("Content-Type", "text/html")], b"<html>ok</html>")


def _blocked_response(status: int = 403) -> tuple[int, list, bytes]:
    return (status, [], b"blocked")


# ---------------------------------------------------------------------------
# Per-host delay enforced
# ---------------------------------------------------------------------------

def test_per_host_delay_enforced():
    cfg = PolitenessConfig(min_delay=0.5, jitter_min=0.0, jitter_max=0.0, max_retries=0)
    client = PoliteHttpClient(cfg)

    with (
        patch.object(client, "_do_request", return_value=_ok_response()),
        patch("portwise.utils.http_client.time.sleep") as mock_sleep,
        patch("portwise.utils.http_client.time.monotonic") as mock_mono,
    ):
        # Both calls return same timestamp — elapsed = 0, so sleep should fire
        mock_mono.return_value = 100.0
        client.request("example.com", 80, "GET", "/", False)   # first request, stores t=100
        client.request("example.com", 80, "GET", "/b", False)  # second request, elapsed=0 < 0.5

    # At least one sleep call for the second request's delay
    assert mock_sleep.called
    sleep_values = [c.args[0] for c in mock_sleep.call_args_list]
    assert any(v >= 0.4 for v in sleep_values), f"Expected sleep ≥ 0.4s, got: {sleep_values}"


# ---------------------------------------------------------------------------
# Jitter applied
# ---------------------------------------------------------------------------

def test_jitter_applied():
    cfg = PolitenessConfig(min_delay=0.2, jitter_min=0.1, jitter_max=0.3, max_retries=0)
    client = PoliteHttpClient(cfg)

    slept: list[float] = []

    with (
        patch.object(client, "_do_request", return_value=_ok_response()),
        patch("portwise.utils.http_client.time.sleep", side_effect=lambda s: slept.append(s)),
        patch("portwise.utils.http_client.time.monotonic", return_value=100.0),
        patch("portwise.utils.http_client.random.uniform", return_value=0.25),
    ):
        client.request("host.test", 80, "GET", "/", False)
        client.request("host.test", 80, "GET", "/b", False)

    # Should have slept: elapsed=0, delay=0.2+0.25=0.45 → sleep(0.45)
    assert slept, "Expected at least one sleep call"
    assert abs(slept[-1] - 0.45) < 0.01, f"Expected jittered delay ~0.45, got {slept[-1]}"


# ---------------------------------------------------------------------------
# Backoff on 403 then success
# ---------------------------------------------------------------------------

def test_backoff_on_403_then_success():
    cfg = PolitenessConfig(
        min_delay=0.0, jitter_min=0.0, jitter_max=0.0,
        max_retries=1, backoff_base=1.0, backoff_max=10.0,
    )
    client = PoliteHttpClient(cfg)
    call_count = 0

    def fake_do(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _blocked_response(403)
        return _ok_response()

    with (
        patch.object(client, "_do_request", side_effect=fake_do),
        patch("portwise.utils.http_client.time.sleep") as mock_sleep,
        patch("portwise.utils.http_client.random.uniform", return_value=0.0),
    ):
        response = client.request("host.test", 80, "GET", "/", False)

    assert response.status == 200
    assert mock_sleep.called  # backoff sleep was called before retry


# ---------------------------------------------------------------------------
# Backoff on 429 respects Retry-After
# ---------------------------------------------------------------------------

def test_backoff_on_429_respects_retry_after():
    cfg = PolitenessConfig(
        min_delay=0.0, jitter_min=0.0, jitter_max=0.0,
        max_retries=1, backoff_base=1.0, respect_retry_after=True,
    )
    client = PoliteHttpClient(cfg)
    call_count = 0

    def fake_do(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return (429, [("Retry-After", "7")], b"rate limited")
        return _ok_response()

    slept: list[float] = []
    with (
        patch.object(client, "_do_request", side_effect=fake_do),
        patch("portwise.utils.http_client.time.sleep", side_effect=lambda s: slept.append(s)),
        patch("portwise.utils.http_client.random.uniform", return_value=0.0),
    ):
        response = client.request("host.test", 80, "GET", "/", False)

    assert response.status == 200
    assert slept, "Expected sleep to be called"
    assert slept[0] >= 7.0, f"Retry-After=7 should cause sleep ≥ 7s, got {slept[0]}"


# ---------------------------------------------------------------------------
# Circuit breaker trips after threshold and skips
# ---------------------------------------------------------------------------

def test_circuit_breaker_trips_after_threshold_and_skips():
    cfg = PolitenessConfig(
        min_delay=0.0, jitter_min=0.0, jitter_max=0.0,
        max_retries=0,  # one error = one request
        circuit_breaker_threshold=3,
        max_requests_per_host=100,
    )
    client = PoliteHttpClient(cfg)

    with (
        patch.object(client, "_do_request", return_value=_blocked_response(403)),
        patch("portwise.utils.http_client.time.sleep"),
    ):
        # First 2 requests: 403 recorded but breaker not tripped yet
        client.request("host.test", 80, "GET", "/a", False)
        client.request("host.test", 80, "GET", "/b", False)
        assert not client.is_tripped("host.test")

        # Third request trips the breaker
        with pytest.raises(OSError, match="[Cc]ircuit breaker"):
            client.request("host.test", 80, "GET", "/c", False)
        assert client.is_tripped("host.test")

    # Subsequent request raises immediately without hitting _do_request
    with pytest.raises(OSError, match="[Cc]ircuit breaker"):
        client.request("host.test", 80, "GET", "/d", False)


# ---------------------------------------------------------------------------
# Per-host budget enforced
# ---------------------------------------------------------------------------

def test_per_host_budget_enforced():
    cfg = _fast_config(max_requests_per_host=2)
    client = PoliteHttpClient(cfg)

    with patch.object(client, "_do_request", return_value=_ok_response()):
        client.request("host.test", 80, "GET", "/a", False)
        client.request("host.test", 80, "GET", "/b", False)
        with pytest.raises(OSError, match="budget exhausted"):
            client.request("host.test", 80, "GET", "/c", False)

    assert client.budget_remaining("host.test") == 0


# ---------------------------------------------------------------------------
# Default UA is not the old scanner signature
# ---------------------------------------------------------------------------

def test_default_user_agent_is_not_the_old_signature():
    cfg = PolitenessConfig()
    assert "safe-validation" not in cfg.user_agent
    assert "Mozilla" in cfg.user_agent


# ---------------------------------------------------------------------------
# Fallback to urllib when requests is missing
# ---------------------------------------------------------------------------

def test_falls_back_to_urllib_when_requests_missing():
    client = _client()
    # Force session to None (simulates requests import failure)
    client._sessions["fallback.test"] = None

    with patch.object(client, "_do_request", return_value=_ok_response()) as mock_do:
        resp = client.request("fallback.test", 80, "GET", "/", False)

    assert resp.status == 200
    mock_do.assert_called_once()


# ---------------------------------------------------------------------------
# client_from_config wires politeness_mode correctly
# ---------------------------------------------------------------------------

def test_client_from_config_polite_mode():
    cfg = {"politeness_mode": "polite", "http_politeness": {"min_delay_seconds": 1.0}}
    client = client_from_config(cfg)
    # polite mode multiplies min_delay by 4
    assert client.config.min_delay == 4.0


def test_client_from_config_aggressive_mode():
    cfg = {"politeness_mode": "aggressive"}
    client = client_from_config(cfg)
    assert client.config.min_delay < 0.1  # much less than default 0.5


def test_client_from_config_balanced_defaults():
    cfg = {}
    client = client_from_config(cfg)
    assert client.config.min_delay == 0.5
    assert client.config.max_requests_per_host == 30


# ---------------------------------------------------------------------------
# Request timeline — proves spacing works (unit-level)
# ---------------------------------------------------------------------------

def test_request_timeline_spacing():
    """Simulate a 3-path scan and verify monotonic spacing between requests."""
    cfg = PolitenessConfig(min_delay=0.1, jitter_min=0.0, jitter_max=0.0, max_retries=0)
    client = PoliteHttpClient(cfg)

    real_timestamps: list[float] = []

    def fake_do(*args, **kwargs):
        real_timestamps.append(time.monotonic())
        return _ok_response()

    for path in ("/a", "/b", "/c"):
        client._do_request = fake_do  # type: ignore[method-assign]
        try:
            client.request("timing.test", 80, "GET", path, False)
        except Exception:
            pass

    # Gaps should be at least min_delay apart
    for i in range(1, len(real_timestamps)):
        gap = real_timestamps[i] - real_timestamps[i - 1]
        assert gap >= 0.08, f"Gap between request {i-1} and {i} was only {gap:.3f}s"


# ---------------------------------------------------------------------------
# PoliteResponse is drop-in compatible with callers
# ---------------------------------------------------------------------------

def test_polite_response_interface():
    raw = [("Content-Type", "text/html"), ("X-Custom", "val")]
    resp = PoliteResponse(200, raw, b"hello world")

    assert resp.status == 200
    assert resp.getheader("content-type") == "text/html"
    assert resp.getheader("missing", "default") == "default"
    assert resp.getheaders() == raw
    assert resp.read(5) == b"hello"
    assert resp.read() == b"hello world"

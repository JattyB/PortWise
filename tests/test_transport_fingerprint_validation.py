from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _module():
    path = Path(__file__).parent.parent / "tools" / "validate_transport_fingerprint.py"
    spec = importlib.util.spec_from_file_location("validate_transport_fingerprint", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_extract_preserves_http2_pseudo_header_order():
    mod = _module()
    payload = {
        "http_version": "h2",
        "user_agent": "Mozilla/5.0 Chrome/146.0.0.0",
        "tls": {"ja3_hash": "x", "ja4": mod.EXPECTED_CHROME_JA4},
        "http2": {
            "akamai_fingerprint": mod.EXPECTED_CHROME_AKAMAI,
            "sent_frames": [
                {"frame_type": "HEADERS", "headers": [":method: GET", ":authority: tls.peet.ws", "sec-ch-ua: chrome"]}
            ],
        },
    }

    fp = mod.extract("portwise", payload)

    assert fp.header_order[:3] == [":method", ":authority", "sec-ch-ua"]
    assert fp.sec_ch_ua == "chrome"


def test_assert_fingerprints_rejects_stdlib_match():
    mod = _module()
    transport = mod.Fingerprint(
        label="portwise",
        http_version="h2",
        user_agent="Mozilla/5.0 Chrome/146.0.0.0",
        ja3="",
        ja3_hash="same",
        ja4=mod.EXPECTED_CHROME_JA4,
        ja4_r="",
        akamai=mod.EXPECTED_CHROME_AKAMAI,
        akamai_hash="",
        header_order=mod.EXPECTED_CHROME_HEADERS,
        sec_ch_ua='"Chromium";v="146", "Google Chrome";v="146"',
    )
    control = mod.Fingerprint(
        label="stdlib",
        http_version="HTTP/1.1",
        user_agent="Python-urllib/3",
        ja3="",
        ja3_hash="same",
        ja4="other",
        ja4_r="",
        akamai="",
        akamai_hash="",
        header_order=[],
        sec_ch_ua="",
    )

    with pytest.raises(AssertionError, match="matches the stdlib control"):
        mod.assert_fingerprints(transport, control)

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from dataclasses import dataclass
from typing import Any

from portwise.utils.http_client import PoliteHttpClient, PolitenessConfig

DEFAULT_ECHO_URL = "https://tls.peet.ws/api/all"
EXPECTED_CHROME_JA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
EXPECTED_CHROME_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
EXPECTED_CHROME_HEADERS = [
    ":method",
    ":authority",
    ":scheme",
    ":path",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
    "priority",
]


@dataclass(slots=True)
class Fingerprint:
    label: str
    http_version: str
    user_agent: str
    ja3: str
    ja3_hash: str
    ja4: str
    ja4_r: str
    akamai: str
    akamai_hash: str
    header_order: list[str]
    sec_ch_ua: str


def fetch_stdlib(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "Python-urllib/3"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_portwise(url: str, timeout: float) -> dict[str, Any]:
    client = PoliteHttpClient(PolitenessConfig(
        min_delay=0.0,
        jitter_min=0.0,
        jitter_max=0.0,
        max_retries=0,
        max_requests_per_host=5,
        impersonate="chrome",
        browser_profiles=("chrome",),
    ))
    response = client.request_url(url, timeout=timeout)
    return json.loads(response.read().decode("utf-8"))


def extract(label: str, payload: dict[str, Any]) -> Fingerprint:
    tls = payload.get("tls") or {}
    http2 = payload.get("http2") or {}
    headers = _headers_from_payload(payload)
    sec_ch_ua = _header_value(headers, "sec-ch-ua")
    return Fingerprint(
        label=label,
        http_version=str(payload.get("http_version") or ""),
        user_agent=str(payload.get("user_agent") or ""),
        ja3=str(tls.get("ja3") or ""),
        ja3_hash=str(tls.get("ja3_hash") or ""),
        ja4=str(tls.get("ja4") or ""),
        ja4_r=str(tls.get("ja4_r") or ""),
        akamai=str(http2.get("akamai_fingerprint") or ""),
        akamai_hash=str(http2.get("akamai_fingerprint_hash") or ""),
        header_order=[_header_name(line) for line in headers],
        sec_ch_ua=sec_ch_ua,
    )


def _headers_from_payload(payload: dict[str, Any]) -> list[str]:
    http2 = payload.get("http2") or {}
    for frame in http2.get("sent_frames") or []:
        if frame.get("frame_type") == "HEADERS":
            return [str(item) for item in frame.get("headers") or []]
    http1 = payload.get("http1") or {}
    return [str(item) for item in http1.get("headers") or []]


def _header_value(headers: list[str], name: str) -> str:
    prefix = name.lower() + ":"
    for header in headers:
        if header.lower().startswith(prefix):
            return header.split(":", 1)[1].strip()
    return ""


def _header_name(header: str) -> str:
    if header.startswith(":"):
        return ":" + header[1:].split(":", 1)[0].lower()
    return header.split(":", 1)[0].lower()


def assert_fingerprints(transport: Fingerprint, control: Fingerprint) -> None:
    failures: list[str] = []
    if transport.http_version != "h2":
        failures.append(f"transport HTTP version is {transport.http_version!r}, expected h2")
    if control.http_version == "h2":
        failures.append("control unexpectedly negotiated HTTP/2")
    if transport.ja4 != EXPECTED_CHROME_JA4:
        failures.append(f"transport JA4 {transport.ja4!r} != expected Chrome JA4 {EXPECTED_CHROME_JA4!r}")
    if transport.akamai != EXPECTED_CHROME_AKAMAI:
        failures.append("transport HTTP/2 Akamai fingerprint does not match current Chrome profile")
    if transport.ja4 == control.ja4 or transport.ja3_hash == control.ja3_hash:
        failures.append("transport TLS fingerprint matches the stdlib control")
    if "Chrome/146.0.0.0" not in transport.user_agent:
        failures.append(f"transport UA is not current Chrome 146: {transport.user_agent!r}")
    if '"Chromium";v="146"' not in transport.sec_ch_ua or '"Google Chrome";v="146"' not in transport.sec_ch_ua:
        failures.append(f"transport Sec-CH-UA is not Chrome 146: {transport.sec_ch_ua!r}")
    if transport.header_order != EXPECTED_CHROME_HEADERS:
        failures.append(
            "transport header order mismatch:\n"
            f"  got      {transport.header_order}\n"
            f"  expected {EXPECTED_CHROME_HEADERS}"
        )
    if failures:
        raise AssertionError("\n".join(failures))


def print_summary(transport: Fingerprint, control: Fingerprint) -> None:
    rows = [
        ("HTTP", transport.http_version, control.http_version),
        ("User-Agent", transport.user_agent, control.user_agent),
        ("Sec-CH-UA", transport.sec_ch_ua, control.sec_ch_ua or "<absent>"),
        ("JA3 hash", transport.ja3_hash, control.ja3_hash),
        ("JA4", transport.ja4, control.ja4),
        ("JA4_r", transport.ja4_r, control.ja4_r),
        ("Akamai H2", transport.akamai, control.akamai or "<absent>"),
        ("Akamai H2 hash", transport.akamai_hash, control.akamai_hash or "<absent>"),
        ("Header order", ", ".join(transport.header_order), ", ".join(control.header_order) or "<absent>"),
    ]
    print("PortWise shared transport vs stdlib control")
    print("field | portwise | stdlib")
    print("--- | --- | ---")
    for field, portwise, stdlib in rows:
        print(f"{field} | {portwise} | {stdlib}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate PortWise curl_cffi Chrome fingerprint against a TLS echo endpoint.")
    parser.add_argument("--url", default=DEFAULT_ECHO_URL)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args(argv)

    control = extract("stdlib", fetch_stdlib(args.url, args.timeout))
    transport = extract("portwise", fetch_portwise(args.url, args.timeout))
    assert_fingerprints(transport, control)
    print_summary(transport, control)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

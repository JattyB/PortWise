from __future__ import annotations

import asyncio
from time import perf_counter

from portwise.core.models import Severity, Service
from portwise.modules.http.http_engine import HttpEngine
from portwise.modules.http.nuclei_engine import (
    NucleiExtractor,
    NucleiMatcher,
    NucleiRequest,
    TemplateResponse,
    _evaluate_matcher,
    _json_path_lookup,
    _parse_raw_request,
    _run_extractor,
    run_native_nuclei_async,
)
from portwise.utils.http_client import PoliteResponse


def _response(
    *,
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
    body: bytes | str = b"",
    url: str = "http://example.test/",
) -> TemplateResponse:
    raw_body = body.encode("utf-8") if isinstance(body, str) else body
    return TemplateResponse(status=status, headers=headers or [], body=raw_body, url=url)


def test_matchers_cover_status_word_regex_binary_size_parts_and_negative():
    response = _response(
        status=200,
        headers=[("Server", "Apache/2.4.7"), ("X-Test", "visible")],
        body=b"magic token body \x4a\x41\x56\x41 and 12345",
    )
    assert _evaluate_matcher(NucleiMatcher(type="status", status=[200]), response)
    assert _evaluate_matcher(NucleiMatcher(type="word", part="body", words=["magic token"]), response)
    assert _evaluate_matcher(NucleiMatcher(type="word", part="header", words=["Server: Apache"]), response)
    assert _evaluate_matcher(NucleiMatcher(type="regex", part="all", regex=[r"X-Test:\s+visible", r"magic token"], condition="and"), response)
    assert _evaluate_matcher(NucleiMatcher(type="binary", binary=["4a415641"]), response)
    assert _evaluate_matcher(NucleiMatcher(type="size", size=[len(response.body)]), response)
    assert _evaluate_matcher(NucleiMatcher(type="word", part="body", words=["forbidden"], negative=True), response)


def test_matchers_condition_and_or_behave_correctly():
    response = _response(body="alpha beta")
    and_matcher = NucleiMatcher(type="word", words=["alpha", "beta"], condition="and")
    or_matcher = NucleiMatcher(type="word", words=["alpha", "missing"], condition="or")
    and_fail = NucleiMatcher(type="word", words=["alpha", "missing"], condition="and")
    assert _evaluate_matcher(and_matcher, response)
    assert _evaluate_matcher(or_matcher, response)
    assert not _evaluate_matcher(and_fail, response)


def test_extractors_cover_regex_kval_and_json():
    response = _response(
        headers=[("X-Powered-By", "ASP.NET"), ("Set-Cookie", "sid=abc123")],
        body='{"user":{"name":"alice","roles":["admin","ops"]},"token":"xyz"}',
    )
    regex = NucleiExtractor(type="regex", regex=[r'"token":"([^"]+)"'], group=1)
    kval = NucleiExtractor(type="kval", kval=["x_powered_by"])
    json_ex = NucleiExtractor(type="json", json_paths=["user.name", "user.roles[0]"])
    assert _run_extractor(regex, response) == ["xyz"]
    assert _run_extractor(kval, response) == ["ASP.NET"]
    assert _run_extractor(json_ex, response) == ["alice", "admin"]


def test_json_path_lookup_skips_unsupported_expressions():
    document = {"user": {"name": "alice"}, "roles": ["admin"]}
    assert _json_path_lookup(document, "user.name") == "alice"
    assert _json_path_lookup(document, ".roles[0]") == "admin"
    assert _json_path_lookup(document, "roles | first") is None


def test_parse_raw_request_renders_method_headers_and_body():
    raw = "POST /login HTTP/1.1\nHost: {{Hostname}}\nX-Test: value\n\nusername=admin"
    method, url, headers, body = _parse_raw_request(
        raw.replace("{{Hostname}}", "example.test"),
        {"Hostname": "example.test", "Scheme": "http"},
    )
    assert method == "POST"
    assert url == "http://example.test/login"
    assert headers["Host"] == "example.test"
    assert body == "username=admin"


class _NativeClient:
    def __init__(self, routes: dict[str, tuple[int, list[tuple[str, str]], str]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str]] = []

    async def request_url_async(self, url, method="GET", headers=None, body=None, timeout=8.0, allow_redirects=True):
        self.calls.append((method, url))
        status, hdrs, text = self.routes.get(url, (404, [("Content-Type", "text/plain")], "missing"))
        return PoliteResponse(status, hdrs, text.encode("utf-8"), {"url": url})


def test_run_native_nuclei_async_matches_extracts_and_skips_unsupported(tmp_path):
    supported = tmp_path / "supported.yaml"
    supported.write_text(
        """
id: custom-login-check
info:
  name: Custom Login Check
  severity: medium
  description: Detects a login page.
  classification:
    cve-id: CVE-2026-0001
    cvss-score: 6.5
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["admin-login"]
    extractors:
      - type: regex
        regex: ["session=([a-z0-9]+)"]
        group: 1
""".strip(),
        encoding="utf-8",
    )
    unsupported = tmp_path / "unsupported.yaml"
    unsupported.write_text(
        """
id: unsupported-workflow
workflow:
  - template: child
""".strip(),
        encoding="utf-8",
    )
    unsupported_matcher = tmp_path / "unsupported-matcher.yaml"
    unsupported_matcher.write_text(
        """
id: unsupported-dsl
info:
  name: Unsupported DSL
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/dsl"
    matchers:
      - type: dsl
        dsl:
          - contains(body, 'x')
""".strip(),
        encoding="utf-8",
    )
    client = _NativeClient({
        "http://example.test/login": (200, [("Server", "Example")], "<html>admin-login session=abc123</html>")
    })

    result = asyncio.run(run_native_nuclei_async(
        client,  # type: ignore[arg-type]
        {"host": "example.test", "port": 80, "protocol": "tcp", "service": "http"},
        {"web_template_engine": {"include_packaged": False, "template_dir": str(tmp_path), "enabled": True}},
    ))

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.title == "Custom Login Check"
    assert finding.severity == Severity.MEDIUM
    assert finding.cve_id == "CVE-2026-0001"
    assert finding.evidence[0].data["extracted"] == ["abc123"]
    assert result.loaded_templates == 1
    assert result.matched_requests == 1
    assert result.skipped_templates
    assert any("unsupported-top-level" in item for item in result.skipped_features)
    assert any("matcher:dsl" in item for item in result.skipped_features)


def test_http_engine_runs_native_templates_when_enabled(tmp_path):
    template = tmp_path / "detect.yaml"
    template.write_text(
        """
id: root-marker
info:
  name: Root Marker
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: body
        words: ["marker"]
""".strip(),
        encoding="utf-8",
    )

    class _EngineClient(_NativeClient):
        def request(self, host, port, method, path, tls, timeout):
            url = f"{'https' if tls else 'http'}://{host}:{port}{path}"
            status, hdrs, text = self.routes.get(url, (404, [], "missing"))
            return PoliteResponse(status, hdrs, text.encode("utf-8"), {"url": url})

        def is_access_blocked(self, response):
            return False

        def is_tripped(self, host):
            return False

        def throttle(self, host):
            return None

    client = _EngineClient({
        "http://example.test:80/": (200, [("Server", "Apache")], "<html><title>x</title>marker</html>"),
        "http://example.test/": (200, [("Server", "Apache")], "<html><title>x</title>marker</html>"),
    })
    service = Service(host="example.test", port=80, protocol="tcp", state="open", service_name="http")
    engine = HttpEngine(client=client)

    findings = engine.run(service, {
        "validation_level": "full",
        "web_template_engine": {"enabled": True, "include_packaged": False, "template_dir": str(tmp_path)},
        "web_archive_discovery": {"enabled": False},
        "web_content_fuzzer": {"enabled": False},
        "web_param_discovery": {"enabled": False},
    })

    assert any(f.title == "Root Marker" for f in findings)


def test_native_nuclei_benchmark_records_templates_per_s(tmp_path):
    for index in range(10):
        (tmp_path / f"t{index}.yaml").write_text(
            f"""
id: template-{index}
info:
  name: Template {index}
  severity: info
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/probe/{index}"
    matchers:
      - type: status
        status: [200]
""".strip(),
            encoding="utf-8",
        )
    routes = {
        f"http://example.test/probe/{index}": (200, [("Server", "Example")], "ok")
        for index in range(10)
    }
    client = _NativeClient(routes)

    started = perf_counter()
    result = asyncio.run(run_native_nuclei_async(
        client,  # type: ignore[arg-type]
        {"host": "example.test", "port": 80, "protocol": "tcp", "service": "http"},
        {"web_template_engine": {"enabled": True, "include_packaged": False, "template_dir": str(tmp_path), "concurrency": 5}},
    ))
    elapsed = perf_counter() - started

    assert len(result.findings) == 10
    assert result.templates_per_s > 0
    assert result.loaded_templates / max(elapsed, 0.001) >= 100.0

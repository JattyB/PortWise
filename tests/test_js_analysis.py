from __future__ import annotations

from portwise.modules.http.js_analysis import _candidate_js_urls, extract_js_endpoints
from portwise.modules.http.surface import DiscoveredSurface


def test_js_endpoint_extraction_fixture_precision_recall():
    body = """
    const rel = '/api/v1/users';
    const relWithQuery = "/graphql?op=listUsers";
    const nested = '../rest/admin/audit';
    const scriptUrl = "/static/app.js";
    fetch('/api/v2/orders');
    axios.post("/auth/login", payload);
    XMLHttpRequest.open("GET", "/internal/health");
    const abs = "https://app.example.test/api/report";
    const sameOriginUrl = new URL('/comments/list', window.location.origin);
    const offOrigin = "https://evil.example.net/api/leak";
    const ignored1 = "mailto:ops@example.test";
    const ignored2 = "javascript:void(0)";
    const ignored3 = "data:text/plain,hello";
    const ignored4 = "/assets/site.css";
    <script src="/static/runtime.js"></script>
    """

    base_url = "https://app.example.test/dashboard/main.js"
    extracted = extract_js_endpoints(body, base_url, base_url)
    urls = {item.url for item in extracted}

    must_extract = {
        "https://app.example.test/api/v1/users",
        "https://app.example.test/graphql?op=listUsers",
        "https://app.example.test/rest/admin/audit",
        "https://app.example.test/static/app.js",
        "https://app.example.test/api/v2/orders",
        "https://app.example.test/auth/login",
        "https://app.example.test/internal/health",
        "https://app.example.test/api/report",
        "https://app.example.test/comments/list",
        "https://app.example.test/static/runtime.js",
    }
    must_not_extract = {
        "https://evil.example.net/api/leak",
        "mailto:ops@example.test",
        "javascript:void(0)",
        "data:text/plain,hello",
        "https://app.example.test/assets/site.css",
    }

    tp = len(urls & must_extract)
    fp = len(urls & must_not_extract)
    fn = len(must_extract - urls)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    assert fp == 0, f"must-not-extract URLs were returned: {urls & must_not_extract}"
    assert precision >= 0.95, (precision, sorted(urls))
    assert recall >= 0.95, (recall, sorted(urls))


def test_js_fetch_candidates_are_same_origin_only():
    surface = DiscoveredSurface("app.example.test")
    surface.js_files.update({
        "https://app.example.test/static/app.js",
        "https://www.google-analytics.com/analytics.js",
    })
    assert _candidate_js_urls(surface, "https://app.example.test/") == [
        "https://app.example.test/static/app.js"
    ]

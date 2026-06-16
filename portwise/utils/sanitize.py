from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Sanitization for stored request/response transcripts
# ---------------------------------------------------------------------------

_REDACTED = "<redacted>"
_BODY_CAP_DEFAULT = 2048  # bytes

_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token",
})

# Patterns in body / URL query strings
_SECRET_PARAM_PATTERNS = re.compile(
    r"(api_key|token|password|passwd|secret|auth|apikey|api-key|access_token|refresh_token)"
    r"=[^&\s\"']{1,256}",
    re.IGNORECASE,
)


def sanitize_headers(headers: dict[str, str] | list[tuple[str, str]]) -> dict[str, str]:
    """Redact sensitive header values. Returns a plain dict."""
    if isinstance(headers, list):
        headers = dict(headers)
    return {
        k: (_REDACTED if k.lower() in _SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


def sanitize_body(body: str | bytes, cap: int = _BODY_CAP_DEFAULT) -> str:
    """Cap body size and redact secret parameter patterns."""
    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
    else:
        text = str(body)
    text = text[:cap]
    text = _SECRET_PARAM_PATTERNS.sub(lambda m: m.group(0).split("=")[0] + "=" + _REDACTED, text)
    return text


def sanitize_url(url: str) -> str:
    """Redact secret parameter values in URLs."""
    return _SECRET_PARAM_PATTERNS.sub(lambda m: m.group(0).split("=")[0] + "=" + _REDACTED, url)


def build_transcript(
    method: str,
    url: str,
    request_headers: dict[str, str],
    request_body: str | bytes | None,
    response_status: int,
    response_reason: str,
    response_headers: dict[str, str] | list[tuple[str, str]],
    response_body: str | bytes,
    timing_ms: int,
    observed_at: str,
    body_cap: int = _BODY_CAP_DEFAULT,
) -> dict:
    """Build a sanitized transcript dict for Evidence.data['transcript']."""
    return {
        "request": {
            "method": method.upper(),
            "url": sanitize_url(url),
            "headers": sanitize_headers(request_headers),
            "body_sent": sanitize_body(request_body, body_cap) if request_body else None,
        },
        "response": {
            "status": response_status,
            "reason": response_reason,
            "headers": sanitize_headers(response_headers),
            "body_excerpt": sanitize_body(response_body, body_cap),
            "body_bytes_len": len(response_body) if isinstance(response_body, bytes) else len(response_body.encode("utf-8", errors="replace")),
        },
        "timing_ms": timing_ms,
        "observed_at": observed_at,
    }

from __future__ import annotations

import re
from typing import Any

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.utils.http_client import PoliteHttpClient

# ---------------------------------------------------------------------------
# CMS / framework fingerprint rules
# ---------------------------------------------------------------------------
# Each entry: (cms_name, version_regex_or_None, detection_fn)
# Detection: fn(headers, cookies, body, path_hit_map) -> version | None

_WP_VERSION_RE = re.compile(r'<meta name="generator" content="WordPress ([0-9.]+)"', re.IGNORECASE)
_JOOMLA_VERSION_RE = re.compile(r'<meta name="generator" content="Joomla! ([0-9.]+)"', re.IGNORECASE)
_DRUPAL_VERSION_RE = re.compile(r'Drupal ([0-9.]+)', re.IGNORECASE)
_DJANGO_VERSION_RE = re.compile(r'Django ([0-9.]+)', re.IGNORECASE)


def _detect_wordpress(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    if paths.get("/wp-login.php") == 200 or paths.get("/wp-admin/") in (200, 301, 302):
        m = _WP_VERSION_RE.search(body)
        return m.group(1) if m else "unknown"
    if "wordpress_" in " ".join(cookies) or "/wp-content/" in body or "/wp-includes/" in body:
        m = _WP_VERSION_RE.search(body)
        return m.group(1) if m else "unknown"
    return None


def _detect_joomla(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    if paths.get("/administrator/") in (200, 301, 302):
        m = _JOOMLA_VERSION_RE.search(body)
        return m.group(1) if m else "unknown"
    if "joomla" in body.lower():
        m = _JOOMLA_VERSION_RE.search(body)
        return m.group(1) if m else None
    return None


def _detect_drupal(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    if paths.get("/sites/default/") == 200 or paths.get("/user/login") in (200, 301, 302):
        m = _DRUPAL_VERSION_RE.search(body)
        return m.group(1) if m else "unknown"
    if "drupal" in headers.get("x-generator", "").lower() or "drupal" in body.lower():
        m = _DRUPAL_VERSION_RE.search(body)
        return m.group(1) if m else "unknown"
    return None


def _detect_magento(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    if paths.get("/app/etc/local.xml") == 200 or "skin/frontend/default/magento" in body:
        return "unknown"
    if "mage" in " ".join(cookies).lower():
        return "unknown"
    return None


def _detect_django(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    if "csrftoken" in cookies:
        return "unknown"
    if headers.get("x-powered-by", "").startswith("Django"):
        m = _DJANGO_VERSION_RE.search(headers.get("x-powered-by", ""))
        return m.group(1) if m else "unknown"
    return None


def _detect_laravel(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    if "laravel_session" in cookies or "laravel_token" in cookies:
        return "unknown"
    return None


def _detect_express(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    if "express" in headers.get("x-powered-by", "").lower():
        return "unknown"
    if "connect.sid" in cookies:
        return "unknown"
    return None


def _detect_spring(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    if "jsessionid" in cookies:
        if "spring" in body.lower() or paths.get("/actuator/health") in (200, 401):
            return "unknown"
    return None


def _detect_aspnet(headers: dict, cookies: dict, body: str, paths: dict) -> str | None:
    powered = headers.get("x-powered-by", "")
    aspnet = headers.get("x-aspnet-version", "")
    if "asp.net" in powered.lower() or aspnet:
        return aspnet or "unknown"
    if "asp.net_sessionid" in cookies or "__requestverificationtoken" in cookies:
        return "unknown"
    return None


_DETECTORS: list[tuple[str, list[str], Any]] = [
    ("WordPress", ["/wp-login.php", "/wp-admin/"], _detect_wordpress),
    ("Joomla", ["/administrator/"], _detect_joomla),
    ("Drupal", ["/sites/default/", "/user/login"], _detect_drupal),
    ("Magento", ["/app/etc/local.xml"], _detect_magento),
    ("Django", [], _detect_django),
    ("Laravel", [], _detect_laravel),
    ("Express", [], _detect_express),
    ("Spring", ["/actuator/health"], _detect_spring),
    ("ASP.NET", [], _detect_aspnet),
]

_CMS_EOL: dict[str, list[str]] = {
    "WordPress": ["3.", "4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9"],
    "Joomla": ["2.", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "3.9"],
    "Drupal": ["6.", "7.", "8."],
}


def _build_wp_cpe(version: str) -> str | None:
    if version and version != "unknown":
        return f"cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*"
    return None


def run_cms_fingerprint(
    host: str,
    port: int,
    tls: bool,
    timeout: float,
    client: PoliteHttpClient,
    target: dict[str, Any],
    homepage_headers: dict[str, str],
    homepage_cookies: dict[str, str],
    homepage_body: str,
    module: str = "http",
) -> list[Finding]:
    """Detect CMS/framework and return findings. No auth, GET-only."""
    findings: list[Finding] = []

    # Probe extra CMS-specific paths
    path_hits: dict[str, int] = {}
    all_paths: set[str] = set()
    for _, cms_paths, _ in _DETECTORS:
        all_paths.update(cms_paths)

    for path in all_paths:
        if client.is_tripped(host):
            break
        client.throttle(host)
        try:
            resp = client.request(host, port, "HEAD", path, tls, timeout)
            path_hits[path] = resp.status
        except Exception:
            pass

    for cms_name, _, detector in _DETECTORS:
        version = detector(homepage_headers, homepage_cookies, homepage_body, path_hits)
        if version is None:
            continue

        eol_prefixes = _CMS_EOL.get(cms_name, [])
        is_eol = version != "unknown" and any(version.startswith(pfx) for pfx in eol_prefixes)
        severity = Severity.LOW if not is_eol else Severity.MEDIUM
        category = FindingCategory.INFORMATION if not is_eol else FindingCategory.BEST_PRACTICE
        version_label = version if version != "unknown" else "(version unknown)"
        scheme = "https" if tls else "http"
        url = f"{scheme}://{host}:{port}/"

        evidence = Evidence(
            f"module:{module}:cms",
            f"{cms_name} {version_label} detected at {url}.",
            4,
            {"cms": cms_name, "version": version, "url": url},
        )
        desc = f"{cms_name} {version_label} detected via response fingerprinting at {url}."
        if is_eol:
            desc += f" {cms_name} {version} is end-of-life and no longer receives security updates."

        cpe = _build_wp_cpe(version) if cms_name == "WordPress" and version != "unknown" else None
        tags = ["cms-detection", cms_name.lower()]
        if cpe:
            tags.append("cpe-available")

        findings.append(Finding(
            title=f"CMS Detected: {cms_name} {version_label}",
            severity=severity,
            asset=str(target.get("host", host)),
            port=port,
            protocol=str(target.get("protocol", "tcp")),
            service=str(target.get("service", "")),
            description=desc,
            recommendation=f"Keep {cms_name} and its plugins/themes up to date. Monitor vendor security advisories.",
            confidence=Confidence.LIKELY,
            evidence_strength=evidence.strength,
            type="Fingerprint",
            module=module,
            false_positive_risk="low",
            manual_validation=False,
            evidence=[evidence],
            category=category,
            tags=tags,
        ))

        # For WordPress with known version: feed into CVE pipeline note
        if cms_name == "WordPress" and cpe:
            findings.append(Finding(
                title=f"WordPress {version} — CVE Enrichment Recommended",
                severity=Severity.INFO,
                asset=str(target.get("host", host)),
                port=port,
                protocol=str(target.get("protocol", "tcp")),
                service=str(target.get("service", "")),
                description=f"WordPress {version} detected (CPE: {cpe}). Check NVD for known CVEs affecting this version.",
                recommendation=f"Run CVE enrichment with CPE {cpe} to identify known vulnerabilities.",
                confidence=Confidence.INFORMATIONAL,
                evidence_strength=3,
                type="Enrichment Lead",
                module=module,
                false_positive_risk="low",
                manual_validation=True,
                evidence=[Evidence(f"module:{module}:cms", f"CPE generated for WordPress {version}", 3, {"cpe": cpe})],
                category=FindingCategory.INFORMATION,
                tags=["wordpress", "cpe-available"],
            ))

    return findings

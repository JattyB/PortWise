from __future__ import annotations

import random
import string
from typing import Any

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.utils.http_client import PoliteHttpClient

# ---------------------------------------------------------------------------
# Curated high-signal wordlist
# ---------------------------------------------------------------------------
_WORDLIST: list[tuple[str, str, str]] = [
    # (path, category, label)
    # === Safe-level paths (always checked) ===
    ("/robots.txt", "info", "Robots.txt"),
    ("/sitemap.xml", "info", "Sitemap"),
    ("/.well-known/security.txt", "info", "Security.txt"),
    # === VCS / source exposure ===
    ("/.git/", "vcs", "Git Repository"),
    ("/.git/HEAD", "vcs", "Git HEAD"),
    ("/.git/config", "vcs", "Git Config"),
    ("/.svn/entries", "vcs", "SVN Repository"),
    ("/.hg/", "vcs", "Mercurial Repository"),
    # === Backup / archive files ===
    ("/backup/", "backup", "Backup Directory"),
    ("/backup.zip", "backup", "Backup Archive"),
    ("/backup.tar.gz", "backup", "Backup Archive"),
    ("/db.sql", "backup", "Database Dump"),
    ("/database.sql", "backup", "Database Dump"),
    ("/dump.sql", "backup", "Database Dump"),
    ("/data.sql", "backup", "Database Dump"),
    # === Config files ===
    ("/.env", "config", "Environment File"),
    ("/.env.backup", "config", "Environment Backup"),
    ("/.env.production", "config", "Production Env File"),
    ("/config.php", "config", "PHP Config"),
    ("/config.inc.php", "config", "PHP Config"),
    ("/configuration.php", "config", "PHP Config"),
    ("/web.config", "config", "IIS Web Config"),
    ("/app.config", "config", "App Config"),
    ("/.htaccess", "config", "Apache Htaccess"),
    ("/local.xml", "config", "Magento Local Config"),
    ("/app/etc/local.xml", "config", "Magento Local Config"),
    # === CI/CD / secrets ===
    ("/.gitlab-ci.yml", "cicd", "GitLab CI Config"),
    ("/Jenkinsfile", "cicd", "Jenkins Pipeline"),
    ("/.travis.yml", "cicd", "Travis CI Config"),
    ("/Dockerfile", "cicd", "Dockerfile"),
    ("/docker-compose.yml", "cicd", "Docker Compose"),
    # === Docs / disclosure ===
    ("/README.md", "info", "README"),
    ("/CHANGELOG.md", "info", "Changelog"),
    ("/CHANGELOG", "info", "Changelog"),
    ("/LICENSE", "info", "License File"),
    # === Admin / management ===
    ("/admin/", "admin", "Admin Panel"),
    ("/admin/login", "admin", "Admin Login"),
    ("/administrator/", "admin", "Admin Panel"),
    ("/manager/", "admin", "Manager Panel"),
    ("/phpmyadmin/", "admin", "phpMyAdmin"),
    ("/pma/", "admin", "phpMyAdmin"),
    # === API ===
    ("/api/", "info", "API Root"),
    ("/api/v1/", "info", "API v1"),
    ("/api/v2/", "info", "API v2"),
    ("/api/docs", "info", "API Docs"),
    ("/swagger.json", "info", "Swagger Spec"),
    ("/openapi.json", "info", "OpenAPI Spec"),
    # === Upload / user content ===
    ("/uploads/", "info", "Uploads Directory"),
    ("/upload/", "info", "Upload Directory"),
    ("/files/", "info", "Files Directory"),
    # === Dev / test ===
    ("/test/", "info", "Test Directory"),
    ("/dev/", "info", "Dev Directory"),
    ("/staging/", "info", "Staging Directory"),
    ("/phpinfo.php", "config", "PHP Info Page"),
    ("/info.php", "config", "PHP Info Page"),
    ("/server-status", "config", "Apache Server Status"),
    ("/server-info", "config", "Apache Server Info"),
]

# Only these are checked at "safe" validation level
_SAFE_LEVEL_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}

# Content signatures: a discovered path is only treated as a CONFIRMED real
# exposure when its body actually looks like the sensitive file. Without this,
# SPAs / catch-all servers that return index.html for every path (HTTP 200)
# produced confident-but-wrong "Git/Env/Config exposed" findings. Each entry maps
# a path (or suffix) to substrings, ANY of which must appear (case-insensitive).
_PATH_SIGNATURES: dict[str, tuple[str, ...]] = {
    "/.git/head": ("ref:", "refs/heads"),
    "/.git/config": ("[core]", "repositoryformatversion"),
    "/.svn/entries": ("dir", "svn:"),
    "/.env": ("=",),  # KEY=value; combined with the HTML guard below
    "/web.config": ("<configuration", "<system.web"),
    "/.htaccess": ("rewriteengine", "require ", "order ", "deny from"),
    "/dockerfile": ("from ", "run ", "cmd "),
    "/docker-compose.yml": ("services:", "version:", "image:"),
    "/.gitlab-ci.yml": ("stages:", "script:", "image:"),
    "/swagger.json": ('"swagger"', '"openapi"', '"paths"'),
    "/openapi.json": ('"openapi"', '"paths"'),
    "/phpinfo.php": ("phpinfo()", "php version", "php credits"),
    "/info.php": ("phpinfo()", "php version"),
    "/server-status": ("apache server status", "server uptime"),
    "/server-info": ("apache server information", "server settings"),
}

# Suffix-based signatures for families of files.
_SUFFIX_SIGNATURES: dict[str, tuple[str, ...]] = {
    ".sql": ("insert into", "create table", "drop table", "-- mysql", "values ("),
    ".php": ("<?php", "<?=", "define("),  # source disclosure (executed PHP is empty/HTML)
    "local.xml": ("<config", "<connection", "<host>"),
}


def _looks_like_html(body: str) -> bool:
    head = body[:512].lower()
    return "<!doctype html" in head or "<html" in head or "<head" in head


def _signature_for(path: str) -> tuple[str, ...] | None:
    pl = path.lower()
    if pl in _PATH_SIGNATURES:
        return _PATH_SIGNATURES[pl]
    for suffix, sig in _SUFFIX_SIGNATURES.items():
        if pl.endswith(suffix):
            return sig
    return None


def _content_verdict(path: str, category: str, body: str) -> str:
    """Return 'confirmed', 'needs_validation', or 'drop' for a 200-body hit."""
    bl = body.lower()
    sig = _signature_for(path)
    if sig is not None:
        if any(s in bl for s in sig):
            # For .env, also require it not be an HTML page that merely contains '='.
            if path.lower() == "/.env" and _looks_like_html(body):
                return "drop"
            return "confirmed"
        return "drop"  # signature defined but body doesn't match → false positive
    # No signature for this path. High-risk categories returning an HTML page on a
    # non-HTML path are almost always a catch-all/SPA response → demote, don't confirm.
    if category in ("vcs", "backup", "config", "cicd") and _looks_like_html(body):
        return "needs_validation"
    return "confirmed"

_CATEGORY_SEVERITY: dict[str, tuple[Severity, FindingCategory]] = {
    "vcs": (Severity.HIGH, FindingCategory.VULNERABILITY),
    "backup": (Severity.HIGH, FindingCategory.VULNERABILITY),
    "config": (Severity.HIGH, FindingCategory.VULNERABILITY),
    "cicd": (Severity.MEDIUM, FindingCategory.VULNERABILITY),
    "admin": (Severity.MEDIUM, FindingCategory.VULNERABILITY),
    "info": (Severity.LOW, FindingCategory.INFORMATION),
}


def _random_path() -> str:
    suffix = "".join(random.choices(string.ascii_lowercase, k=12))
    return f"/portwise-nonexistent-{suffix}"


def _soft_404_fingerprint(client: PoliteHttpClient, host: str, port: int, tls: bool, timeout: float) -> tuple[int, str]:
    """Fetch a random non-existent path to fingerprint the site's 404 response."""
    try:
        resp = client.request(host, port, "GET", _random_path(), tls, timeout)
        body = resp.read(512).decode("utf-8", errors="replace")
        return resp.status, body[:256]
    except Exception:
        return 404, ""


def _body_matches_soft_404(body: str, soft_status: int, soft_body: str) -> bool:
    """True if this response looks like the site's generic 404-as-200 response."""
    if soft_status == 200 and soft_body and len(soft_body) > 20:
        # Simple similarity: if >80% of 32-char chunks overlap
        chunks = [soft_body[i:i+32] for i in range(0, len(soft_body)-32, 32)]
        matches = sum(1 for c in chunks if c in body)
        if chunks and matches / len(chunks) > 0.8:
            return True
    return False


def run_content_discovery(
    host: str,
    port: int,
    tls: bool,
    timeout: float,
    client: PoliteHttpClient,
    target: dict[str, Any],
    config: dict[str, Any],
    validation_level: str = "safe",
    module: str = "http",
) -> list[Finding]:
    """
    Run content discovery. At 'safe' level only fetches robots.txt/sitemap/security.txt.
    At 'proof' or 'controlled' level runs the full curated wordlist.
    Respects PoliteHttpClient budget + circuit breaker.
    """
    web_config = config.get("web_content_discovery", {}) if isinstance(config.get("web_content_discovery"), dict) else {}
    max_requests = int(web_config.get("max_requests", 150))
    enabled = bool(web_config.get("enabled", True))
    if not enabled:
        return []

    is_full = validation_level != "safe"
    paths_to_check = [
        (path, cat, label)
        for path, cat, label in _WORDLIST
        if is_full or path in _SAFE_LEVEL_PATHS
    ]

    findings: list[Finding] = []
    request_count = 0

    # Fingerprint the soft-404 response first
    if client.is_tripped(host):
        return []
    client.throttle(host)
    soft_status, soft_body = _soft_404_fingerprint(client, host, port, tls, timeout)
    request_count += 1

    for path, category, label in paths_to_check:
        if request_count >= max_requests:
            break
        if client.is_tripped(host):
            break
        client.throttle(host)
        request_count += 1
        try:
            resp = client.request(host, port, "GET", path, tls, timeout)
            body = resp.read(2048).decode("utf-8", errors="replace")
            status = resp.status
        except Exception:
            continue

        if status != 200:
            continue
        if not body.strip():
            continue
        if _body_matches_soft_404(body, soft_status, soft_body):
            continue

        verdict = _content_verdict(path, category, body)
        if verdict == "drop":
            continue
        catchall = soft_status == 200

        severity, cat_enum = _CATEGORY_SEVERITY.get(category, (Severity.LOW, FindingCategory.INFORMATION))
        if verdict == "needs_validation" or catchall:
            confidence = Confidence.NEEDS_MANUAL_VALIDATION
            fp_risk = "medium"
            manual = True
            # Demote high severities one notch when we couldn't content-confirm.
            if severity == Severity.HIGH:
                severity = Severity.MEDIUM
        else:
            confidence = Confidence.CONFIRMED
            fp_risk = "low"
            manual = False

        scheme = "https" if tls else "http"
        url = f"{scheme}://{host}:{port}{path}"
        proof_note = "content-signature matched" if verdict == "confirmed" and not catchall else "body differs from 404 but not content-verified"
        evidence = Evidence(
            f"module:{module}:content-discovery",
            f"HTTP 200 on {path}; {proof_note}.",
            4 if (category in ("vcs", "backup", "config") and verdict == "confirmed") else 3,
            {"url": url, "status": status, "verdict": verdict, "body_excerpt": body[:500]},
        )
        findings.append(Finding(
            title=f"Sensitive File/Path Discovered: {label}",
            severity=severity,
            asset=str(target.get("host", host)),
            port=port,
            protocol=str(target.get("protocol", "tcp")),
            service=str(target.get("service", "")),
            description=f"Content discovery found accessible path {path} ({label}) at {url}. {proof_note.capitalize()}.",
            recommendation="Remove or restrict access to this path. Ensure VCS directories, backup files, and configuration files are not web-accessible.",
            confidence=confidence,
            evidence_strength=evidence.strength,
            type="Exposure",
            module=module,
            false_positive_risk=fp_risk,
            manual_validation=manual,
            evidence=[evidence],
            category=cat_enum,
            tags=["content-discovery", category],
        ))

    return findings

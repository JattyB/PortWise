from __future__ import annotations

import re

from portwise.core.models import Evidence, Finding, FindingCategory, Service, Severity
from portwise.modules.http.cms_fingerprint import run_cms_fingerprint
from portwise.modules.http.content_discovery import run_content_discovery
from portwise.modules.http.injection_indicators import run_injection_indicators
from portwise.modules.http.signatures import has_password_form, match_admin_panel, match_default_install
from portwise.modules.http.web_crawl import run_web_crawl
from portwise.scanners.nse import nse_http_methods
from portwise.utils.http_client import PoliteHttpClient, PoliteResponse

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

SAFE_PATHS = (
    "/.git/HEAD",
    "/.env",
    "/server-status",
    "/phpinfo.php",
    "/swagger-ui/",
    "/swagger.json",
    "/v2/api-docs",
    "/actuator/health",
    "/actuator/env",
    "/admin",
    "/login",
    "/manager/html",
    "/phpmyadmin/",
    "/adminer.php",
    "/jenkins/",
    "/grafana/login",
    "/kibana/",
    "/portainer/",
    "/wp-login.php",
    "/webmin/",
    "/host-manager/html",
    "/solr/",
)


class HttpEngine:
    def __init__(
        self,
        timeout: float = 5.0,
        paths: tuple[str, ...] = (),
        max_body: int = 262_144,
        client: PoliteHttpClient | None = None,
    ) -> None:
        self.timeout = timeout
        self.paths = paths or SAFE_PATHS
        self.max_body = max_body
        self.client = client or PoliteHttpClient()

    @staticmethod
    def should_run(service: Service) -> bool:
        text = " ".join([service.service_name, service.product, service.extrainfo]).lower()
        return "http" in text or "web" in text or service.port in {80, 443, 8000, 8080, 8443}

    def run(self, service: Service, config: dict | None = None) -> list[Finding]:
        config = config or {}
        https_ports = {443, 8443, 9443, 2053, 2083, 2087, 2096, 4443, 5443, 7443, 12443, 8834, 10443}
        tls = service.tunnel == "ssl" or "https" in service.service_name.lower() or service.port in https_ports
        findings: list[Finding] = []
        try:
            head = self._request(service.host, service.port, "HEAD", "/", tls)
            get = self._request(service.host, service.port, "GET", "/", tls)
            options = self._request(service.host, service.port, "OPTIONS", "/", tls)
        except OSError as exc:
            # Try the opposite scheme before giving up (ambiguous alt ports).
            try:
                tls = not tls
                head = self._request(service.host, service.port, "HEAD", "/", tls)
                get = self._request(service.host, service.port, "GET", "/", tls)
                options = self._request(service.host, service.port, "OPTIONS", "/", tls)
            except OSError:
                return [self._failed_check(service, f"HTTP check failed: {exc}")]

        if self.client.is_access_blocked(get):
            return [self._blocked_finding(service, get)]

        headers = {k.lower(): v for k, v in get.getheaders()}
        findings.extend(self._header_findings(service, headers, tls))
        findings.extend(self._cookie_findings(service, get.getheaders()))
        findings.extend(self._method_findings(service, options))
        findings.extend(self._safe_path_findings(service, tls))

        body_text = get.read(self.max_body).decode("utf-8", errors="ignore")
        title = self._extract_title_from_body(body_text)
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server:
            evidence = Evidence("http-header", "Server header disclosed product metadata.", 5, {"server": server})
            findings.append(Finding(
                title="HTTP Server Version Disclosure",
                severity=Severity.LOW,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="The HTTP Server header is visible.",
                recommendation="Review whether product/version headers are required.",
                evidence_strength=5,
                type="http-disclosure",
                module="http",
                evidence=[evidence],
                tags=["safe-active"],
                category=FindingCategory.VULNERABILITY,
            ))
        if powered:
            evidence = Evidence("http-header", "X-Powered-By header disclosed framework metadata.", 5, {"x-powered-by": powered})
            findings.append(Finding(
                title="HTTP Framework Version Disclosure",
                severity=Severity.LOW,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="The X-Powered-By header is visible.",
                recommendation="Remove framework disclosure headers where practical.",
                evidence_strength=5,
                type="http-disclosure",
                module="http",
                evidence=[evidence],
                tags=["safe-active"],
                category=FindingCategory.VULNERABILITY,
            ))
        if title or server or head.status:
            evidence = Evidence(
                source="http-basic",
                description="HTTP service metadata collected using GET/HEAD /.",
                strength=4,
                data={"title": title, "server": server, "x-powered-by": powered, "status": get.status, "head_status": head.status},
            )
            findings.append(Finding(
                title="HTTP Service Metadata",
                severity=Severity.INFO,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="HTTP service responded to safe metadata collection.",
                evidence_strength=4,
                type="http-metadata",
                module="http",
                evidence=[evidence],
                tags=["safe-active"],
                category=FindingCategory.INFORMATION,
            ))

        validation_level = str(config.get("validation_level", "recon"))
        target_dict: dict = {
            "host": service.host,
            "port": service.port,
            "protocol": service.protocol,
            "service": service.service_name,
        }
        cookies_dict = {
            k.strip(): v.strip()
            for hdr_val in (v for k, v in get.getheaders() if k.lower() == "set-cookie")
            for part in hdr_val.split(";")
            if "=" in part
            for k, v in [part.split("=", 1)]
        }
        findings.extend(run_content_discovery(
            host=service.host, port=service.port, tls=tls,
            timeout=self.timeout, client=self.client,
            target=target_dict, config=config,
            validation_level=validation_level,
        ))
        findings.extend(run_cms_fingerprint(
            host=service.host, port=service.port, tls=tls,
            timeout=self.timeout, client=self.client,
            target=target_dict,
            homepage_headers=headers,
            homepage_cookies=cookies_dict,
            homepage_body=body_text,
        ))
        findings.extend(run_injection_indicators(
            host=service.host, port=service.port, tls=tls,
            timeout=self.timeout, client=self.client,
            target=target_dict,
            homepage_body=body_text,
            validation_level=validation_level,
        ))
        findings.extend(run_web_crawl(
            host=service.host, port=service.port, tls=tls,
            timeout=self.timeout, client=self.client,
            target=target_dict, config=config,
            homepage_body=body_text,
            validation_level=validation_level,
        ))
        return findings

    def _request(self, host: str, port: int, method: str, path: str, tls: bool) -> PoliteResponse:
        return self.client.request(host, port, method, path, tls, timeout=self.timeout)

    @staticmethod
    def _extract_title_from_body(body: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""

    def _header_findings(self, service: Service, headers: dict[str, str], tls: bool) -> list[Finding]:
        findings: list[Finding] = []
        for header in SECURITY_HEADERS:
            if header.lower() in headers:
                continue
            severity = Severity.LOW
            if header == "Strict-Transport-Security" and not tls:
                severity = Severity.INFO
            evidence = Evidence("http-headers", f"{header} header was not present.", 5, {"header": header})
            title = {
                "Strict-Transport-Security": "Missing HSTS Header",
                "Content-Security-Policy": "Missing Content Security Policy",
                "X-Frame-Options": "Missing X-Frame-Options",
                "X-Content-Type-Options": "Missing X-Content-Type-Options",
            }.get(header, f"Missing HTTP Security Header: {header}")
            findings.append(Finding(
                title=title,
                severity=severity,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description=f"The response did not include {header}. Applicability depends on application context.",
                recommendation="Review whether the header is appropriate for this application and add it where applicable.",
                evidence_strength=5,
                type="http-header",
                module="http",
                evidence=[evidence],
                tags=["safe-active"],
                category=FindingCategory.BEST_PRACTICE,
            ))
        return findings

    def _cookie_findings(self, service: Service, raw_headers: list[tuple[str, str]]) -> list[Finding]:
        findings: list[Finding] = []
        for name, value in raw_headers:
            if name.lower() != "set-cookie":
                continue
            lower = value.lower()
            missing = [attr for attr in ("secure", "httponly", "samesite") if attr not in lower]
            if not missing:
                continue
            evidence = Evidence("http-cookie", "Cookie missing recommended attributes.", 5, {"cookie": value, "missing": missing})
            findings.append(Finding(
                title="Cookie Missing Security Attributes",
                severity=Severity.LOW,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description=f"Set-Cookie is missing: {', '.join(missing)}.",
                recommendation="Set Secure, HttpOnly, and SameSite where compatible with application behavior.",
                evidence_strength=5,
                type="http-cookie",
                module="http",
                evidence=[evidence],
                tags=["safe-active"],
                category=FindingCategory.BEST_PRACTICE,
            ))
        return findings

    def _method_findings(self, service: Service, options: PoliteResponse) -> list[Finding]:
        allow = options.getheader("Allow", "")
        # Merge OPTIONS header with NSE http-methods for authoritative method list
        all_methods: set[str] = {m.strip().upper() for m in allow.split(",") if m.strip()}
        for m in (nse_http_methods(service) or []):
            all_methods.add(m.upper())
        findings: list[Finding] = []
        if "TRACE" in all_methods:
            evidence = Evidence("http-options", "OPTIONS Allow header includes TRACE.", 5, {"allow": allow})
            findings.append(Finding(
                title="HTTP TRACE Method Enabled",
                severity=Severity.LOW,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="The server advertises TRACE in the Allow header.",
                recommendation="Disable TRACE unless explicitly required.",
                evidence_strength=5,
                type="http-method",
                module="http",
                evidence=[evidence],
                tags=["safe-active"],
                category=FindingCategory.HYGIENE,
            ))
        dangerous = [method for method in ("PUT", "DELETE") if method in all_methods]
        if dangerous:
            evidence = Evidence("http-options", "OPTIONS Allow header includes potentially dangerous methods.", 5, {"allow": allow, "methods": dangerous})
            findings.append(Finding(
                title="Dangerous HTTP Methods Allowed",
                severity=Severity.MEDIUM,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description=f"The server advertises potentially dangerous methods: {', '.join(dangerous)}.",
                recommendation="Disable write-capable HTTP methods unless explicitly required and protected.",
                evidence_strength=5,
                type="http-method",
                module="http",
                evidence=[evidence],
                tags=["safe-active"],
                category=FindingCategory.VULNERABILITY,
            ))
        return findings

    def _safe_path_findings(self, service: Service, tls: bool) -> list[Finding]:
        findings: list[Finding] = []
        for path in self.paths:
            if self.client.is_tripped(service.host):
                break  # circuit breaker tripped — stop hammering this host
            try:
                response = self._request(service.host, service.port, "GET", path, tls)
            except OSError:
                continue
            if response.status not in {200, 401, 403}:
                continue
            body = response.read(self.max_body).decode("utf-8", errors="ignore")
            title, severity, category = self._path_title(path, response.status, body)
            if not title:
                continue
            evidence = Evidence("http-safe-path", f"Safe GET returned HTTP {response.status}.", 5, {"path": path, "status": response.status, "sample": body[:200]})
            findings.append(Finding(
                title=title,
                severity=severity,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="A common administrative or diagnostic path responded to a safe GET request.",
                recommendation="Confirm business need and restrict access where appropriate.",
                evidence_strength=5,
                type="http-exposure",
                module="http",
                evidence=[evidence],
                tags=["safe-active"],
                category=category,
            ))
        return findings

    @staticmethod
    def _path_title(path: str, status: int, body: str) -> tuple[str | None, Severity, FindingCategory]:
        if status in {401, 403}:
            return None, Severity.INFO, FindingCategory.INFORMATION

        if status != 200:
            return None, Severity.INFO, FindingCategory.INFORMATION

        lower = body.lower()

        if path == "/.git/HEAD" and ("ref:" in lower or "refs/heads" in lower):
            return "Exposed Git Metadata", Severity.HIGH, FindingCategory.VULNERABILITY
        if path == "/.env" and ("=" in body and any(key in lower for key in ("password", "secret", "key", "database", "token"))):
            return "Exposed Environment File", Severity.HIGH, FindingCategory.VULNERABILITY
        if path == "/phpinfo.php" and "phpinfo()" in lower:
            return "Exposed phpinfo Page", Severity.HIGH, FindingCategory.VULNERABILITY
        if path.startswith("/actuator/"):
            sev = Severity.HIGH if path.endswith("/env") else Severity.MEDIUM
            return "Exposed Spring Boot Actuator Endpoint", sev, FindingCategory.VULNERABILITY
        if "index of /" in lower or "directory listing" in lower:
            return "Directory Listing Enabled", Severity.MEDIUM, FindingCategory.VULNERABILITY
        if path in {"/swagger-ui/", "/swagger.json", "/v2/api-docs"}:
            return "Exposed API Documentation", Severity.LOW, FindingCategory.INFORMATION
        if path == "/server-status":
            return "Exposed Server Status Page", Severity.MEDIUM, FindingCategory.INFORMATION

        sig = match_admin_panel(path, status, body)
        if sig:
            if sig.unauthenticated_management:
                return f"Exposed Admin Panel: {sig.name}", Severity.HIGH, FindingCategory.VULNERABILITY
            return f"Admin Panel Detected: {sig.name}", Severity.LOW, FindingCategory.INFORMATION

        sig = match_default_install(path, status, body)
        if sig:
            return f"Default Installation Page: {sig.name}", Severity.LOW, FindingCategory.HYGIENE

        if has_password_form(body):
            return "Login Page Detected", Severity.INFO, FindingCategory.INFORMATION

        return None, Severity.INFO, FindingCategory.INFORMATION

    @staticmethod
    def _failed_check(service: Service, message: str) -> Finding:
        evidence = Evidence("http-basic", message, 1, {})
        return Finding(
            title="HTTP Check Not Completed",
            severity=Severity.INFO,
            asset=service.host,
            port=service.port,
            protocol=service.protocol,
            service=service.service_name,
            description=message,
            evidence_strength=1,
            type="skipped-check",
            module="http",
            evidence=[evidence],
            tags=["check-failed"],
        )

    @staticmethod
    def _blocked_finding(service: Service, response: PoliteResponse) -> Finding:
        body = response.read(512).decode("utf-8", errors="replace")
        evidence = Evidence(
            "http-transport",
            f"Target returned HTTP {response.status} after browser-impersonated transport.",
            4,
            {
                "status": response.status,
                "headers": dict(response.getheaders()),
                "body_excerpt": body[:300],
                "impersonate": response.request_meta.get("impersonate"),
                "used_playwright": response.request_meta.get("used_playwright", False),
            },
        )
        return Finding(
            title="WAF / Access Blocked",
            severity=Severity.INFO,
            asset=service.host,
            port=service.port,
            protocol=service.protocol,
            service=service.service_name,
            description="The target blocked browser-impersonated HTTP probing. Treat this as an access-control signal, not a completed HTTP assessment.",
            recommendation="Validate from an authorized source IP or through the approved upstream proxy when deeper web testing is in scope.",
            evidence_strength=4,
            type="http-access-blocked",
            module="http",
            evidence=[evidence],
            tags=["waf", "access-blocked"],
            category=FindingCategory.INFORMATION,
        )

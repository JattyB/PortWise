from __future__ import annotations

import re
import ssl
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from urllib.parse import urljoin

from portwise.core.models import Evidence, Finding, Service, Severity


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
)


class HttpEngine:
    def __init__(self, timeout: float = 5.0, paths: tuple[str, ...] = (), max_body: int = 262_144) -> None:
        self.timeout = timeout
        self.paths = paths or SAFE_PATHS
        self.max_body = max_body

    @staticmethod
    def should_run(service: Service) -> bool:
        text = " ".join([service.service_name, service.product, service.extrainfo]).lower()
        return "http" in text or "web" in text or service.port in {80, 443, 8000, 8080, 8443}

    def run(self, service: Service) -> list[Finding]:
        tls = service.tunnel == "ssl" or "https" in service.service_name.lower() or service.port in {443, 8443}
        findings: list[Finding] = []
        try:
            head = self._request(service.host, service.port, "HEAD", "/", tls)
            get = self._request(service.host, service.port, "GET", "/", tls)
            options = self._request(service.host, service.port, "OPTIONS", "/", tls)
        except OSError as exc:
            if tls:
                try:
                    tls = False
                    head = self._request(service.host, service.port, "HEAD", "/", tls)
                    get = self._request(service.host, service.port, "GET", "/", tls)
                    options = self._request(service.host, service.port, "OPTIONS", "/", tls)
                except OSError:
                    return [self._failed_check(service, f"HTTP check failed: {exc}")]
            else:
                return [self._failed_check(service, f"HTTP check failed: {exc}")]

        headers = {k.lower(): v for k, v in get.getheaders()}
        findings.extend(self._header_findings(service, headers, tls))
        findings.extend(self._cookie_findings(service, get.getheaders()))
        findings.extend(self._method_findings(service, options))
        findings.extend(self._safe_path_findings(service, tls))

        title = self._extract_title(get)
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server:
            evidence = Evidence("http-header", "Server header disclosed product metadata.", 5, {"server": server})
            findings.append(Finding(
                title="HTTP Server Version Disclosure",
                severity=Severity.INFO,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="The HTTP Server header is visible.",
                recommendation="Review whether product/version headers are required.",
                evidence_strength=5,
                type="http-disclosure",
                evidence=[evidence],
                tags=["safe-active"],
            ))
        if powered:
            evidence = Evidence("http-header", "X-Powered-By header disclosed framework metadata.", 5, {"x-powered-by": powered})
            findings.append(Finding(
                title="HTTP Framework Version Disclosure",
                severity=Severity.INFO,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="The X-Powered-By header is visible.",
                recommendation="Remove framework disclosure headers where practical.",
                evidence_strength=5,
                type="http-disclosure",
                evidence=[evidence],
                tags=["safe-active"],
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
                evidence=[evidence],
                tags=["safe-active"],
            ))
        return findings

    def _request(self, host: str, port: int, method: str, path: str, tls: bool) -> HTTPResponse:
        context = ssl.create_default_context()
        conn_cls = HTTPSConnection if tls else HTTPConnection
        conn = conn_cls(host, port=port, timeout=self.timeout, context=context) if tls else conn_cls(host, port=port, timeout=self.timeout)
        conn.request(method, path, headers={"User-Agent": "PortWise/0.1 safe-validation"})
        return conn.getresponse()

    @staticmethod
    def _extract_title(response: HTTPResponse) -> str:
        body = response.read(262_144).decode("utf-8", errors="ignore")
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
                evidence=[evidence],
                tags=["safe-active"],
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
                evidence=[evidence],
                tags=["safe-active"],
            ))
        return findings

    def _method_findings(self, service: Service, options: HTTPResponse) -> list[Finding]:
        allow = options.getheader("Allow", "")
        findings: list[Finding] = []
        if "TRACE" not in allow.upper():
            pass
        else:
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
                evidence=[evidence],
                tags=["safe-active"],
            ))
        dangerous = [method for method in ("PUT", "DELETE") if method in allow.upper()]
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
                evidence=[evidence],
                tags=["safe-active"],
            ))
        return findings

    def _safe_path_findings(self, service: Service, tls: bool) -> list[Finding]:
        findings: list[Finding] = []
        for path in self.paths:
            try:
                response = self._request(service.host, service.port, "GET", path, tls)
            except OSError:
                continue
            if response.status not in {200, 401, 403}:
                continue
            body = response.read(self.max_body).decode("utf-8", errors="ignore")
            title, severity = self._path_title(path, response.status, body)
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
                evidence=[evidence],
                tags=["safe-active"],
            ))
        return findings

    @staticmethod
    def _path_title(path: str, status: int, body: str) -> tuple[str | None, Severity]:
        lower = body.lower()
        if status in {401, 403}:
            if path in {"/admin", "/login", "/manager/html"}:
                return "Default/Admin Login Panel Exposed", Severity.LOW
            return None, Severity.INFO
        if path == "/.git/HEAD" and ("ref:" in lower or "refs/heads" in lower):
            return "Exposed Git Metadata", Severity.HIGH
        if path == "/.env" and ("=" in body and any(key in lower for key in ("password", "secret", "key", "database", "token"))):
            return "Exposed Environment File", Severity.HIGH
        if path == "/phpinfo.php" and "phpinfo()" in lower:
            return "Exposed phpinfo Page", Severity.HIGH
        if path.startswith("/actuator/"):
            return "Exposed Spring Boot Actuator Endpoint", Severity.HIGH if path.endswith("/env") else Severity.MEDIUM
        if "index of /" in lower or "directory listing" in lower:
            return "Directory Listing Enabled", Severity.MEDIUM
        if path in {"/swagger-ui/", "/swagger.json", "/v2/api-docs"}:
            return "Exposed API Documentation", Severity.LOW
        if path in {"/admin", "/login", "/manager/html"}:
            return "Default/Admin Login Panel Exposed", Severity.LOW
        if path == "/server-status":
            return "Exposed Server Status Page", Severity.MEDIUM
        return f"Potentially Exposed HTTP Path: {path}", Severity.LOW

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
            evidence=[evidence],
            tags=["check-failed"],
        )

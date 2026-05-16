from __future__ import annotations

import socket
import ssl
from http.client import HTTPSConnection
from datetime import datetime, timezone
from typing import Any

from portwise.core.models import Evidence, Finding, Service, Severity
from portwise.modules.tls.cert_checks import days_until, parse_cert_time
from portwise.modules.tls.http_tls_checks import service_suggests_tls
from portwise.modules.tls.protocol_checks import TLS_PROTOCOLS


class TlsEngine:
    def __init__(self, timeout: float = 5.0, expiring_days: int = 30) -> None:
        self.timeout = timeout
        self.expiring_days = expiring_days

    def should_run(self, service: Service) -> bool:
        return service_suggests_tls(service) or self.detect_tls(service.host, service.port, service.hostname)

    def detect_tls(self, host: str, port: int, server_name: str | None = None) -> bool:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name or host):
                    return True
        except (OSError, ssl.SSLError):
            return False

    def run(self, service: Service) -> list[Finding]:
        findings: list[Finding] = []
        cert = self._fetch_certificate(service.host, service.port, service.hostname)
        if cert:
            findings.extend(self._certificate_findings(service, cert))
        else:
            findings.append(Finding(
                title="TLS Certificate Not Retrieved",
                severity=Severity.INFO,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="TLS appeared possible, but the certificate could not be retrieved with the local Python/OpenSSL stack.",
                evidence_strength=1,
                type="tls-info",
                evidence=[Evidence("tls-handshake", "Certificate retrieval failed.", 1)],
                tags=["not-tested"],
            ))
        findings.extend(self._protocol_findings(service))
        findings.extend(self._hsts_findings(service))
        findings.append(Finding(
            title="OCSP Stapling Not Tested",
            severity=Severity.INFO,
            asset=service.host,
            port=service.port,
            protocol=service.protocol,
            service=service.service_name,
            description="OCSP stapling was not tested by the native TLS engine.",
            evidence_strength=1,
            type="tls-info",
            evidence=[Evidence("tls-ocsp", "OCSP stapling check is not implemented in this native engine.", 1)],
            tags=["not-tested"],
        ))
        return findings

    def _fetch_certificate(self, host: str, port: int, server_name: str | None) -> dict[str, Any] | None:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name or host) as tls_sock:
                    return tls_sock.getpeercert()
        except (OSError, ssl.SSLError):
            return None

    def _certificate_findings(self, service: Service, cert: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        subject = self._name_tuple_to_dict(cert.get("subject", ()))
        issuer = self._name_tuple_to_dict(cert.get("issuer", ()))
        sans = [value for kind, value in cert.get("subjectAltName", []) if kind.lower() == "dns"]
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        serial = cert.get("serialNumber", "")
        evidence_data = {
            "subject": subject,
            "issuer": issuer,
            "sans": sans,
            "notBefore": not_before,
            "notAfter": not_after,
            "serialNumber": serial,
        }
        findings.append(Finding(
            title="TLS Certificate Metadata",
            severity=Severity.INFO,
            asset=service.host,
            port=service.port,
            protocol=service.protocol,
            service=service.service_name,
            description="TLS certificate metadata collected.",
            evidence_strength=4,
            type="tls-info",
            evidence=[Evidence("tls-certificate", "Certificate metadata retrieved via TLS handshake.", 4, evidence_data)],
            tags=["safe-active"],
        ))

        if not_after:
            expiry = parse_cert_time(not_after)
            days = days_until(expiry)
            if expiry < datetime.now(timezone.utc):
                findings.append(self._tls_finding(service, "Expired TLS Certificate", Severity.HIGH, f"Certificate expired {abs(days)} days ago.", evidence_data))
            elif days <= self.expiring_days:
                findings.append(self._tls_finding(service, "TLS Certificate Expiring Soon", Severity.MEDIUM, f"Certificate expires in {days} days.", evidence_data))

        subject_cn = subject.get("commonName", "")
        if subject and issuer and subject == issuer:
            findings.append(self._tls_finding(service, "Self-Signed TLS Certificate", Severity.LOW, "Certificate subject and issuer are identical.", evidence_data))

        hostname = service.hostname
        if hostname:
            try:
                ssl.match_hostname(cert, hostname)
            except ssl.CertificateError as exc:
                findings.append(self._tls_finding(service, "TLS Hostname Mismatch", Severity.MEDIUM, str(exc), evidence_data))
        elif subject_cn:
            findings[-1].evidence[0].data["subject_common_name"] = subject_cn
        key_info = cert.get("subjectPublicKeyInfo")
        if isinstance(key_info, dict):
            key_size = key_info.get("key_size")
            if isinstance(key_size, int) and key_size < 2048:
                findings.append(self._tls_finding(service, "Weak TLS Certificate Key", Severity.MEDIUM, f"Certificate key size appears weak: {key_size}.", evidence_data))
        return findings

    def _protocol_findings(self, service: Service) -> list[Finding]:
        findings: list[Finding] = []
        for label, version in TLS_PROTOCOLS.items():
            try:
                supported = self._test_protocol(service.host, service.port, service.hostname, version)
            except (ValueError, ssl.SSLError) as exc:
                findings.append(Finding(
                    title=f"{label} Not Tested",
                    severity=Severity.INFO,
                    asset=service.host,
                    port=service.port,
                    protocol=service.protocol,
                    service=service.service_name,
                    description=f"Local Python/OpenSSL could not test {label}: {exc}",
                    evidence_strength=1,
                    type="tls-protocol",
                    evidence=[Evidence("tls-protocol", "Protocol test unsupported by local runtime.", 1, {"protocol": label})],
                    tags=["not-tested"],
                ))
                continue
            if not supported:
                continue
            severity = Severity.MEDIUM if label in {"TLS 1.0", "TLS 1.1"} else Severity.INFO
            title = f"{label} Supported" if severity == Severity.INFO else f"{label} Supported"
            findings.append(Finding(
                title=title,
                severity=severity,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description=f"The service accepted a {label} handshake.",
                recommendation="Disable deprecated TLS versions. TLS 1.2/1.3 support is informational.",
                evidence_strength=5,
                type="tls-protocol",
                evidence=[Evidence("tls-protocol", f"{label} handshake succeeded.", 5, {"protocol": label})],
                tags=["safe-active"],
            ))
        return findings

    def _test_protocol(self, host: str, port: int, server_name: str | None, version: ssl.TLSVersion) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name or host):
                    return True
        except (OSError, ssl.SSLError):
            return False

    def _hsts_findings(self, service: Service) -> list[Finding]:
        findings: list[Finding] = []
        try:
            conn = HTTPSConnection(service.host, port=service.port, timeout=self.timeout, context=ssl.create_default_context())
            conn.request("HEAD", "/", headers={"User-Agent": "PortWise/0.1 safe-validation"})
            response = conn.getresponse()
        except (OSError, ssl.SSLError):
            return findings
        hsts = response.getheader("Strict-Transport-Security", "")
        if not hsts:
            findings.append(Finding(
                title="HSTS Missing",
                severity=Severity.LOW,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="HTTPS response did not include Strict-Transport-Security.",
                recommendation="Add HSTS with an appropriate max-age for browser-facing HTTPS applications.",
                evidence_strength=5,
                type="tls-http",
                evidence=[Evidence("tls-hsts", "HSTS header missing on HTTPS response.", 5, {"status": response.status})],
                tags=["safe-active", "contextual"],
            ))
            return findings
        max_age = self._hsts_max_age(hsts)
        if max_age is not None and max_age < 15_552_000:
            findings.append(Finding(
                title="Weak HSTS Policy",
                severity=Severity.LOW,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description="HSTS max-age is shorter than 180 days.",
                recommendation="Use a longer max-age where appropriate for browser-facing applications.",
                evidence_strength=5,
                type="tls-http",
                evidence=[Evidence("tls-hsts", "Weak HSTS max-age.", 5, {"hsts": hsts, "max_age": max_age})],
                tags=["safe-active", "contextual"],
            ))
        return findings

    @staticmethod
    def _hsts_max_age(value: str) -> int | None:
        for part in value.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age="):
                try:
                    return int(part.split("=", 1)[1])
                except ValueError:
                    return None
        return None

    @staticmethod
    def _name_tuple_to_dict(value: tuple[tuple[tuple[str, str], ...], ...]) -> dict[str, str]:
        result: dict[str, str] = {}
        for group in value:
            for key, item in group:
                result[key] = item
        return result

    @staticmethod
    def _tls_finding(service: Service, title: str, severity: Severity, description: str, data: dict[str, Any]) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            asset=service.host,
            port=service.port,
            protocol=service.protocol,
            service=service.service_name,
            description=description,
            recommendation="Replace or reissue the certificate and align TLS configuration with current policy.",
            evidence_strength=5,
            type="tls-certificate",
            evidence=[Evidence("tls-certificate", description, 5, data)],
            tags=["safe-active"],
        )

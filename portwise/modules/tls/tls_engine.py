from __future__ import annotations

import socket
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from portwise.core.models import Evidence, Finding, FindingCategory, Service, Severity
from portwise.modules.tls.cert_checks import days_until, parse_cert_time
from portwise.modules.tls.http_tls_checks import service_suggests_tls
from portwise.modules.tls.protocol_checks import TLS_PROTOCOLS
from portwise.utils.http_client import PoliteHttpClient

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class TlsEngine:
    def __init__(
        self,
        timeout: float = 5.0,
        expiring_days: int = 30,
        http_client: PoliteHttpClient | None = None,
    ) -> None:
        self.timeout = timeout
        self.expiring_days = expiring_days
        self.http_client = http_client or PoliteHttpClient()
        # Tracks TLS versions that the local OpenSSL build cannot test
        self._runtime_unsupported: set[str] = set()

    def should_run(self, service: Service) -> bool:
        return service_suggests_tls(service) or self.detect_tls(service.host, service.port, service.hostname)

    def detect_tls(self, host: str, port: int, server_name: str | None = None) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        _allow_legacy_tls(context)
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
                module="tls",
                evidence=[Evidence("tls-handshake", "Certificate retrieval failed.", 1)],
                tags=["not-tested"],
                category=FindingCategory.INFORMATION,
            ))
        findings.extend(self._protocol_findings(service))
        findings.extend(self._hsts_findings(service))
        findings.extend(self._cipher_findings(service))
        return findings

    def _cipher_findings(self, service: Service) -> list[Finding]:
        from portwise.modules.tls.cipher_checks import run_cipher_checks
        target = {
            "host": service.host,
            "port": service.port,
            "protocol": service.protocol,
            "service": service.service_name,
            "scripts": service.scripts,
        }
        return run_cipher_checks(service, target, {}, module="tls")

    def get_capability_notes(self) -> list[str]:
        """Returns run-level notes about local TLS testing limitations (call after scanning)."""
        if self._runtime_unsupported:
            protocols = ", ".join(sorted(self._runtime_unsupported))
            return [
                f"TLS protocol testing limited: {protocols} not supported by the local "
                "OpenSSL build; deprecated-protocol checks skipped for these versions."
            ]
        return []

    def _fetch_certificate(self, host: str, port: int, server_name: str | None) -> dict[str, Any] | None:
        der_cert = self._fetch_certificate_der(host, port, server_name, legacy=False)
        if not der_cert:
            der_cert = self._fetch_certificate_der(host, port, server_name, legacy=True)
        if not der_cert:
            return None
        cert = self._decode_der_certificate(der_cert)
        if cert is None:
            return None
        chain_valid, chain_error = self._validate_certificate_chain(host, port, server_name)
        cert["_portwise_chain_valid"] = chain_valid
        cert["_portwise_chain_error"] = chain_error
        return cert

    def _fetch_certificate_der(self, host: str, port: int, server_name: str | None, *, legacy: bool) -> bytes | None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if legacy:
            _allow_legacy_tls(context)
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name or host) as tls_sock:
                    return tls_sock.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None

    def _validate_certificate_chain(self, host: str, port: int, server_name: str | None) -> tuple[bool | None, str]:
        context = ssl.create_default_context()
        context.check_hostname = False
        _allow_legacy_tls(context)
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name or host):
                    return True, ""
        except ssl.SSLCertVerificationError as exc:
            return False, str(exc)
        except (OSError, ssl.SSLError):
            return None, "Certificate chain validation could not complete."

    @staticmethod
    def _decode_der_certificate(der_cert: bytes) -> dict[str, Any] | None:
        path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="ascii", suffix=".pem", delete=False) as handle:
                handle.write(ssl.DER_cert_to_PEM_cert(der_cert))
                path = Path(handle.name)
            return ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
        except (OSError, ssl.SSLError, ValueError):
            return None
        finally:
            if path is not None:
                try:
                    path.unlink()
                except OSError:
                    pass

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
            module="tls",
            evidence=[Evidence("tls-certificate", "Certificate metadata retrieved via TLS handshake.", 4, evidence_data)],
            tags=["safe-active"],
            category=FindingCategory.INFORMATION,
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

        chain_valid = cert.get("_portwise_chain_valid")
        if chain_valid is False:
            chain_error = str(cert.get("_portwise_chain_error") or "Default trust store rejected the certificate chain.")
            findings.append(self._tls_finding(service, "Untrusted Certificate Chain", Severity.MEDIUM, chain_error, evidence_data))

        hostname = self._certificate_hostname(service)
        if hostname:
            matched, reason = self._hostname_matches_certificate(hostname, cert)
            if not matched:
                findings.append(self._tls_finding(service, "TLS Hostname Mismatch", Severity.MEDIUM, reason, evidence_data))
        elif subject_cn:
            findings[-1].evidence[0].data["subject_common_name"] = subject_cn

        return findings

    @staticmethod
    def _certificate_hostname(service: Service) -> str:
        candidate = service.hostname or service.host
        try:
            import ipaddress
            ipaddress.ip_address(candidate)
            return service.hostname or ""
        except ValueError:
            return candidate

    @classmethod
    def _hostname_matches_certificate(cls, hostname: str, cert: dict[str, Any]) -> tuple[bool, str]:
        names = [value for kind, value in cert.get("subjectAltName", []) if str(kind).lower() == "dns"]
        if not names:
            subject = cls._name_tuple_to_dict(cert.get("subject", ()))
            common_name = subject.get("commonName", "")
            if common_name:
                names = [common_name]
        if not names:
            return False, f"Certificate contains no DNS SAN or CN for hostname {hostname}."
        for pattern in names:
            if cls._dnsname_match(str(pattern), hostname):
                return True, ""
        return False, f"Certificate names {', '.join(names)} do not match hostname {hostname}."

    @staticmethod
    def _dnsname_match(pattern: str, hostname: str) -> bool:
        pattern = pattern.rstrip(".").lower()
        hostname = hostname.rstrip(".").lower()
        if not pattern or not hostname:
            return False
        if "*" not in pattern:
            return pattern == hostname
        if not pattern.startswith("*.") or pattern.count("*") != 1:
            return False
        suffix = pattern[2:]
        suffix_labels = suffix.split(".")
        host_labels = hostname.split(".")
        return len(host_labels) == len(suffix_labels) + 1 and host_labels[1:] == suffix_labels

    def _protocol_findings(self, service: Service) -> list[Finding]:
        findings: list[Finding] = []
        for label, version in TLS_PROTOCOLS.items():
            self.http_client.throttle(service.host)  # space out raw handshakes per host
            try:
                supported = self._test_protocol(service.host, service.port, service.hostname, version)
            except (ValueError, ssl.SSLError):
                # Local OpenSSL build cannot test this protocol version.
                # Record it once at engine level; do NOT emit per-host noise.
                self._runtime_unsupported.add(label)
                continue
            if not supported:
                continue
            is_deprecated = label in {"TLS 1.0", "TLS 1.1"}
            severity = Severity.MEDIUM if is_deprecated else Severity.INFO
            proto_category = FindingCategory.VULNERABILITY if is_deprecated else FindingCategory.INFORMATION
            poc = f"nmap --script ssl-enum-ciphers -p {service.port} {service.host}    # protocol section lists {label}"
            desc = f"The service accepted a {label} handshake."
            if is_deprecated:
                desc += f" Reproduce / capture POC with:  {poc}"
            findings.append(Finding(
                title=f"{label} Supported",
                severity=severity,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description=desc,
                recommendation="Disable deprecated TLS versions (require TLS 1.2 minimum). TLS 1.2/1.3 support is informational.",
                evidence_strength=5,
                type="tls-protocol",
                module="tls",
                evidence=[Evidence("tls-protocol", f"{label} handshake succeeded.", 5, {"protocol": label, "poc_command": poc})],
                tags=["safe-active"],
                category=proto_category,
            ))
        return findings

    def _test_protocol(self, host: str, port: int, server_name: str | None, version: ssl.TLSVersion) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if version in {ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1} and port in {1010, 1011}:
            _allow_legacy_tls(context)
        context.minimum_version = version
        context.maximum_version = version
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server_name or host) as tls_sock:
                    return tls_sock.version() == _tls_version_name(version)
        except (OSError, ssl.SSLError):
            return False

    def _hsts_findings(self, service: Service) -> list[Finding]:
        findings: list[Finding] = []
        try:
            response = self.http_client.request(service.host, service.port, "HEAD", "/", True, timeout=self.timeout)
        except OSError:
            return findings
        hsts = response.getheader("Strict-Transport-Security", "")
        hsts_poc = f"nmap --script http-security-headers -p {service.port} {service.host}    # (or) curl -sI https://{service.host}:{service.port}/ | grep -i strict-transport"
        if not hsts:
            findings.append(Finding(
                title="HSTS Missing",
                severity=Severity.LOW,
                asset=service.host,
                port=service.port,
                protocol=service.protocol,
                service=service.service_name,
                description=f"HTTPS response did not include Strict-Transport-Security. Reproduce / capture POC with:  {hsts_poc}",
                recommendation="Add HSTS with an appropriate max-age for browser-facing HTTPS applications.",
                evidence_strength=5,
                type="tls-http",
                module="tls",
                evidence=[Evidence("tls-hsts", "HSTS header missing on HTTPS response.", 5, {"status": response.status, "poc_command": hsts_poc})],
                tags=["safe-active", "contextual"],
                category=FindingCategory.BEST_PRACTICE,
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
                module="tls",
                evidence=[Evidence("tls-hsts", "Weak HSTS max-age.", 5, {"hsts": hsts, "max_age": max_age})],
                tags=["safe-active", "contextual"],
                category=FindingCategory.BEST_PRACTICE,
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
            module="tls",
            evidence=[Evidence("tls-certificate", description, 5, data)],
            tags=["safe-active"],
            category=FindingCategory.VULNERABILITY,
        )


def _allow_legacy_tls(context: ssl.SSLContext) -> None:
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        pass
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass


def _tls_version_name(version: ssl.TLSVersion) -> str:
    return {
        ssl.TLSVersion.TLSv1: "TLSv1",
        ssl.TLSVersion.TLSv1_1: "TLSv1.1",
        ssl.TLSVersion.TLSv1_2: "TLSv1.2",
        ssl.TLSVersion.TLSv1_3: "TLSv1.3",
    }.get(version, "")

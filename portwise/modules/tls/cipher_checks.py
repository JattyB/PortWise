from __future__ import annotations

import socket
import ssl
from typing import Any

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.scanners.nse import nse_ssl_cert, nse_ssl_ciphers

# Weak cipher classification — kept deliberately simple: any suite using RC4,
# 3DES, plain CBC, or NULL/EXPORT/anon is reported under a single "weak ciphers
# in use" finding (no separate CBC/PFS sub-findings).
_RC4 = ("rc4", "arcfour")
_3DES = ("3des", "des-cbc3", "des_cbc3")
_CBC = ("-cbc-", "_cbc_", "-cbc-sha", "aes128-sha", "aes256-sha")
_INSECURE = ("null", "export", "anon", "adh", "aecdh", "_md5")


def _poc_ciphers(host: str, port: int) -> str:
    return f"nmap --script ssl-enum-ciphers -p {port} {host}"


def _poc_protocol(host: str, port: int) -> str:
    return f"nmap --script ssl-enum-ciphers -p {port} {host}    # protocol section shows SSLv3/TLSv1.0/1.1"


def _is_weak(name: str) -> bool:
    nl = name.lower()
    return (any(p in nl for p in _RC4) or any(p in nl for p in _3DES)
            or any(p in nl for p in _INSECURE) or any(p in nl for p in _CBC))


def _is_insecure(name: str) -> bool:
    nl = name.lower()
    return any(p in nl for p in _INSECURE)


_DEPRECATED_VERSIONS = {
    "sslv2": ("SSLv2", Severity.HIGH),
    "sslv3": ("SSLv3", Severity.HIGH),
    "tlsv1.0": ("TLS 1.0", Severity.MEDIUM),
    "tlsv1": ("TLS 1.0", Severity.MEDIUM),
    "tlsv1.1": ("TLS 1.1", Severity.MEDIUM),
}


def _findings_from_nse(service: Any, target: dict[str, Any], module: str) -> list[Finding]:
    findings: list[Finding] = []
    ciphers_by_ver = nse_ssl_ciphers(service)
    if not ciphers_by_ver:
        return findings

    host = str(target.get("host", ""))
    port = int(target.get("port", 443))
    protocol = str(target.get("protocol", "tcp"))
    svc = str(target.get("service", ""))

    weak_suites: list[str] = []
    insecure_present = False
    deprecated_versions: list[tuple[str, Severity]] = []

    for version, ciphers in ciphers_by_ver.items():
        vkey = str(version).lower().replace(" ", "")
        if vkey in _DEPRECATED_VERSIONS:
            deprecated_versions.append(_DEPRECATED_VERSIONS[vkey])
        for c in ciphers:
            name = c.get("name", "")
            if _is_weak(name):
                weak_suites.append(f"{name} ({version})")
                if _is_insecure(name):
                    insecure_present = True

    # ---- Single weak-cipher finding ----
    if weak_suites:
        severity = Severity.HIGH if insecure_present else Severity.MEDIUM
        poc = _poc_ciphers(host, port)
        findings.append(Finding(
            title="Weak TLS Ciphers In Use",
            severity=severity,
            asset=host, port=port, protocol=protocol, service=svc,
            description=(
                f"The service supports weak TLS cipher suites: {', '.join(weak_suites[:8])}"
                f"{' …' if len(weak_suites) > 8 else ''}. "
                f"Reproduce / capture POC with:  {poc}"
            ),
            recommendation="Disable weak cipher suites (RC4, 3DES, CBC, NULL/EXPORT/anon). Prefer TLS 1.2+ with AEAD suites (AES-GCM, ChaCha20).",
            confidence=Confidence.CONFIRMED,
            evidence_strength=5,
            type="Vulnerability",
            module=module,
            false_positive_risk="low",
            manual_validation=False,
            evidence=[Evidence(f"module:{module}:cipher",
                               f"NSE ssl-enum-ciphers identified weak suites: {', '.join(weak_suites[:8])}",
                               5, {"suites": weak_suites, "poc_command": poc})],
            category=FindingCategory.VULNERABILITY,
            tags=["tls", "weak-cipher"],
        ))

    # ---- Deprecated protocol versions (SSLv3 / TLS 1.0 / 1.1) ----
    seen: set[str] = set()
    for label, sev in deprecated_versions:
        if label in seen:
            continue
        seen.add(label)
        poc = _poc_protocol(host, port)
        findings.append(Finding(
            title=f"Deprecated TLS/SSL Protocol Supported ({label})",
            severity=sev,
            asset=host, port=port, protocol=protocol, service=svc,
            description=(
                f"The service accepts {label}, which is deprecated and insecure "
                f"(POODLE/BEAST-class exposure). Reproduce / capture POC with:  {poc}"
            ),
            recommendation=f"Disable {label}. Require TLS 1.2 as the minimum protocol version (TLS 1.3 preferred).",
            confidence=Confidence.CONFIRMED,
            evidence_strength=5,
            type="Vulnerability",
            module=module,
            false_positive_risk="low",
            manual_validation=False,
            evidence=[Evidence(f"module:{module}:protocol",
                               f"NSE ssl-enum-ciphers reports {label} support.",
                               5, {"protocol": label, "poc_command": poc})],
            category=FindingCategory.VULNERABILITY,
            tags=["tls", "deprecated-protocol"],
        ))

    return findings


def _sha1_cert_finding(service: Any, target: dict[str, Any], module: str) -> Finding | None:
    cert = nse_ssl_cert(service)
    sig_alg = cert.get("sig_alg", "")
    if not sig_alg or "sha1" not in sig_alg.lower():
        return None
    host = str(target.get("host", ""))
    port = int(target.get("port", 443))
    poc = f"nmap --script ssl-cert -p {port} {host}    # shows Signature Algorithm"
    return Finding(
        title="Weak TLS Certificate Signature Algorithm (SHA-1)",
        severity=Severity.MEDIUM,
        asset=host, port=port, protocol=str(target.get("protocol", "tcp")), service=str(target.get("service", "")),
        description=f"The TLS certificate uses SHA-1 ({sig_alg}). SHA-1 is broken and distrusted by browsers. POC:  {poc}",
        recommendation="Reissue the certificate with SHA-256 or stronger.",
        confidence=Confidence.CONFIRMED,
        evidence_strength=5,
        type="Vulnerability",
        module=module,
        false_positive_risk="low",
        manual_validation=False,
        evidence=[Evidence(f"module:{module}:cipher", f"NSE ssl-cert signature algorithm: {sig_alg}", 5,
                           {"sig_alg": sig_alg, "poc_command": poc})],
        category=FindingCategory.VULNERABILITY,
        tags=["tls", "sha1-cert"],
    )


# Native fallback: probe a few weak cipher families and, if ANY are accepted,
# emit a single weak-cipher finding (no per-family granularity).
_WEAK_FAMILY_STRINGS = ("RC4", "3DES", "AES128-SHA:AES256-SHA:DES-CBC3-SHA", "aNULL:eNULL:EXPORT")


def _native_cipher_probe(host: str, port: int, target: dict[str, Any], module: str, timeout: float) -> list[Finding]:
    accepted: list[str] = []
    for cipher_str in _WEAK_FAMILY_STRINGS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher_str)
        except ssl.SSLError:
            continue
        try:
            with ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=host) as s:
                negotiated = s.cipher()
                if negotiated:
                    accepted.append(negotiated[0])
        except (ssl.SSLError, OSError, TimeoutError):
            pass
    if not accepted:
        return []
    poc = _poc_ciphers(host, port)
    return [Finding(
        title="Weak TLS Ciphers In Use",
        severity=Severity.MEDIUM,
        asset=host, port=port, protocol=str(target.get("protocol", "tcp")), service=str(target.get("service", "")),
        description=f"Native TLS handshakes succeeded with weak cipher suites: {', '.join(sorted(set(accepted)))}. POC:  {poc}",
        recommendation="Disable weak cipher suites. Prefer TLS 1.2+ with AEAD suites (AES-GCM, ChaCha20).",
        confidence=Confidence.CONFIRMED,
        evidence_strength=5,
        type="Vulnerability",
        module=module,
        false_positive_risk="low",
        manual_validation=False,
        evidence=[Evidence(f"module:{module}:cipher", f"Native probe accepted: {', '.join(sorted(set(accepted)))}", 5,
                           {"negotiated": sorted(set(accepted)), "poc_command": poc})],
        category=FindingCategory.VULNERABILITY,
        tags=["tls", "weak-cipher", "native-probe"],
    )]


def run_cipher_checks(service: Any, target: dict[str, Any], config: dict[str, Any], module: str = "tls") -> list[Finding]:
    tls_config = config.get("tls", {}) if isinstance(config.get("tls"), dict) else {}
    if not bool(tls_config.get("cipher_enumeration", True)):
        return []

    findings: list[Finding] = []
    nse_findings = _findings_from_nse(service, target, module)
    findings.extend(nse_findings)

    sha1_finding = _sha1_cert_finding(service, target, module)
    if sha1_finding:
        findings.append(sha1_finding)

    if not nse_findings and bool(tls_config.get("native_cipher_probe", True)):
        host = str(target.get("host", ""))
        port = int(target.get("port", 443))
        timeout = float(tls_config.get("timeout", config.get("timeout", 5)))
        findings.extend(_native_cipher_probe(host, port, target, module, timeout))

    return findings

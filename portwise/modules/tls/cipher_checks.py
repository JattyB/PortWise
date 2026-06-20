from __future__ import annotations

import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
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


# Native fallback: probe clearly weak cipher families and, if ANY are accepted,
# emit a single weak-cipher finding (no per-family granularity). AES-CBC suites
# are left to richer NSE/template enumeration to avoid false positives on
# compatibility-only TLS 1.2 endpoints.
_WEAK_FAMILY_STRINGS = ("-ALL:RC4:@SECLEVEL=0", "-ALL:3DES:@SECLEVEL=0", "-ALL:aNULL:eNULL:EXPORT:@SECLEVEL=0")
_RAW_WEAK_CIPHERS = {
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 0x000A,
}
_NATIVE_ENUM_PROTOCOLS = {
    "TLS 1.0": getattr(ssl.TLSVersion, "TLSv1", None),
    "TLS 1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
    "TLS 1.2": getattr(ssl.TLSVersion, "TLSv1_2", None),
    "TLS 1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
}


def _native_cipher_probe(host: str, port: int, target: dict[str, Any], module: str, timeout: float) -> list[Finding]:
    accepted: list[str] = []
    probe_timeout = timeout
    jobs = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        for cipher_str in _WEAK_FAMILY_STRINGS:
            jobs.append(executor.submit(_weak_family_probe, host, port, host, cipher_str, probe_timeout))
        if target.get("tls_cert_retrieved") is False:
            for name, suite in _RAW_WEAK_CIPHERS.items():
                jobs.append(executor.submit(_raw_weak_cipher_name_probe, host, port, host, name, suite, probe_timeout))
        if port == 443 or target.get("force_weak_dh_probe"):
            jobs.append(executor.submit(_weak_dh_probe, host, port, host, probe_timeout))
        for future in as_completed(jobs):
            result = future.result()
            if result:
                accepted.append(result)
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


def _weak_family_probe(host: str, port: int, server_name: str, cipher_str: str, timeout: float) -> str | None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(cipher_str)
    except ssl.SSLError:
        return None
    try:
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=server_name) as s:
            negotiated = s.cipher()
            if negotiated and _is_weak(negotiated[0]) and _matches_requested_family(cipher_str, negotiated[0]):
                return negotiated[0]
    except (ssl.SSLError, OSError, TimeoutError):
        return None
    return None


def _raw_weak_cipher_name_probe(host: str, port: int, server_name: str, name: str, suite: int, timeout: float) -> str | None:
    return name if _raw_tls_cipher_probe(host, port, server_name, suite, timeout) else None


def _native_cipher_enumeration(host: str, port: int, server_name: str, timeout: float, max_ciphers: int) -> dict[str, list[dict[str, Any]]]:
    enumeration: dict[str, list[dict[str, Any]]] = {}
    for label, version in _NATIVE_ENUM_PROTOCOLS.items():
        if version is None:
            continue
        accepted: list[dict[str, Any]] = []
        if label == "TLS 1.3":
            negotiated = _negotiate_cipher(host, port, server_name, version, None, timeout)
            if negotiated:
                accepted.append(_cipher_info(negotiated))
            if accepted:
                enumeration[label] = accepted
            continue
        for cipher_name in _candidate_cipher_names(version):
            negotiated = _negotiate_cipher(host, port, server_name, version, cipher_name, timeout)
            if not negotiated:
                continue
            info = _cipher_info(negotiated)
            if info not in accepted:
                accepted.append(info)
            if len(accepted) >= max_ciphers:
                break
        if accepted:
            enumeration[label] = accepted
    return enumeration


def _native_enumeration_finding(host: str, port: int, target: dict[str, Any], module: str, enumeration: dict[str, list[dict[str, Any]]]) -> Finding | None:
    if not enumeration:
        return None
    protocol_count = len(enumeration)
    cipher_count = sum(len(items) for items in enumeration.values())
    poc = _poc_ciphers(host, port)
    return Finding(
        title="TLS Native Cipher Enumeration",
        severity=Severity.INFO,
        asset=host,
        port=port,
        protocol=str(target.get("protocol", "tcp")),
        service=str(target.get("service", "")),
        description=f"Native TLS handshakes enumerated {cipher_count} accepted cipher/protocol combinations across {protocol_count} protocol version(s).",
        recommendation="Use this inventory to confirm only approved TLS versions and cipher suites remain enabled.",
        confidence=Confidence.CONFIRMED,
        evidence_strength=4,
        type="tls-info",
        module=module,
        false_positive_risk="low",
        manual_validation=False,
        evidence=[Evidence("module:tls:native-cipher-enum", "Per-version native cipher enumeration completed.", 4, {
            "protocols": enumeration,
            "poc_command": poc,
        })],
        category=FindingCategory.INFORMATION,
        tags=["tls", "cipher-enumeration", "safe-active"],
    )


def _candidate_cipher_names(version: ssl.TLSVersion) -> list[str]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        if version in {ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1}:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        names = []
        for item in ctx.get_ciphers():
            name = str(item.get("name", ""))
            if name and not name.startswith("TLS_"):
                names.append(name)
        return sorted(set(names))
    except (ssl.SSLError, ValueError):
        return []


def _negotiate_cipher(host: str, port: int, server_name: str, version: ssl.TLSVersion, cipher_name: str | None, timeout: float) -> tuple[str, str, int] | None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        if version in {ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1}:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        if cipher_name:
            ctx.set_ciphers(f"{cipher_name}:@SECLEVEL=0")
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=server_name) as tls_sock:
            negotiated = tls_sock.cipher()
            negotiated_version = tls_sock.version() or ""
            if negotiated and _version_matches_label(version, negotiated_version):
                return negotiated
    except (ssl.SSLError, OSError, TimeoutError, ValueError):
        return None
    return None


def _cipher_info(negotiated: tuple[str, str, int]) -> dict[str, Any]:
    name, protocol, bits = negotiated
    return {
        "name": name,
        "protocol": protocol,
        "bits": bits,
        "weak": _is_weak(name),
    }


def _version_matches_label(version: ssl.TLSVersion, negotiated: str) -> bool:
    expected = {
        ssl.TLSVersion.TLSv1: "TLSv1",
        ssl.TLSVersion.TLSv1_1: "TLSv1.1",
        ssl.TLSVersion.TLSv1_2: "TLSv1.2",
        ssl.TLSVersion.TLSv1_3: "TLSv1.3",
    }.get(version)
    return expected == negotiated


def _raw_tls_cipher_probe(host: str, port: int, server_name: str, cipher_suite: int, timeout: float) -> bool:
    try:
        hello = _build_tls12_client_hello(server_name, [cipher_suite, 0x00FF])
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(hello)
            data = sock.recv(4096)
    except (OSError, TimeoutError):
        return False
    return _server_hello_cipher(data) == cipher_suite


def _weak_dh_probe(host: str, port: int, server_name: str, timeout: float) -> str | None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("DHE:@SECLEVEL=2")
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=server_name):
            return None
    except ssl.SSLError as exc:
        text = str(exc).lower()
        if "dh key too small" in text or "dh_key_too_small" in text:
            return "DHE weak/1024-bit parameter"
        return None
    except (OSError, TimeoutError):
        return None


def _matches_requested_family(cipher_str: str, negotiated: str) -> bool:
    requested = cipher_str.lower()
    name = negotiated.lower()
    if "3des" in requested:
        return any(marker in name for marker in _3DES)
    if "rc4" in requested:
        return any(marker in name for marker in _RC4)
    return _is_insecure(name)


def _build_tls12_client_hello(server_name: str, cipher_suites: list[int]) -> bytes:
    random = b"PWS1" + b"\x00" * 28
    suites = b"".join(struct.pack("!H", suite) for suite in cipher_suites)
    hostname = server_name.encode("idna")
    sni_name = b"\x00" + struct.pack("!H", len(hostname)) + hostname
    sni = struct.pack("!HHH", 0, len(sni_name) + 2, len(sni_name)) + sni_name
    sig_algs = b"\x00\x0d\x00\x08\x00\x06\x04\x01\x05\x01\x02\x01"
    extensions = sni + sig_algs
    body = (
        b"\x03\x03"
        + random
        + b"\x00"
        + struct.pack("!H", len(suites))
        + suites
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def _server_hello_cipher(data: bytes) -> int | None:
    if len(data) < 5 or data[0] != 22:
        return None
    record_len = int.from_bytes(data[3:5], "big")
    payload = data[5:5 + record_len]
    if len(payload) < 42 or payload[0] != 2:
        return None
    body_len = int.from_bytes(payload[1:4], "big")
    body = payload[4:4 + body_len]
    if len(body) < 35:
        return None
    session_len = body[34]
    cipher_offset = 35 + session_len
    if len(body) < cipher_offset + 2:
        return None
    return int.from_bytes(body[cipher_offset:cipher_offset + 2], "big")


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
        if bool(tls_config.get("native_full_enumeration", False)):
            server_name = str(target.get("hostname") or host)
            max_ciphers = int(tls_config.get("native_enum_max_ciphers_per_version", 128))
            enumeration = _native_cipher_enumeration(host, port, server_name, timeout, max_ciphers)
            enum_finding = _native_enumeration_finding(host, port, target, module, enumeration)
            if enum_finding:
                findings.append(enum_finding)

    return findings

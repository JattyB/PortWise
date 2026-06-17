from __future__ import annotations

import ftplib
import socket
import ssl
import struct
from http.client import HTTPConnection, HTTPSConnection
from typing import Any

from portwise.core.models import Confidence, Evidence, Finding, FindingCategory, Severity
from portwise.intelligence.default_creds import lookup_default_creds
from portwise.modules.base import PortWiseModule
from portwise.modules.http.http_engine import HttpEngine
from portwise.modules.results import ModuleResult
from portwise.modules.tls.tls_engine import TlsEngine
from portwise.scanners.nse import (
    nse_dns_recursion,
    nse_ftp_anon,
    nse_rdp_ntlm,
    nse_smb_os,
    nse_smb_security,
    nse_snmp_info,
    nse_ssh_algos,
)
from portwise.scanners.smb_native import probe_smb
from portwise.scanners.ssh_algos import enumerate_ssh_algorithms
from portwise.utils.http_client import PoliteHttpClient, client_from_config

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def available_modules() -> list[PortWiseModule]:
    return [
        ExposureModule(),
        PlaintextProtocolModule(),
        TlsModule(),
        HttpModule(),
        SmbSafeModule(),
        SshSafeModule(),
        RdpSafeModule(),
        WinRmSafeModule(),
        FtpSafeModule(),
        SnmpSafeModule(),
        DnsSafeModule(),
        NtpSafeModule(),
        DatabaseSafeModule(),
        DevOpsAdminModule(),
        KubernetesContainerModule(),
        MailSafeModule(),
        VpnApplianceModule(),
    ]


def module_map() -> dict[str, PortWiseModule]:
    return {module.name: module for module in available_modules()}


def module_targets_key(module_name: str) -> str:
    return {
        "exposure": "all_services",
        "plaintext": "all_services",
        "tls": "tls_targets",
        "http": "http_targets",
        "smb": "smb_targets",
        "ssh": "ssh_targets",
        "rdp": "rdp_targets",
        "winrm": "winrm_targets",
        "ftp": "ftp_targets",
        "snmp": "snmp_targets",
        "dns": "dns_targets",
        "ntp": "ntp_targets",
        "database": "database_targets",
        "devops": "devops_targets",
        "kubernetes": "kubernetes_targets",
        "mail": "mail_targets",
        "vpn": "vpn_appliance_targets",
    }.get(module_name, "")


class FindingFactory:
    @staticmethod
    def finding(
        *,
        title: str,
        severity: Severity,
        target: dict[str, Any],
        module: str,
        description: str,
        recommendation: str,
        evidence: Evidence,
        confidence: Confidence = Confidence.LIKELY,
        type_: str = "Risk Indicator",
        false_positive_risk: str = "medium",
        manual_validation: bool = True,
        category: FindingCategory = FindingCategory.VULNERABILITY,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            asset=str(target.get("host", "")),
            port=int(target.get("port", 0) or 0),
            protocol=str(target.get("protocol", "")),
            service=str(target.get("service", "")),
            description=description,
            recommendation=recommendation,
            confidence=confidence,
            evidence_strength=evidence.strength,
            type=type_,
            module=module,
            false_positive_risk=false_positive_risk,
            manual_validation=manual_validation,
            evidence=[evidence],
            category=category,
        )


def _target_hostname(target: dict[str, Any]) -> str | None:
    """Return a name-based vhost for the target when a DNS hostname is known and
    differs from the connection IP; otherwise None (probe the IP directly)."""
    hostname = str(target.get("hostname") or "").strip()
    host = str(target.get("host") or "").strip()
    if not hostname or hostname == host:
        return None
    return hostname


def target_text(target: dict[str, Any]) -> str:
    return " ".join([
        str(target.get("service", "")),
        str(target.get("product", "")),
        str(target.get("version", "")),
        " ".join(target.get("cpe", []) or []),
        str(target.get("routing_reason", "")),
    ]).lower()


def _timeout(config: dict[str, Any], section: str | None = None, default: float = 4.0) -> float:
    if section and isinstance(config.get(section), dict):
        section_data = config[section]
        return float(section_data.get("timeout_seconds", section_data.get("timeout", default)))
    return float(config.get("timeout_seconds", config.get("timeout", default)))


def _truncate(value: bytes | str, limit: int = 512) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    text = text.replace("\x00", " ").strip()
    return text[:limit]


def _tcp_send_recv(host: str, port: int, payload: bytes, timeout: float, recv_size: int = 4096) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if payload:
            sock.sendall(payload)
        return sock.recv(recv_size)


def _http_request(host: str, port: int, path: str, timeout: float, tls: bool | None = None) -> tuple[int, dict[str, str], str, str]:
    attempts = [tls] if tls is not None else [port in {443, 8443, 9443}, False]
    last_error = ""
    for use_tls in attempts:
        try:
            conn_cls = HTTPSConnection if use_tls else HTTPConnection
            kwargs: dict[str, Any] = {"timeout": timeout}
            if use_tls:
                kwargs["context"] = ssl.create_default_context()
            conn = conn_cls(host, port=port, **kwargs)
            conn.request("GET", path, headers={"User-Agent": _BROWSER_UA})
            response = conn.getresponse()
            body = response.read(4096).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in response.getheaders()}
            return response.status, headers, body, "https" if use_tls else "http"
        except Exception as exc:
            last_error = str(exc)
            continue
    raise OSError(last_error)


def _extract_title(body: str) -> str:
    lower = body.lower()
    start = lower.find("<title")
    if start == -1:
        return ""
    start = lower.find(">", start)
    end = lower.find("</title>", start)
    if start == -1 or end == -1:
        return ""
    return " ".join(body[start + 1:end].split())[:160]


class TlsModule(PortWiseModule):
    name = "tls"
    description = "Native safe TLS certificate, protocol, and HSTS checks."
    supported_target_types = ("tls_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        from portwise.core.models import Service

        hostname = _target_hostname(target)
        service = Service(
            host=str(target["host"]),
            port=int(target["port"]),
            protocol=str(target.get("protocol", "tcp")),
            state="open",
            service_name=str(target.get("service", "")),
            product=str(target.get("product", "")),
            version=str(target.get("version", "")),
            cpes=list(target.get("cpe", []) or []),
            tunnel="ssl",
            scripts=dict(target.get("scripts") or {}),
            hostname=hostname,
        )
        tls_client = client_from_config(config)
        if hostname:
            tls_client.vhost = hostname
            tls_client.sni = hostname
        engine = TlsEngine(
            timeout=float(config.get("timeout", 5)),
            expiring_days=int(config.get("tls_expiry_days", 30)),
            http_client=tls_client,
        )
        findings = engine.run(service)
        for finding in findings:
            finding.module = self.name
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class HttpModule(PortWiseModule):
    name = "http"
    description = "Safe HTTP metadata, header, method, cookie, and common exposure checks."
    supported_target_types = ("http_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        from portwise.core.models import Service

        hostname = _target_hostname(target)
        service = Service(
            host=str(target["host"]),
            port=int(target["port"]),
            protocol=str(target.get("protocol", "tcp")),
            state="open",
            service_name=str(target.get("service", "")),
            product=str(target.get("product", "")),
            version=str(target.get("version", "")),
            cpes=list(target.get("cpe", []) or []),
            tunnel="ssl" if "tls" in str(target.get("routing_reason", "")).lower() or "https" in str(target.get("service", "")).lower() else None,
            scripts=dict(target.get("scripts") or {}),
            hostname=hostname,
        )
        http_client = client_from_config(config)
        if hostname:
            # Send Host: <vhost> and use it as SNI so name-based / fronted vhosts
            # are tested instead of the bare IP.
            http_client.vhost = hostname
            http_client.sni = hostname
        engine = HttpEngine(
            timeout=float(config.get("timeout", 5)),
            paths=tuple(config.get("http_paths", []) or ()),
            client=http_client,
        )
        findings = engine.run(service, config=config)
        for finding in findings:
            finding.module = self.name
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class ExposureModule(PortWiseModule):
    name = "exposure"
    description = "Context-aware exposure and owner-validation findings."
    supported_target_types = ("all_services",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        context = str(config.get("context", "unknown"))
        internet = bool(config.get("internet_facing", False))
        risky = {
            "ftp": Severity.MEDIUM,
            "telnet": Severity.HIGH,
            "ssh": Severity.LOW,
            "smb": Severity.MEDIUM,
            "microsoft-ds": Severity.MEDIUM,
            "rdp": Severity.MEDIUM,
            "winrm": Severity.MEDIUM,
            "snmp": Severity.MEDIUM,
            "redis": Severity.HIGH,
            "mongodb": Severity.HIGH,
            "elasticsearch": Severity.HIGH,
            "memcached": Severity.HIGH,
            "docker": Severity.HIGH,
            "kubernetes": Severity.HIGH,
            "jenkins": Severity.MEDIUM,
            "grafana": Severity.MEDIUM,
            "kibana": Severity.MEDIUM,
            "prometheus": Severity.MEDIUM,
            "rabbitmq": Severity.MEDIUM,
            "sonarqube": Severity.MEDIUM,
            "nexus": Severity.MEDIUM,
            "artifactory": Severity.MEDIUM,
            "tomcat": Severity.MEDIUM,
            "jboss": Severity.HIGH,
            "wildfly": Severity.HIGH,
            "weblogic": Severity.HIGH,
            "vpn": Severity.MEDIUM,
            "fortinet": Severity.MEDIUM,
        }
        findings: list[Finding] = []
        for key, severity in risky.items():
            if key not in text:
                continue
            if context == "external" or internet:
                severity = Severity.HIGH if severity == Severity.MEDIUM else Severity.MEDIUM if severity == Severity.LOW else severity
            evidence = Evidence("module:exposure", f"Service fingerprint matched exposure keyword '{key}'.", 2, target)
            title = f"Exposed {key.upper()} Service"
            type_ = "Needs Owner Validation" if context == "unknown" else "Exposure"
            findings.append(FindingFactory.finding(
                title=title,
                severity=severity,
                target=target,
                module=self.name,
                description="A potentially sensitive service is reachable and should be validated against approved exposure policy.",
                recommendation="Confirm business need, restrict network access, and harden configuration.",
                evidence=evidence,
                confidence=Confidence.INFORMATIONAL,
                type_=type_,
                false_positive_risk="contextual",
                manual_validation=True,
            ))
            break
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


# Protocols that transmit credentials/data without transport encryption.
# (severity, what's exposed, whether opportunistic TLS upgrade is common)
_PLAINTEXT_PORTS: dict[int, tuple[str, Severity, str, bool]] = {
    21:   ("FTP",    Severity.MEDIUM, "credentials and file data", False),
    23:   ("Telnet", Severity.HIGH,   "credentials, keystrokes and session data", False),
    25:   ("SMTP",   Severity.LOW,    "mail content and AUTH credentials", True),
    80:   ("HTTP",   Severity.LOW,    "request/response data and any submitted credentials", True),
    110:  ("POP3",   Severity.MEDIUM, "mailbox credentials and message content", True),
    143:  ("IMAP",   Severity.MEDIUM, "mailbox credentials and message content", True),
    389:  ("LDAP",   Severity.MEDIUM, "directory bind credentials and queries", True),
    512:  ("rexec",  Severity.HIGH,   "credentials and command output (legacy r-service)", False),
    513:  ("rlogin", Severity.HIGH,   "credentials and session data (legacy r-service)", False),
    514:  ("rsh",    Severity.HIGH,   "commands and output with host-based trust (legacy r-service)", False),
    79:   ("Finger", Severity.LOW,    "user and system information", False),
    1521: ("Oracle TNS", Severity.LOW, "database traffic (encryption is configuration-dependent)", False),
    3306: ("MySQL",  Severity.LOW,    "database traffic (TLS is configuration-dependent)", False),
    5432: ("PostgreSQL", Severity.LOW, "database traffic (TLS is configuration-dependent)", False),
    5900: ("VNC",    Severity.MEDIUM, "screen contents and input (often weak/no encryption)", False),
}

_PLAINTEXT_UDP_PORTS: dict[int, tuple[str, Severity, str, bool]] = {
    69:  ("TFTP", Severity.MEDIUM, "files with no authentication or encryption", False),
    161: ("SNMP", Severity.MEDIUM, "device metadata via community strings (v1/v2c)", False),
}

_PLAINTEXT_SERVICE_HINTS = {
    "telnet": (23, "Telnet"),
    "ftp": (21, "FTP"),
    "rlogin": (513, "rlogin"),
    "rsh": (514, "rsh"),
    "rexec": (512, "rexec"),
    "finger": (79, "Finger"),
    "vnc": (5900, "VNC"),
    "tftp": (69, "TFTP"),
}


class PlaintextProtocolModule(PortWiseModule):
    name = "plaintext"
    description = "Flags services that carry credentials/data without transport encryption."
    supported_target_types = ("all_services",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        port = int(target.get("port", 0) or 0)
        protocol = str(target.get("protocol", "tcp")).lower()
        service = str(target.get("service", "")).lower()
        text = target_text(target)

        # A TLS tunnel means the transport is encrypted — never flag those.
        tunnel = str(target.get("tunnel", "")).lower()
        if tunnel == "ssl" or service.startswith("ssl/") or service.endswith("s") and service in {"https", "ftps", "imaps", "pop3s", "smtps", "ldaps"}:
            return ModuleResult(self.name, target, findings=[], evidence=[])
        if "ssl/" in text or "https" in service:
            return ModuleResult(self.name, target, findings=[], evidence=[])

        table = _PLAINTEXT_UDP_PORTS if protocol == "udp" else _PLAINTEXT_PORTS
        entry = table.get(port)

        # Service-name match (covers non-standard ports).
        if entry is None:
            for hint, (canon_port, _label) in _PLAINTEXT_SERVICE_HINTS.items():
                if hint in service:
                    entry = _PLAINTEXT_PORTS.get(canon_port) or _PLAINTEXT_UDP_PORTS.get(canon_port)
                    break

        if entry is None:
            return ModuleResult(self.name, target, findings=[], evidence=[])

        label, severity, exposes, opportunistic = entry
        context = str(config.get("context", "unknown"))
        internet = bool(config.get("internet_facing", False))
        if (context == "external" or internet) and severity == Severity.LOW:
            severity = Severity.MEDIUM

        if opportunistic:
            description = (
                f"{label} on {protocol}/{port} can carry {exposes} in cleartext. "
                f"This protocol commonly supports opportunistic TLS (e.g. STARTTLS); confirm "
                f"whether encryption is enforced or whether cleartext sessions are still permitted."
            )
            confidence = Confidence.NEEDS_MANUAL_VALIDATION
            manual = True
            category = FindingCategory.BEST_PRACTICE
            strength = 2
        else:
            description = (
                f"{label} on {protocol}/{port} transmits {exposes} without transport encryption. "
                f"Traffic can be intercepted or modified by anyone on the path."
            )
            confidence = Confidence.CONFIRMED
            manual = False
            category = FindingCategory.VULNERABILITY
            strength = 4

        finding = _simple_finding(
            self.name, target,
            f"Cleartext Protocol Exposed — {label}",
            severity, description,
            strength=strength, confidence=confidence, manual=manual, category=category,
        )
        finding.tags.append("plaintext-protocol")
        finding.recommendation = (
            f"Disable cleartext access and require an encrypted equivalent "
            f"(e.g. SSH/SFTP instead of Telnet/FTP, HTTPS instead of HTTP, "
            f"LDAPS/STARTTLS instead of plain LDAP). Restrict the port to trusted networks."
        )
        return ModuleResult(self.name, target, findings=[finding], evidence=finding.evidence)


class FtpSafeModule(PortWiseModule):
    name = "ftp"
    description = "FTP cleartext exposure and anonymous-login check."
    supported_target_types = ("ftp_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "FTP Cleartext Service Exposed", Severity.MEDIUM, "FTP transmits credentials and data without transport encryption.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]
        nse_anon = nse_ftp_anon(target)
        native_anon = False
        if bool(config.get("ftp_anonymous_check", True)):
            client = client_from_config(config)
            host = str(target["host"])
            if not client.is_tripped(host):
                client.throttle(host)
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(host, int(target["port"]), timeout=float(config.get("timeout", 5)))
                    ftp.login("anonymous", "anonymous@")
                    ftp.quit()
                    native_anon = True
                except Exception:
                    pass
        if native_anon and nse_anon:
            findings.append(_simple_finding(self.name, target, "Anonymous FTP Login Enabled", Severity.HIGH, "Both native probe and Nmap ftp-anon confirm anonymous FTP login is accepted.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
        elif native_anon or nse_anon:
            source = "Nmap ftp-anon script" if nse_anon else "Native FTP probe"
            findings.append(_simple_finding(self.name, target, "Anonymous FTP Login Enabled", Severity.HIGH, f"{source} indicates anonymous FTP login is accepted.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


_WEAK_KEX = frozenset({"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "rsa1024-sha1", "gss-group1-sha1-toWkFwperkl0GDisCHkwqg=="})
_WEAK_CIPHERS = frozenset({"3des-cbc", "arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se", "blowfish-cbc", "cast128-cbc"})
_WEAK_MACS = frozenset({"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com", "umac-64"})
_WEAK_HOSTKEYS = frozenset({"ssh-dss"})


class SshSafeModule(PortWiseModule):
    name = "ssh"
    description = "SSH exposure and version-disclosure checks without authentication attempts."
    supported_target_types = ("ssh_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "SSH Service Exposed", Severity.LOW, "SSH is reachable and should be owner-approved.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]
        text = target_text(target)
        if target.get("version") or target.get("product"):
            findings.append(_simple_finding(self.name, target, "SSH Version Disclosure", Severity.LOW, "SSH product/version is visible in service fingerprint.", category=FindingCategory.VULNERABILITY))
        if "openssh 5" in text or "openssh 4" in text:
            findings.append(_simple_finding(self.name, target, "Legacy SSH Service", Severity.MEDIUM, "SSH service appears to be an old major version.", category=FindingCategory.BEST_PRACTICE))

        algos = nse_ssh_algos(target)
        algo_source = "Nmap ssh2-enum-algos"
        if not algos and bool(config.get("ssh_algo_probe", True)):
            client = client_from_config(config)
            host = str(target["host"])
            if not client.is_tripped(host):
                client.throttle(host)
                native = enumerate_ssh_algorithms(host, int(target.get("port", 22) or 22), _timeout(config, "ssh", 5.0))
                if native and (native.get("kex") or native.get("encryption")):
                    algos = {
                        "kex": native.get("kex", []),
                        "encryption": list(native.get("encryption", [])) + list(native.get("encryption_s2c", [])),
                        "mac": list(native.get("mac", [])) + list(native.get("mac_s2c", [])),
                        "hostkey": native.get("hostkey", []),
                    }
                    algo_source = "Native SSH KEXINIT probe"

        if algos:
            weak_kex = sorted({a for a in algos.get("kex", []) if a in _WEAK_KEX})
            weak_enc = sorted({a for a in algos.get("encryption", []) if a in _WEAK_CIPHERS})
            weak_mac = sorted({a for a in algos.get("mac", []) if a in _WEAK_MACS})
            weak_key = sorted({a for a in algos.get("hostkey", []) if a in _WEAK_HOSTKEYS})
            confirmed = algo_source.startswith("Native")
            algo_conf = Confidence.CONFIRMED if confirmed else Confidence.LIKELY
            if weak_kex:
                findings.append(_simple_finding(self.name, target, "Weak SSH Key Exchange Algorithm", Severity.MEDIUM, f"Weak KEX algorithms offered ({algo_source}): {', '.join(weak_kex)}. These are susceptible to Logjam/SHA1-downgrade-class attacks.", strength=5, confidence=algo_conf, manual=not confirmed, category=FindingCategory.VULNERABILITY))
            if weak_enc:
                findings.append(_simple_finding(self.name, target, "Weak SSH Cipher", Severity.MEDIUM, f"Weak/legacy ciphers offered ({algo_source}): {', '.join(weak_enc)}. CBC-mode and RC4 ciphers are deprecated.", strength=5, confidence=algo_conf, manual=not confirmed, category=FindingCategory.VULNERABILITY))
            if weak_mac:
                findings.append(_simple_finding(self.name, target, "Weak SSH MAC Algorithm", Severity.LOW, f"Weak MAC algorithms offered ({algo_source}): {', '.join(weak_mac)}.", strength=5, confidence=algo_conf, manual=not confirmed, category=FindingCategory.BEST_PRACTICE))
            if weak_key:
                findings.append(_simple_finding(self.name, target, "Deprecated SSH Host Key Type", Severity.MEDIUM, f"Deprecated host key types in use ({algo_source}): {', '.join(weak_key)}. ssh-dss (DSA) is disabled in OpenSSH 7+.", strength=5, confidence=algo_conf, manual=not confirmed, category=FindingCategory.VULNERABILITY))

        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class SmbSafeModule(PortWiseModule):
    name = "smb"
    description = "SMB exposure and safe Nmap-script evidence parser."
    supported_target_types = ("smb_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        findings = [_simple_finding(self.name, target, "SMB Service Exposed", Severity.MEDIUM, "SMB is reachable and should be limited to trusted networks.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]

        smb_sec = nse_smb_security(target)
        smb_os = nse_smb_os(target)

        # Native fallback: if nmap NSE produced no security-mode data, perform a
        # read-only SMB NEGOTIATE handshake to determine SMBv1 support + signing.
        native_smb = None
        if not smb_sec.get("smbv1") and not smb_sec.get("signing") and bool(config.get("smb_native_probe", True)):
            client = client_from_config(config)
            host = str(target["host"])
            if not client.is_tripped(host):
                client.throttle(host)
                native_smb = probe_smb(host, int(target.get("port", 445) or 445), _timeout(config, "smb", 5.0))

        # SMBv1 — NSE authoritative (strength=5/CONFIRMED), fallback to substring (strength=4/LIKELY)
        if smb_sec.get("smbv1"):
            findings.append(_simple_finding(self.name, target, "SMBv1 Enabled", Severity.HIGH, "Nmap smb-security-mode confirms SMBv1 is negotiated. SMBv1 is deprecated and vulnerable to EternalBlue-class attacks.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
        elif native_smb and native_smb.get("smbv1"):
            findings.append(_simple_finding(self.name, target, "SMBv1 Enabled", Severity.HIGH, "Native SMB NEGOTIATE handshake confirms the legacy SMBv1 dialect (NT LM 0.12) is still accepted. SMBv1 is deprecated and vulnerable to EternalBlue-class attacks.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
        elif "smbv1" in text or "nt lm 0.12" in text:
            findings.append(_simple_finding(self.name, target, "SMBv1 Enabled", Severity.HIGH, "Nmap script evidence indicates SMBv1 may be enabled.", strength=4, category=FindingCategory.VULNERABILITY))

        # SMB signing — NSE authoritative, then native handshake, then substring
        signing = smb_sec.get("signing") or (native_smb.get("signing") if native_smb else None)
        signing_source = "Nmap smb-security-mode" if smb_sec.get("signing") else "Native SMB handshake"
        if signing in ("not_required", "disabled"):
            label = "disabled" if signing == "disabled" else "not required"
            findings.append(_simple_finding(self.name, target, "SMB Signing Not Required", Severity.MEDIUM, f"SMB message signing is {label} ({signing_source}), exposing the host to NTLM relay attacks.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
        elif "message signing disabled" in text or "signing: disabled" in text or "signing not required" in text:
            findings.append(_simple_finding(self.name, target, "SMB Signing Not Required", Severity.MEDIUM, "SMB signing appears not required.", strength=4, category=FindingCategory.VULNERABILITY))

        # OS/domain disclosure — NSE structured data preferred
        if smb_os:
            os_details = ", ".join(f"{k}={v}" for k, v in smb_os.items() if k != "raw")
            desc = f"SMB OS discovery disclosed: {os_details or smb_os.get('raw', '')}."
            findings.append(_simple_finding(self.name, target, "SMB OS/Domain Disclosure", Severity.LOW, desc, strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.INFORMATION))
        elif "domain" in text or "workgroup" in text or "os:" in text:
            findings.append(_simple_finding(self.name, target, "SMB OS/Domain Disclosure", Severity.LOW, "SMB script evidence discloses OS or domain metadata.", strength=4, category=FindingCategory.INFORMATION))

        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class RdpSafeModule(PortWiseModule):
    name = "rdp"
    description = "RDP exposure checks without login attempts."
    supported_target_types = ("rdp_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "RDP Service Exposed", Severity.MEDIUM, "RDP is reachable and should be restricted.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]

        rdp_info = nse_rdp_ntlm(target)
        nla_status = rdp_info.get("nla", "")

        if nla_status == "disabled":
            findings.append(_simple_finding(self.name, target, "RDP NLA Disabled", Severity.HIGH, "Nmap confirms Network Level Authentication (NLA) is disabled. Unauthenticated connection phase exposes the host to credential harvesting.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
        elif "nla: disabled" in target_text(target):
            findings.append(_simple_finding(self.name, target, "RDP NLA Disabled", Severity.HIGH, "Nmap script evidence indicates NLA is disabled.", strength=4, category=FindingCategory.VULNERABILITY))

        # Weak RDP encryption / security layer from rdp-enum-encryption
        enc_level = rdp_info.get("encryption_level", rdp_info.get("security_layer", ""))
        if enc_level and "rdp" in enc_level.lower():
            findings.append(_simple_finding(self.name, target, "Weak RDP Security Layer", Severity.MEDIUM, f"RDP using legacy RDP Security Layer (not CredSSP/TLS): {enc_level}.", strength=4, confidence=Confidence.LIKELY, manual=False, category=FindingCategory.VULNERABILITY))

        # Domain/hostname/version disclosure from NTLM info
        disclosed = [v for k, v in rdp_info.items() if k in ("target_name", "dns_domain_name", "product_version") and v]
        if disclosed:
            findings.append(_simple_finding(self.name, target, "RDP Host Information Disclosure", Severity.LOW, f"RDP NTLM negotiation disclosed host metadata: {', '.join(disclosed)}.", strength=4, confidence=Confidence.LIKELY, manual=False, category=FindingCategory.INFORMATION))

        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class WinRmSafeModule(PortWiseModule):
    name = "winrm"
    description = "WinRM exposure checks without authentication attempts."
    supported_target_types = ("winrm_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        port = int(target.get("port", 0))
        severity = Severity.HIGH if port == 5985 else Severity.MEDIUM
        findings = [_simple_finding(self.name, target, "WinRM Exposed", severity, "WinRM management endpoint is reachable.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]

        client = client_from_config(config)
        host = str(target["host"])
        tls = port == 5986
        if not client.is_tripped(host):
            client.throttle(host)
            methods = _winrm_auth_methods(client, host, port, tls, _timeout(config, default=5.0))
            if methods:
                findings.append(_simple_finding(
                    self.name, target, "WinRM Authentication Methods Disclosed", Severity.LOW,
                    f"The WinRM endpoint advertised these authentication methods on an unauthenticated request: {', '.join(methods)}.",
                    strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.INFORMATION,
                ))
                if any(m.lower() == "basic" for m in methods):
                    if not tls:
                        findings.append(_simple_finding(
                            self.name, target, "WinRM Basic Authentication Over Cleartext", Severity.HIGH,
                            "WinRM offers HTTP Basic authentication over cleartext (port 5985). Credentials are sent base64-encoded with no transport encryption and can be intercepted.",
                            strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY,
                        ))
                    else:
                        findings.append(_simple_finding(
                            self.name, target, "WinRM Basic Authentication Enabled", Severity.MEDIUM,
                            "WinRM offers HTTP Basic authentication. Basic auth bypasses Kerberos/Negotiate protections and is brute-forceable; prefer Negotiate/Kerberos only.",
                            strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.BEST_PRACTICE,
                        ))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class SnmpSafeModule(PortWiseModule):
    name = "snmp"
    description = "SNMP exposure and optional default-community check."
    supported_target_types = ("snmp_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        snmp_config = config.get("snmp", {}) if isinstance(config.get("snmp"), dict) else {}
        findings = [
            _simple_finding(self.name, target, "SNMP Service Exposed", Severity.MEDIUM, "SNMP service is reachable based on discovery evidence.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION),
            _simple_finding(self.name, target, "SNMP v1/v2c Exposed", Severity.MEDIUM, "SNMP v1/v2c may disclose device metadata when community strings are accepted.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.BEST_PRACTICE),
        ]
        # NSE snmp-info enrichment
        snmp_nse = nse_snmp_info(target)
        if snmp_nse:
            raw = snmp_nse.get("raw", "")
            details = "; ".join(f"{k}={v}" for k, v in snmp_nse.items() if k != "raw")[:200]
            findings.append(_simple_finding(self.name, target, "SNMP System Information Disclosure", Severity.LOW, f"SNMP NSE script disclosed system metadata: {details or raw[:200]}.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.INFORMATION))

        if bool(snmp_config.get("default_community_check", config.get("snmp_default_community_check", True))):
            client = client_from_config(config)
            host = str(target["host"])
            for community in list(snmp_config.get("communities", ["public", "private"]))[:2]:
                if client.is_tripped(host):
                    break
                client.throttle(host)
                value = _snmp_get(host, int(target["port"]), str(community), _timeout(config, "snmp", 3.0))
                if value:
                    f_community = _simple_finding(self.name, target, "Default SNMP Community Accepted", Severity.HIGH, f"SNMP community '{community}' returned minimal system metadata: {_truncate(value, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY)
                    f_community.evidence.append(_probe_transcript_evidence(
                        f"module:{self.name}",
                        f"SNMP GET sysDescr with community '{community}'",
                        "SNMP GET sysDescr (OID 1.3.6.1.2.1.1.1.0) community=<redacted>",
                        f"udp://{host}:{target['port']}",
                        str(value),
                    ))
                    findings.append(f_community)
                    findings.append(_simple_finding(self.name, target, "SNMP Information Disclosure", Severity.MEDIUM, f"SNMP returned minimal system metadata: {_truncate(value, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.INFORMATION))
                    break

        # Write-community check (active SET; opt-in + full depth only). The probe
        # reads sysName.0 and writes the same value back, so device state is not
        # changed — it only confirms whether the community grants write access.
        write_enabled = bool(snmp_config.get("write_check", config.get("snmp_write_check", False)))
        depth_full = str(config.get("validation_level", "recon")) == "full"
        if write_enabled and depth_full:
            client = client_from_config(config)
            host = str(target["host"])
            for community in list(snmp_config.get("communities", ["public", "private"]))[:3]:
                if client.is_tripped(host):
                    break
                client.throttle(host)
                if _snmp_write_community_check(host, int(target["port"]), str(community), _timeout(config, "snmp", 3.0)):
                    findings.append(_simple_finding(
                        self.name, target, "SNMP Write Community Accepted", Severity.CRITICAL,
                        f"SNMP community '{community}' grants write access (a no-op sysName.0 round-trip SET succeeded). Write access permits reconfiguring or disrupting the device.",
                        strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY,
                    ))
                    break

        note = _default_cred_note(self.name, target, "snmp " + target_text(target))
        if note:
            findings.append(note)
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class DnsSafeModule(PortWiseModule):
    name = "dns"
    description = "DNS exposure, recursion, version, and bounded zone-transfer checks."
    supported_target_types = ("dns_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        dns_config = config.get("dns", {}) if isinstance(config.get("dns"), dict) else {}
        findings = [_simple_finding(self.name, target, "DNS Service Exposed", Severity.LOW, "DNS service is reachable.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]
        timeout = _timeout(config, "dns", 3.0)
        client = client_from_config(config)
        host = str(target["host"])
        port = int(target["port"])
        nse_recursion = nse_dns_recursion(target)
        if dns_config.get("recursion_check", True) and not client.is_tripped(host):
            client.throttle(host)
            answer = _dns_query(host, port, "example.com", 1, timeout, recursion=True)
            native_recursion = bool(answer and answer.get("ra") and answer.get("ancount", 0) > 0)
            if native_recursion and nse_recursion:
                findings.append(_simple_finding(self.name, target, "DNS Recursion Enabled", Severity.MEDIUM, "Both Nmap dns-recursion script and native probe confirm open recursion.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
            elif native_recursion:
                findings.append(_simple_finding(self.name, target, "DNS Recursion Enabled", Severity.MEDIUM, "Resolver answered a recursive query for example.com.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
            elif nse_recursion:
                findings.append(_simple_finding(self.name, target, "DNS Recursion Enabled", Severity.MEDIUM, "Nmap dns-recursion script indicates open recursion.", strength=5, confidence=Confidence.LIKELY, manual=False, category=FindingCategory.VULNERABILITY))
        if not client.is_tripped(host):
            client.throttle(host)
            version = _dns_chaos_version(host, port, timeout)
            if version:
                f_ver = _simple_finding(self.name, target, "DNS Version Disclosure", Severity.LOW, f"DNS CHAOS version query returned: {_truncate(version, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY)
                f_ver.evidence.append(_probe_transcript_evidence(
                    f"module:{self.name}",
                    "DNS CHAOS TXT version.bind query",
                    "DNS CHAOS TXT version.bind",
                    f"udp://{host}:{port}",
                    str(version),
                ))
                findings.append(f_ver)
        zones = list(dns_config.get("zones", []) or [])
        if dns_config.get("zone_transfer_check", True) and zones:
            for zone in zones[:5]:
                if client.is_tripped(host):
                    break
                client.throttle(host)
                if _dns_axfr_check(host, port, str(zone), timeout):
                    findings.append(_simple_finding(self.name, target, "DNS Zone Transfer Allowed", Severity.HIGH, f"AXFR succeeded for configured zone {zone}.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class NtpSafeModule(PortWiseModule):
    name = "ntp"
    description = "NTP exposure and version/info checks."
    supported_target_types = ("ntp_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "NTP Service Exposed", Severity.LOW, "NTP service is reachable.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]
        client = client_from_config(config)
        host = str(target["host"])
        port = int(target["port"])
        timeout = _timeout(config, "ntp", 3.0)
        if not client.is_tripped(host):
            client.throttle(host)
            response = _ntp_request(host, port, timeout)
            if response:
                findings.append(_simple_finding(self.name, target, "NTP Information Disclosure", Severity.INFO, f"NTP returned a valid time response; stratum={response.get('stratum')}.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.INFORMATION))

        # Mode 6 (control) queries: enable ntpq-style readvar, used for both
        # information disclosure and DRDoS amplification (CVE-2014-9293 class).
        if not client.is_tripped(host):
            client.throttle(host)
            mode6 = _ntp_mode6_readvar(host, port, timeout)
            if mode6:
                f6 = _simple_finding(self.name, target, "NTP Mode 6 Queries Enabled", Severity.MEDIUM, f"The NTP daemon answered an unauthenticated mode-6 (control) readvar query, disclosing daemon variables and providing a DDoS reflection/amplification vector. Response: {_truncate(mode6, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY)
                f6.evidence.append(_probe_transcript_evidence(f"module:{self.name}", "NTP mode-6 control readvar", "NTP mode 6 (control) READVAR", f"udp://{host}:{port}", _truncate(mode6, 200)))
                findings.append(f6)

        # monlist (mode 7) — classic high-amplification reflection (CVE-2013-5211).
        if not client.is_tripped(host):
            client.throttle(host)
            monlist_size = _ntp_monlist(host, port, timeout)
            if monlist_size:
                fm = _simple_finding(self.name, target, "NTP monlist Enabled", Severity.HIGH, f"The NTP daemon responded to a mode-7 monlist (MON_GETLIST_1) request with {monlist_size} bytes. monlist is a high-amplification DDoS reflection vector (CVE-2013-5211) and discloses recent client addresses.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY)
                fm.cve_id = "CVE-2013-5211"
                fm.references = ["https://nvd.nist.gov/vuln/detail/CVE-2013-5211"]
                findings.append(fm)
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class DatabaseSafeModule(PortWiseModule):
    name = "database"
    description = "Database exposure and minimal unauthenticated version probes."
    supported_target_types = ("database_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        title = "Database Service Exposed"
        severity = Severity.MEDIUM
        if "redis" in text:
            title = "Database Service Exposed"
        if "memcached" in text:
            title = "Memcached Exposed"
            severity = Severity.HIGH
        findings = [_simple_finding(self.name, target, title, severity, "Database service is reachable; no data was queried or dumped.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]
        if bool((config.get("database", {}) if isinstance(config.get("database"), dict) else {}).get("unauthenticated_checks", True)):
            client = client_from_config(config)
            findings.extend(_database_safe_probe(self.name, target, config, text, client=client))
        if target.get("version"):
            findings.append(_simple_finding(self.name, target, "Database Version Disclosure", Severity.LOW, "Database product/version is visible in service fingerprint.", category=FindingCategory.VULNERABILITY))
        note = _default_cred_note(self.name, target, text)
        if note:
            findings.append(note)
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class DevOpsAdminModule(PortWiseModule):
    name = "devops"
    description = "DevOps/admin panel fingerprint checks."
    supported_target_types = ("devops_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "DevOps/Admin Panel Exposed", Severity.MEDIUM, "Administrative or DevOps service fingerprint is reachable.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]
        client = client_from_config(config)
        text = target_text(target)
        probe = _safe_http_fingerprint(target, config, ["/", "/login", "/-/readiness", "/api/v4/version", "/service/rest/v1/status", "/api/health", "/-/health"], client=client)
        if probe:
            status, title, indicator, url = probe
            findings[0].evidence[0].data.update({"url": url, "status": status, "title": title, "indicator": indicator})
            if status == 200 and any(word in indicator.lower() for word in ("anonymous", "public", "unauthenticated", "ready", "healthy")):
                findings.append(_simple_finding(self.name, target, "Anonymous Access Possible", Severity.MEDIUM, f"Safe endpoint responded with public status indicator at {url}.", strength=4, category=FindingCategory.VULNERABILITY))
            if any(word in text + " " + indicator.lower() for word in ("vault", "consul", "minio", "airflow", "jupyter", "portainer")):
                findings.append(_simple_finding(self.name, target, "Sensitive Management Interface Exposed", Severity.HIGH, f"Sensitive management fingerprint observed at {url}.", strength=4, category=FindingCategory.VULNERABILITY))
        if target.get("version"):
            findings.append(_simple_finding(self.name, target, "Version Disclosure", Severity.LOW, "Service version is visible in fingerprint.", category=FindingCategory.VULNERABILITY))
        note = _default_cred_note(self.name, target, text)
        if note:
            findings.append(note)
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class KubernetesContainerModule(PortWiseModule):
    name = "kubernetes"
    description = "Container management exposure checks using safe endpoints only."
    supported_target_types = ("kubernetes_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        port = int(target.get("port", 0))
        if "docker registry" in text:
            title = "Docker Registry Exposed"
            paths = ["/v2/"]
        elif "docker" in text or port in {2375, 2376}:
            title = "Docker API Exposed"
            paths = ["/version", "/info"]
        elif "etcd" in text:
            title = "etcd Exposed"
            paths = ["/version", "/health"]
        elif "kubelet" in text:
            title = "Kubelet Endpoint Exposed"
            paths = ["/healthz"]
        else:
            title = "Kubernetes API Exposed"
            paths = ["/version", "/readyz", "/healthz"]
        finding = _simple_finding(self.name, target, title, Severity.HIGH, "Container management interface is reachable. Only safe metadata endpoints are in scope.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)
        client = client_from_config(config)
        findings = [finding]
        probe = _safe_http_fingerprint(target, config, paths, client=client)
        if probe:
            status, title_text, indicator, url = probe
            finding.evidence[0].data.update({"url": url, "status": status, "title": title_text, "indicator": indicator})
            ind = indicator.lower()
            # Confirmed unauthenticated Docker API = remote container takeover → CRITICAL
            if ("docker" in title.lower()) and status == 200 and ("apiversion" in ind or "\"version\"" in ind or "docker" in ind or "containers" in ind):
                crit = _simple_finding(self.name, target, "Unauthenticated Docker API Access", Severity.CRITICAL, f"The Docker Engine API responded to an unauthenticated request at {url}. This typically permits full container/host takeover.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY)
                crit.evidence.append(_probe_transcript_evidence(f"module:{self.name}", "Unauthenticated Docker API metadata request", f"GET {url}", url, _truncate(indicator, 300)))
                findings.append(crit)
            elif title == "Docker Registry Exposed" and status in (200, 401):
                reg = _simple_finding(self.name, target, "Exposed Docker Registry", Severity.HIGH, f"A Docker registry v2 API is reachable at {url} (status {status}). Review whether anonymous pull/push is permitted.", strength=4, confidence=Confidence.LIKELY, manual=True, category=FindingCategory.VULNERABILITY)
                findings.append(reg)
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class MailSafeModule(PortWiseModule):
    name = "mail"
    description = "Mail service exposure and STARTTLS/banner checks."
    supported_target_types = ("mail_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        findings: list[Finding] = []
        client = client_from_config(config)
        host = str(target["host"])
        if "smtp" in text or int(target.get("port", 0)) in {25, 465, 587}:
            findings.append(_simple_finding(self.name, target, "SMTP Service Exposed", Severity.LOW, "SMTP service is reachable; no mail sending was performed.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION))
            if not client.is_tripped(host):
                client.throttle(host)
                banner, replies = _smtp_safe_check(host, int(target["port"]), _timeout(config, "mail", 4.0))
                if banner:
                    findings.append(_simple_finding(self.name, target, "Mail Server Version Disclosure", Severity.LOW, f"SMTP banner: {_truncate(banner, 160)}", strength=4, category=FindingCategory.VULNERABILITY))
                if replies.get("starttls") is False and int(target.get("port", 0)) in {25, 587}:
                    findings.append(_simple_finding(self.name, target, "SMTP STARTTLS Missing", Severity.MEDIUM, "SMTP EHLO capabilities did not advertise STARTTLS.", strength=4, category=FindingCategory.BEST_PRACTICE))
                if replies.get("vrfy"):
                    findings.append(_simple_finding(self.name, target, "VRFY Enabled", Severity.LOW, "SMTP server accepted VRFY command syntax check without user enumeration.", strength=4, category=FindingCategory.BEST_PRACTICE))
                if replies.get("expn"):
                    findings.append(_simple_finding(self.name, target, "EXPN Enabled", Severity.LOW, "SMTP server accepted EXPN command syntax check without list enumeration.", strength=4, category=FindingCategory.BEST_PRACTICE))
        else:
            title = "POP3 Cleartext Service Exposed" if "pop3" in text or int(target.get("port", 0)) == 110 else "IMAP Cleartext Service Exposed"
            findings.append(_simple_finding(self.name, target, title, Severity.LOW, "Mail service is reachable; no authentication was attempted.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


# Known SSL-VPN / appliance login-portal paths per vendor (read-only confirmation).
_VPN_PORTAL_PATHS: dict[str, list[str]] = {
    "fortinet": ["/remote/login", "/remote/info"],
    "globalprotect": ["/global-protect/login.esp", "/sslvpn/Login/Login"],
    "ivanti": ["/dana-na/auth/url_default/welcome.cgi", "/dana-na/"],
    "citrix": ["/vpn/index.html", "/logon/LogonPoint/index.html", "/citrix/"],
    "cisco": ["/+CSCOE+/logon.html", "/+webvpn+/index.html"],
    "sonicwall": ["/auth.html", "/cgi-bin/welcome"],
    "generic": ["/remote/login", "/dana-na/", "/vpn/index.html", "/global-protect/login.esp"],
}

_VPN_VENDOR_HINTS: dict[str, tuple[str, ...]] = {
    "fortinet": ("fortinet", "fortigate", "fortiweb"),
    "globalprotect": ("globalprotect", "palo alto", "pan-os"),
    "ivanti": ("ivanti", "pulse", "connect secure"),
    "citrix": ("citrix", "netscaler", "adc", "gateway"),
    "cisco": ("cisco", "asa", "anyconnect", "ftd"),
    "sonicwall": ("sonicwall",),
}


class VpnApplianceModule(PortWiseModule):
    name = "vpn"
    description = "VPN/security appliance fingerprint and known portal exposure checks."
    supported_target_types = ("vpn_appliance_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        title = "VPN Interface Exposed" if any(word in text for word in ("vpn", "globalprotect", "fortigate", "pulse", "ivanti", "horizon")) else "Security Appliance Interface Exposed"
        findings = [_simple_finding(self.name, target, title, Severity.MEDIUM, "Security appliance interface is reachable based on fingerprint evidence.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION)]
        findings.append(_simple_finding(self.name, target, "Needs Owner Validation", Severity.INFO, "Security appliance exposure should be validated with the service owner.", confidence=Confidence.INFORMATIONAL, category=FindingCategory.INFORMATION))
        if target.get("version"):
            findings.append(_simple_finding(self.name, target, "Appliance Version Disclosure", Severity.LOW, "Appliance version is visible in fingerprint.", category=FindingCategory.VULNERABILITY))

        # Probe known SSL-VPN / appliance login portals to confirm the product and
        # surface the exposed remote-access entry point. Read-only GETs; no exploits.
        client = client_from_config(config)
        context = str(config.get("context", "unknown"))
        internet = bool(config.get("internet_facing", False))
        portal_sev = Severity.HIGH if (context == "external" or internet) else Severity.MEDIUM
        for vendor, paths in _VPN_PORTAL_PATHS.items():
            if client.is_tripped(str(target["host"])):
                break
            # Probe a vendor's paths when its fingerprint matches, or always for the
            # generic small set when nothing else matched.
            if vendor != "generic" and not any(hint in text for hint in _VPN_VENDOR_HINTS.get(vendor, (vendor,))):
                continue
            probe = _safe_http_fingerprint(target, config, paths, client=client)
            if probe:
                status, _title, indicator, url = probe
                f = _simple_finding(
                    self.name, target, f"SSL-VPN Login Portal Exposed — {vendor.title()}", portal_sev,
                    f"A {vendor.title()} remote-access login portal responded at {url} (HTTP {status}). Confirm whether this entry point should be internet-reachable and that the appliance is fully patched.",
                    strength=4, confidence=Confidence.LIKELY, manual=True, category=FindingCategory.VULNERABILITY,
                )
                f.evidence.append(_probe_transcript_evidence(f"module:{self.name}", f"{vendor} SSL-VPN portal probe", f"GET {url}", url, _truncate(indicator, 200)))
                findings.append(f)
                break
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


def _default_cred_note(module: str, target: dict[str, Any], product_text: str) -> Finding | None:
    """Emit a manual-verification note when a product with known default creds is detected."""
    match = lookup_default_creds(product_text)
    if not match:
        return None
    kb_key, entry = match
    severity_str = entry.get("severity", "low")
    severity = Severity.HIGH if severity_str == "high" else Severity.MEDIUM if severity_str == "medium" else Severity.LOW
    pairs = entry.get("pairs", [])
    if pairs:
        cred_list = ", ".join(f"{u or '(none)'}:{p or '(blank)'}" for u, p in pairs[:5])
        desc_creds = f" Known defaults: {cred_list}."
    else:
        desc_creds = " " + entry.get("notes", "")
    title = f"Default Credentials Should Be Manually Verified — {kb_key}"
    description = (
        f"PortWise detected {kb_key} (fingerprint match). "
        f"This product commonly ships with default credentials.{desc_creds} "
        "PortWise does NOT attempt authentication. "
        "Manually verify these credentials under proper authorization and rotate if valid."
    )
    notes = entry.get("notes", "")
    if notes:
        description += f" Note: {notes}"
    evidence = Evidence(f"module:{module}", description, 2, {"kb_key": kb_key, "refs": entry.get("references", [])})
    return Finding(
        title=title,
        severity=severity,
        asset=str(target.get("host", "")),
        port=int(target.get("port", 0) or 0),
        protocol=str(target.get("protocol", "")),
        service=str(target.get("service", "")),
        description=description,
        recommendation=f"Verify default credentials manually and rotate immediately if valid. References: {', '.join(entry.get('references', []))}",
        confidence=Confidence.INFORMATIONAL,
        evidence_strength=2,
        type="Manual Verification Required",
        module=module,
        false_positive_risk="low",
        manual_validation=True,
        evidence=[evidence],
        category=FindingCategory.BEST_PRACTICE,
        references=entry.get("references", []),
        tags=["default-creds", "manual-verification"],
    )


def _simple_finding(
    module: str,
    target: dict[str, Any],
    title: str,
    severity: Severity,
    description: str,
    *,
    strength: int = 2,
    confidence: Confidence = Confidence.LIKELY,
    manual: bool = True,
    category: FindingCategory = FindingCategory.VULNERABILITY,
) -> Finding:
    evidence = Evidence(f"module:{module}", description, strength, target)
    return FindingFactory.finding(
        title=title,
        severity=severity,
        target=target,
        module=module,
        description=description,
        recommendation="Validate owner approval, restrict exposure where possible, and harden service configuration.",
        evidence=evidence,
        confidence=confidence,
        type_="Exposure" if severity in {Severity.HIGH, Severity.MEDIUM} else "Risk Indicator",
        false_positive_risk="low" if strength >= 4 else "contextual",
        manual_validation=manual,
        category=category,
    )


def _probe_transcript_evidence(source: str, description: str, probe: str, target_str: str, response: str, strength: int = 5) -> Evidence:
    """Build a transcript-like Evidence for non-HTTP probe results (PT5 Step 3)."""
    from datetime import datetime, timezone
    from portwise.utils.sanitize import sanitize_body
    ts = datetime.now(timezone.utc).isoformat()
    return Evidence(
        source=source,
        description=description,
        strength=strength,
        data={
            "transcript": {
                "request": {"probe": probe, "target": target_str},
                "response": {"status": "ok", "body_excerpt": sanitize_body(response, cap=512)},
                "timing_ms": 0,
                "observed_at": ts,
            }
        },
    )


def _dns_query(host: str, port: int, name: str, qtype: int, timeout: float, recursion: bool = True) -> dict[str, int | bool] | None:
    flags = 0x0100 if recursion else 0
    packet_id = 0x5057
    query = struct.pack("!HHHHHH", packet_id, flags, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", qtype, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (host, port))
            data, _ = sock.recvfrom(512)
        if len(data) < 12:
            return None
        _, response_flags, _, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        return {"ra": bool(response_flags & 0x0080), "ancount": ancount}
    except Exception:
        return None


def _dns_chaos_version(host: str, port: int, timeout: float) -> str | None:
    packet_id = 0x5058
    query = struct.pack("!HHHHHH", packet_id, 0, 1, 0, 0, 0) + _dns_name("version.bind") + struct.pack("!HH", 16, 3)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (host, port))
            data, _ = sock.recvfrom(512)
        return _truncate(data[12:], 160) if len(data) > 12 else None
    except Exception:
        return None


def _dns_axfr_check(host: str, port: int, zone: str, timeout: float) -> bool:
    packet_id = 0x5059
    query = struct.pack("!HHHHHH", packet_id, 0, 1, 0, 0, 0) + _dns_name(zone) + struct.pack("!HH", 252, 1)
    payload = struct.pack("!H", len(query)) + query
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            header = sock.recv(2)
            if len(header) != 2:
                return False
            size = struct.unpack("!H", header)[0]
            data = sock.recv(min(size, 4096))
        return len(data) > 12 and struct.unpack("!H", data[6:8])[0] > 0
    except Exception:
        return False


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii", errors="ignore") for part in name.rstrip(".").split(".")) + b"\x00"


def _snmp_get(host: str, port: int, community: str, timeout: float) -> str | None:
    # Minimal SNMPv2c GET for sysDescr.0. This is intentionally one OID and small response only.
    oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
    varbind = b"\x30\x0e" + oid + b"\x05\x00"
    pdu = b"\xa0\x1f\x02\x04\x50\x57\x00\x01\x02\x01\x00\x02\x01\x00\x30\x11" + varbind
    community_bytes = community.encode("ascii", errors="ignore")
    body = b"\x02\x01\x01\x04" + bytes([len(community_bytes)]) + community_bytes + pdu
    packet = b"\x30" + bytes([len(body)]) + body
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(512)
        return _truncate(data, 200)
    except Exception:
        return None


def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    out = b""
    while length:
        out = bytes([length & 0xFF]) + out
        length >>= 8
    return bytes([0x80 | len(out)]) + out


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(value: int) -> bytes:
    if value == 0:
        return _ber_tlv(0x02, b"\x00")
    out = b""
    n = value
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    if out[0] & 0x80:
        out = b"\x00" + out
    return _ber_tlv(0x02, out)


def _snmp_message(community: str, pdu: bytes) -> bytes:
    community_bytes = community.encode("ascii", errors="ignore")
    body = _ber_int(0) + _ber_tlv(0x04, community_bytes) + pdu  # version v1(0)+community+pdu
    return _ber_tlv(0x30, body)


def _snmp_get_value(host: str, port: int, community: str, oid: bytes, timeout: float) -> bytes | None:
    """Send an SNMP GET for a single OID and return the raw value TLV bytes."""
    varbind = _ber_tlv(0x30, oid + _ber_tlv(0x05, b""))  # OID + NULL
    varbind_list = _ber_tlv(0x30, varbind)
    pdu = _ber_tlv(0xA0, _ber_int(0x50570001) + _ber_int(0) + _ber_int(0) + varbind_list)
    packet = _snmp_message(community, pdu)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(2048)
    except Exception:
        return None
    return _snmp_extract_value(data, oid)


def _snmp_extract_value(data: bytes, oid: bytes) -> bytes | None:
    """Find the value TLV that follows the requested OID in an SNMP response."""
    idx = data.find(oid)
    if idx == -1:
        return None
    pos = idx + len(oid)
    if pos >= len(data):
        return None
    tag = data[pos]
    length = data[pos + 1]
    start = pos + 2
    if length & 0x80:
        num = length & 0x7F
        length = int.from_bytes(data[pos + 2:pos + 2 + num], "big")
        start = pos + 2 + num
    return bytes([tag]) + _ber_len(length) + data[start:start + length]


def _snmp_set(host: str, port: int, community: str, oid: bytes, value_tlv: bytes, timeout: float) -> bool:
    """Send an SNMP SET for oid=value_tlv; return True if error-status is 0."""
    varbind = _ber_tlv(0x30, oid + value_tlv)
    varbind_list = _ber_tlv(0x30, varbind)
    pdu = _ber_tlv(0xA3, _ber_int(0x50570002) + _ber_int(0) + _ber_int(0) + varbind_list)
    packet = _snmp_message(community, pdu)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(2048)
    except Exception:
        return False
    return _snmp_response_error_status(data) == 0


def _snmp_response_error_status(data: bytes) -> int | None:
    """Extract error-status from an SNMP response PDU (0xA2). Returns None if not found."""
    idx = data.find(b"\xa2")
    if idx == -1:
        return None
    pos = idx + 2  # skip PDU tag + length byte (responses here are short-form)
    if data[pos] != 0x80 and (data[pos] & 0x80):
        pos += 1 + (data[pos] & 0x7F)
    # request-id INTEGER
    if pos >= len(data) or data[pos] != 0x02:
        return None
    pos += 2 + data[pos + 1]
    # error-status INTEGER
    if pos >= len(data) or data[pos] != 0x02:
        return None
    length = data[pos + 1]
    return int.from_bytes(data[pos + 2:pos + 2 + length], "big")


def _ntp_request(host: str, port: int, timeout: float) -> dict[str, int] | None:
    packet = b"\x1b" + (b"\x00" * 47)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(48)
        if len(data) < 48:
            return None
        return {"stratum": data[1], "version": (data[0] >> 3) & 0b111}
    except Exception:
        return None


def _ntp_mode6_readvar(host: str, port: int, timeout: float) -> str | None:
    """Send an NTP mode-6 (control) READVAR query. Returns the response text if
    the daemon answers (mode-6 enabled), else None. Read-only."""
    # byte0: LI=0, VN=2 (0x10), Mode=6 (0x06) -> 0x16; byte1: opcode 2 (readvar)
    packet = struct.pack("!BBHHHHH", 0x16, 0x02, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(4096)
        # A mode-6 response has the response bit set in byte 1 and carries data.
        if len(data) >= 12 and (data[0] & 0x07) == 6:
            return _truncate(data[12:], 200) or "(mode-6 response received)"
        return None
    except Exception:
        return None


def _ntp_monlist(host: str, port: int, timeout: float) -> int | None:
    """Send an NTP mode-7 monlist (MON_GETLIST_1) request. Returns the response
    byte count if the daemon answers (monlist enabled), else None. Read-only."""
    # byte0: VN=2 (0x10), Mode=7 (0x07) -> 0x17; impl=3 (XNTPD); reqcode=42 (0x2a)
    packet = b"\x17\x00\x03\x2a" + (b"\x00" * 4)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(2048)
        # A monlist reply is a mode-7 response carrying monitor entries.
        if len(data) > 8 and (data[0] & 0x07) == 7:
            return len(data)
        return None
    except Exception:
        return None


def _mongodb_ping(host: str, port: int, timeout: float) -> bool:
    """Send a minimal MongoDB isMaster wire-protocol message. Returns True if a response arrives."""
    # Minimal OP_QUERY for isMaster command (MongoDB wire protocol)
    body = (
        b"\x00\x00\x00\x00"  # flags
        b"admin.$cmd\x00"     # fullCollectionName
        b"\x00\x00\x00\x00"  # numberToSkip
        b"\x01\x00\x00\x00"  # numberToReturn
        b"\x13\x00\x00\x00"  # BSON doc length (19 bytes)
        b"\x01isMaster\x00"  # double field "isMaster"
        b"\x00\x00\x00\x00\x00\x00\xf0\x3f"  # value 1.0
        b"\x00"               # BSON doc terminator
    )
    header = (
        len(body) + 16
    ).to_bytes(4, "little") + b"\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
    packet = header + body
    try:
        import socket as _sock
        with _sock.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(packet)
            data = s.recv(256)
        return len(data) > 16
    except Exception:
        return False


def _database_safe_probe(module: str, target: dict[str, Any], config: dict[str, Any], text: str, *, client: PoliteHttpClient | None = None) -> list[Finding]:
    if client is None:
        client = client_from_config(config)
    host = str(target["host"])
    port = int(target["port"])
    timeout = _timeout(config, "database", 4.0)
    # If the fingerprint text doesn't name the engine, infer it from the port so
    # port-routed targets still get the correct probe.
    _port_hint = {3306: "mysql", 5432: "postgresql", 27017: "mongodb", 6379: "redis",
                  11211: "memcached", 9200: "elasticsearch", 9300: "elasticsearch",
                  5984: "couchdb", 8086: "influxdb", 7474: "neo4j", 2379: "etcd"}.get(port)
    if _port_hint and _port_hint not in text:
        text = f"{text} {_port_hint}"
    findings: list[Finding] = []
    if "redis" in text:
        if not client.is_tripped(host):
            client.throttle(host)
            try:
                data = _tcp_send_recv(host, port, b"*1\r\n$4\r\nPING\r\n", timeout)
                if b"PONG" in data:
                    findings.append(_simple_finding(module, target, "Unauthenticated Redis Access", Severity.HIGH, "Redis PING succeeded without AUTH.", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
            except Exception:
                pass
    elif "memcached" in text:
        if not client.is_tripped(host):
            client.throttle(host)
            try:
                data = _tcp_send_recv(host, port, b"version\r\n", timeout)
                if data:
                    findings.append(_simple_finding(module, target, "Memcached Exposed", Severity.HIGH, f"Memcached responded to version check: {_truncate(data, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False, category=FindingCategory.VULNERABILITY))
            except Exception:
                pass
    elif "mongodb" in text:
        if not client.is_tripped(host):
            client.throttle(host)
            if _mongodb_ping(host, port, timeout):
                findings.append(_simple_finding(module, target, "Unauthenticated MongoDB Access Indicator", Severity.HIGH, "MongoDB responded to a wire-protocol isMaster probe without authentication. Verify whether auth is enforced.", strength=4, confidence=Confidence.LIKELY, manual=True, category=FindingCategory.VULNERABILITY))
    elif any(name in text for name in ("elasticsearch", "couchdb", "solr", "etcd", "neo4j", "influxdb")):
        paths = {
            "elasticsearch": ["/", "/_cluster/health"],
            "couchdb": ["/"],
            "solr": ["/solr/", "/solr/admin/info/system"],
            "etcd": ["/version", "/health"],
            "neo4j": ["/"],
            "influxdb": ["/health", "/ping"],
        }
        selected = next((value for key, value in paths.items() if key in text), ["/"])
        probe = _safe_http_fingerprint(target, config, selected, client=client)
        if probe:
            status, title, indicator, url = probe
            product_title = "Unauthenticated Elasticsearch Access" if "elasticsearch" in text else "Database Service Exposed"
            findings.append(_simple_finding(module, target, product_title, Severity.HIGH if status == 200 else Severity.MEDIUM, f"Safe database HTTP endpoint responded at {url}: {_truncate(indicator, 180)}", strength=5 if status == 200 else 4, category=FindingCategory.VULNERABILITY))
    return findings


def _safe_http_fingerprint(target: dict[str, Any], config: dict[str, Any], paths: list[str], *, client: PoliteHttpClient | None = None) -> tuple[int, str, str, str] | None:
    if client is None:
        client = client_from_config(config)
    host = str(target["host"])
    port = int(target["port"])
    timeout = _timeout(config, default=4.0)
    tls = port in {443, 8443, 9443}
    for path in paths:
        try:
            if client.is_tripped(host):
                break
            resp = client.request(host, port, "GET", path, tls, timeout)
            body = resp.read(4096).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            status = resp.status
            scheme = "https" if tls else "http"
        except OSError as exc:
            if "[PortWise]" in str(exc):
                break
            continue
        except Exception:
            continue
        title = _extract_title(body)
        indicator = title or headers.get("server", "") or headers.get("x-powered-by", "") or body[:160]
        if status in {200, 301, 302, 401, 403}:
            return status, title, _truncate(indicator, 220), f"{scheme}://{host}:{port}{path}"
    return None


def _winrm_auth_methods(client: PoliteHttpClient, host: str, port: int, tls: bool, timeout: float) -> list[str]:
    """Enumerate WinRM authentication methods from the WWW-Authenticate header(s)
    returned for an unauthenticated POST to /wsman. No credentials are sent."""
    known = ("Negotiate", "Kerberos", "NTLM", "Basic", "CredSSP", "Digest")
    try:
        resp = client.request(host, port, "POST", "/wsman", tls, timeout)
    except Exception:
        return []
    raw = " ".join(v for k, v in resp.getheaders() if k.lower() == "www-authenticate")
    if not raw:
        return []
    lowered = raw.lower()
    return [name for name in known if name.lower() in lowered]


def _snmp_write_community_check(host: str, port: int, community: str, timeout: float) -> bool:
    """Non-destructive SNMP write-community test: read sysName.0, then SET it back
    to the same value with the supplied community. A success response means the
    community grants write access. No device state is changed (same value)."""
    sysname_oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00"  # 1.3.6.1.2.1.1.5.0
    current = _snmp_get_value(host, port, community, sysname_oid, timeout)
    if current is None:
        return False
    return _snmp_set(host, port, community, sysname_oid, current, timeout)


def _smtp_safe_check(host: str, port: int, timeout: float) -> tuple[str, dict[str, bool]]:
    replies: dict[str, bool] = {}
    banner = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = _truncate(sock.recv(512), 200)
            sock.sendall(b"EHLO portwise.example\r\n")
            ehlo = _truncate(sock.recv(2048), 1000).lower()
            replies["starttls"] = "starttls" in ehlo
            sock.sendall(b"VRFY portwise\r\n")
            vrfy = _truncate(sock.recv(512), 200)
            replies["vrfy"] = vrfy.startswith("250") or vrfy.startswith("252")
            sock.sendall(b"EXPN portwise\r\n")
            expn = _truncate(sock.recv(512), 200)
            replies["expn"] = expn.startswith("250") or expn.startswith("252")
            sock.sendall(b"QUIT\r\n")
    except Exception:
        pass
    return banner, replies

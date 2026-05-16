from __future__ import annotations

import ftplib
import json
import socket
import ssl
import struct
from http.client import HTTPConnection, HTTPSConnection
from typing import Any

from portwise.core.models import Confidence, Evidence, Finding, Severity
from portwise.modules.base import PortWiseModule
from portwise.modules.http.http_engine import HttpEngine
from portwise.modules.results import ModuleResult
from portwise.modules.tls.tls_engine import TlsEngine


def available_modules() -> list[PortWiseModule]:
    return [
        ExposureModule(),
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
        )


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
            conn.request("GET", path, headers={"User-Agent": "PortWise/0.1 safe-validation"})
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
        )
        engine = TlsEngine(timeout=float(config.get("timeout", 5)), expiring_days=int(config.get("tls_expiry_days", 30)))
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
        )
        engine = HttpEngine(timeout=float(config.get("timeout", 5)), paths=tuple(config.get("http_paths", []) or ()))
        findings = engine.run(service)
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


class FtpSafeModule(PortWiseModule):
    name = "ftp"
    description = "FTP cleartext exposure and anonymous-login check."
    supported_target_types = ("ftp_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "FTP Cleartext Service Exposed", Severity.MEDIUM, "FTP transmits credentials and data without transport encryption.")]
        if bool(config.get("ftp_anonymous_check", True)):
            try:
                ftp = ftplib.FTP()
                ftp.connect(str(target["host"]), int(target["port"]), timeout=float(config.get("timeout", 5)))
                ftp.login("anonymous", "anonymous@")
                ftp.quit()
                findings.append(_simple_finding(self.name, target, "Anonymous FTP Login Enabled", Severity.HIGH, "Anonymous FTP login was accepted.", strength=5, confidence=Confidence.CONFIRMED, manual=False))
            except Exception:
                pass
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class SshSafeModule(PortWiseModule):
    name = "ssh"
    description = "SSH exposure and version-disclosure checks without authentication attempts."
    supported_target_types = ("ssh_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "SSH Service Exposed", Severity.LOW, "SSH is reachable and should be owner-approved.")]
        if target.get("version") or target.get("product"):
            findings.append(_simple_finding(self.name, target, "SSH Version Disclosure", Severity.INFO, "SSH product/version is visible in service fingerprint."))
        if "openssh 5" in target_text(target) or "openssh 4" in target_text(target):
            findings.append(_simple_finding(self.name, target, "Legacy SSH Service", Severity.MEDIUM, "SSH service appears to be an old major version."))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class SmbSafeModule(PortWiseModule):
    name = "smb"
    description = "SMB exposure and safe Nmap-script evidence parser."
    supported_target_types = ("smb_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        findings = [_simple_finding(self.name, target, "SMB Service Exposed", Severity.MEDIUM, "SMB is reachable and should be limited to trusted networks.")]
        if "smbv1" in text or "nt lm 0.12" in text:
            findings.append(_simple_finding(self.name, target, "SMBv1 Enabled", Severity.HIGH, "Nmap script evidence indicates SMBv1 may be enabled.", strength=4))
        if "message signing disabled" in text or "signing: disabled" in text or "signing not required" in text:
            findings.append(_simple_finding(self.name, target, "SMB Signing Not Required", Severity.MEDIUM, "SMB signing appears not required.", strength=4))
        if "domain" in text or "workgroup" in text or "os:" in text:
            findings.append(_simple_finding(self.name, target, "SMB OS/Domain Disclosure", Severity.LOW, "SMB script evidence discloses OS or domain metadata.", strength=4))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class RdpSafeModule(PortWiseModule):
    name = "rdp"
    description = "RDP exposure checks without login attempts."
    supported_target_types = ("rdp_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "RDP Service Exposed", Severity.MEDIUM, "RDP is reachable and should be restricted.")]
        if "nla: disabled" in target_text(target):
            findings.append(_simple_finding(self.name, target, "RDP NLA Disabled", Severity.HIGH, "Nmap script evidence indicates NLA is disabled.", strength=4))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class WinRmSafeModule(PortWiseModule):
    name = "winrm"
    description = "WinRM exposure checks without authentication attempts."
    supported_target_types = ("winrm_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        severity = Severity.HIGH if int(target.get("port", 0)) == 5985 else Severity.MEDIUM
        finding = _simple_finding(self.name, target, "WinRM Exposed", severity, "WinRM management endpoint is reachable.")
        return ModuleResult(self.name, target, findings=[finding], evidence=finding.evidence)


class SnmpSafeModule(PortWiseModule):
    name = "snmp"
    description = "SNMP exposure and optional default-community check."
    supported_target_types = ("snmp_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        snmp_config = config.get("snmp", {}) if isinstance(config.get("snmp"), dict) else {}
        findings = [
            _simple_finding(self.name, target, "SNMP Service Exposed", Severity.MEDIUM, "SNMP service is reachable based on discovery evidence."),
            _simple_finding(self.name, target, "SNMP v1/v2c Exposed", Severity.MEDIUM, "SNMP v1/v2c may disclose device metadata when community strings are accepted."),
        ]
        if bool(snmp_config.get("default_community_check", config.get("snmp_default_community_check", True))):
            for community in list(snmp_config.get("communities", ["public", "private"]))[:2]:
                value = _snmp_get(str(target["host"]), int(target["port"]), str(community), _timeout(config, "snmp", 3.0))
                if value:
                    findings.append(_simple_finding(self.name, target, "Default SNMP Community Accepted", Severity.HIGH, f"SNMP community '{community}' returned minimal system metadata: {_truncate(value, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False))
                    findings.append(_simple_finding(self.name, target, "SNMP Information Disclosure", Severity.MEDIUM, f"SNMP returned minimal system metadata: {_truncate(value, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False))
                    break
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class DnsSafeModule(PortWiseModule):
    name = "dns"
    description = "DNS exposure, recursion, version, and bounded zone-transfer checks."
    supported_target_types = ("dns_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        dns_config = config.get("dns", {}) if isinstance(config.get("dns"), dict) else {}
        findings = [_simple_finding(self.name, target, "DNS Service Exposed", Severity.LOW, "DNS service is reachable.")]
        timeout = _timeout(config, "dns", 3.0)
        if dns_config.get("recursion_check", True):
            answer = _dns_query(str(target["host"]), int(target["port"]), "example.com", 1, timeout, recursion=True)
            if answer and answer.get("ra") and answer.get("ancount", 0) > 0:
                findings.append(_simple_finding(self.name, target, "DNS Recursion Enabled", Severity.MEDIUM, "Resolver answered a recursive query for example.com.", strength=5, confidence=Confidence.CONFIRMED, manual=False))
        version = _dns_chaos_version(str(target["host"]), int(target["port"]), timeout)
        if version:
            findings.append(_simple_finding(self.name, target, "DNS Version Disclosure", Severity.LOW, f"DNS CHAOS version query returned: {_truncate(version, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False))
        zones = list(dns_config.get("zones", []) or [])
        if dns_config.get("zone_transfer_check", True) and zones:
            for zone in zones[:5]:
                if _dns_axfr_check(str(target["host"]), int(target["port"]), str(zone), timeout):
                    findings.append(_simple_finding(self.name, target, "DNS Zone Transfer Allowed", Severity.HIGH, f"AXFR succeeded for configured zone {zone}.", strength=5, confidence=Confidence.CONFIRMED, manual=False))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class NtpSafeModule(PortWiseModule):
    name = "ntp"
    description = "NTP exposure and version/info checks."
    supported_target_types = ("ntp_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "NTP Service Exposed", Severity.LOW, "NTP service is reachable.")]
        response = _ntp_request(str(target["host"]), int(target["port"]), _timeout(config, "ntp", 3.0))
        if response:
            findings.append(_simple_finding(self.name, target, "NTP Information Disclosure", Severity.INFO, f"NTP returned a valid time response; stratum={response.get('stratum')}.", strength=5, confidence=Confidence.CONFIRMED, manual=False))
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
        findings = [_simple_finding(self.name, target, title, severity, "Database service is reachable; no data was queried or dumped.")]
        if bool((config.get("database", {}) if isinstance(config.get("database"), dict) else {}).get("unauthenticated_checks", True)):
            findings.extend(_database_safe_probe(self.name, target, config, text))
        if target.get("version"):
            findings.append(_simple_finding(self.name, target, "Database Version Disclosure", Severity.INFO, "Database product/version is visible in service fingerprint."))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class DevOpsAdminModule(PortWiseModule):
    name = "devops"
    description = "DevOps/admin panel fingerprint checks."
    supported_target_types = ("devops_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        findings = [_simple_finding(self.name, target, "DevOps/Admin Panel Exposed", Severity.MEDIUM, "Administrative or DevOps service fingerprint is reachable.")]
        probe = _safe_http_fingerprint(target, config, ["/", "/login", "/-/readiness", "/api/v4/version", "/service/rest/v1/status", "/api/health", "/-/health"])
        if probe:
            status, title, indicator, url = probe
            findings[0].evidence[0].data.update({"url": url, "status": status, "title": title, "indicator": indicator})
            if status == 200 and any(word in indicator.lower() for word in ("anonymous", "public", "unauthenticated", "ready", "healthy")):
                findings.append(_simple_finding(self.name, target, "Anonymous Access Possible", Severity.MEDIUM, f"Safe endpoint responded with public status indicator at {url}.", strength=4))
            if any(word in target_text(target) + " " + indicator.lower() for word in ("vault", "consul", "minio", "airflow", "jupyter", "portainer")):
                findings.append(_simple_finding(self.name, target, "Sensitive Management Interface Exposed", Severity.HIGH, f"Sensitive management fingerprint observed at {url}.", strength=4))
        if target.get("version"):
            findings.append(_simple_finding(self.name, target, "Version Disclosure", Severity.INFO, "Service version is visible in fingerprint."))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class KubernetesContainerModule(PortWiseModule):
    name = "kubernetes"
    description = "Container management exposure checks using safe endpoints only."
    supported_target_types = ("kubernetes_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        if "docker registry" in text:
            title = "Docker Registry Exposed"
            paths = ["/v2/"]
        elif "docker" in text:
            title = "Docker API Exposed"
            paths = ["/version"]
        elif "etcd" in text:
            title = "etcd Exposed"
            paths = ["/version", "/health"]
        elif "kubelet" in text:
            title = "Kubelet Endpoint Exposed"
            paths = ["/healthz"]
        else:
            title = "Kubernetes API Exposed"
            paths = ["/version", "/readyz", "/healthz"]
        finding = _simple_finding(self.name, target, title, Severity.HIGH, "Container management interface is reachable. Only safe metadata endpoints are in scope.")
        probe = _safe_http_fingerprint(target, config, paths)
        if probe:
            status, title_text, indicator, url = probe
            finding.evidence[0].data.update({"url": url, "status": status, "title": title_text, "indicator": indicator})
        return ModuleResult(self.name, target, findings=[finding], evidence=finding.evidence)


class MailSafeModule(PortWiseModule):
    name = "mail"
    description = "Mail service exposure and STARTTLS/banner checks."
    supported_target_types = ("mail_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        findings: list[Finding] = []
        if "smtp" in text or int(target.get("port", 0)) in {25, 465, 587}:
            findings.append(_simple_finding(self.name, target, "SMTP Service Exposed", Severity.LOW, "SMTP service is reachable; no mail sending was performed."))
            banner, replies = _smtp_safe_check(str(target["host"]), int(target["port"]), _timeout(config, "mail", 4.0))
            if banner:
                findings.append(_simple_finding(self.name, target, "Mail Server Version Disclosure", Severity.INFO, f"SMTP banner: {_truncate(banner, 160)}", strength=4))
            if replies.get("starttls") is False and int(target.get("port", 0)) in {25, 587}:
                findings.append(_simple_finding(self.name, target, "SMTP STARTTLS Missing", Severity.MEDIUM, "SMTP EHLO capabilities did not advertise STARTTLS.", strength=4))
            if replies.get("vrfy"):
                findings.append(_simple_finding(self.name, target, "VRFY Enabled", Severity.LOW, "SMTP server accepted VRFY command syntax check without user enumeration.", strength=4))
            if replies.get("expn"):
                findings.append(_simple_finding(self.name, target, "EXPN Enabled", Severity.LOW, "SMTP server accepted EXPN command syntax check without list enumeration.", strength=4))
        else:
            title = "POP3 Cleartext Service Exposed" if "pop3" in text or int(target.get("port", 0)) == 110 else "IMAP Cleartext Service Exposed"
            findings.append(_simple_finding(self.name, target, title, Severity.LOW, "Mail service is reachable; no authentication was attempted."))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


class VpnApplianceModule(PortWiseModule):
    name = "vpn"
    description = "VPN/security appliance fingerprint checks only."
    supported_target_types = ("vpn_appliance_targets",)

    def run(self, target: dict[str, Any], config: dict[str, Any]) -> ModuleResult:
        text = target_text(target)
        title = "VPN Interface Exposed" if any(word in text for word in ("vpn", "globalprotect", "fortigate", "pulse", "ivanti", "horizon")) else "Security Appliance Interface Exposed"
        findings = [_simple_finding(self.name, target, title, Severity.MEDIUM, "Security appliance interface is reachable based on fingerprint evidence.")]
        findings.append(_simple_finding(self.name, target, "Needs Owner Validation", Severity.INFO, "Security appliance exposure should be validated with the service owner.", confidence=Confidence.INFORMATIONAL))
        if target.get("version"):
            findings.append(_simple_finding(self.name, target, "Appliance Version Disclosure", Severity.INFO, "Appliance version is visible in fingerprint."))
        return ModuleResult(self.name, target, findings=findings, evidence=[e for f in findings for e in f.evidence])


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


def _database_safe_probe(module: str, target: dict[str, Any], config: dict[str, Any], text: str) -> list[Finding]:
    host = str(target["host"])
    port = int(target["port"])
    timeout = _timeout(config, "database", 4.0)
    findings: list[Finding] = []
    if "redis" in text:
        try:
            data = _tcp_send_recv(host, port, b"*1\r\n$4\r\nPING\r\n", timeout)
            if b"PONG" in data:
                findings.append(_simple_finding(module, target, "Unauthenticated Redis Access", Severity.HIGH, "Redis PING succeeded without AUTH.", strength=5, confidence=Confidence.CONFIRMED, manual=False))
        except Exception:
            pass
    elif "memcached" in text:
        try:
            data = _tcp_send_recv(host, port, b"version\r\n", timeout)
            if data:
                findings.append(_simple_finding(module, target, "Memcached Exposed", Severity.HIGH, f"Memcached responded to version check: {_truncate(data, 160)}", strength=5, confidence=Confidence.CONFIRMED, manual=False))
        except Exception:
            pass
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
        probe = _safe_http_fingerprint(target, config, selected)
        if probe:
            status, title, indicator, url = probe
            product_title = "Unauthenticated Elasticsearch Access" if "elasticsearch" in text else "Database Service Exposed"
            findings.append(_simple_finding(module, target, product_title, Severity.HIGH if status == 200 else Severity.MEDIUM, f"Safe database HTTP endpoint responded at {url}: {_truncate(indicator, 180)}", strength=5 if status == 200 else 4))
    return findings


def _safe_http_fingerprint(target: dict[str, Any], config: dict[str, Any], paths: list[str]) -> tuple[int, str, str, str] | None:
    host = str(target["host"])
    port = int(target["port"])
    timeout = _timeout(config, default=4.0)
    for path in paths:
        try:
            status, headers, body, scheme = _http_request(host, port, path, timeout)
        except Exception:
            continue
        title = _extract_title(body)
        indicator = title or headers.get("server", "") or headers.get("x-powered-by", "") or body[:160]
        if status in {200, 301, 302, 401, 403}:
            return status, title, _truncate(indicator, 220), f"{scheme}://{host}:{port}{path}"
    return None


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

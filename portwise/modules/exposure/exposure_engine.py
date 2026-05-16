from __future__ import annotations

from portwise.core.models import Evidence, Finding, Service, Severity


RISKY_SERVICES: dict[str, tuple[Severity, str]] = {
    "ftp": (Severity.MEDIUM, "FTP exposure may disclose data or permit weak authentication paths."),
    "telnet": (Severity.HIGH, "Telnet transmits credentials and session data in clear text."),
    "ssh": (Severity.LOW, "SSH exposure should be owner-approved and hardened."),
    "smb": (Severity.MEDIUM, "SMB exposure should be restricted to trusted networks."),
    "microsoft-ds": (Severity.MEDIUM, "SMB exposure should be restricted to trusted networks."),
    "rdp": (Severity.MEDIUM, "RDP exposure increases remote access attack surface."),
    "ms-wbt-server": (Severity.MEDIUM, "RDP exposure increases remote access attack surface."),
    "winrm": (Severity.MEDIUM, "WinRM exposure should be limited to management networks."),
    "snmp": (Severity.MEDIUM, "SNMP exposure can disclose sensitive device information."),
    "nfs": (Severity.MEDIUM, "NFS exposure can disclose file shares when misconfigured."),
    "rsync": (Severity.MEDIUM, "Rsync exposure can disclose file data when misconfigured."),
    "redis": (Severity.HIGH, "Redis should not be exposed without strict network controls."),
    "mongodb": (Severity.HIGH, "MongoDB exposure should be restricted and authenticated."),
    "elasticsearch": (Severity.HIGH, "Elasticsearch exposure can disclose indexed data."),
    "memcached": (Severity.HIGH, "Memcached exposure can leak cached data and amplify traffic."),
    "docker": (Severity.HIGH, "Docker API exposure can permit container control."),
    "kubernetes": (Severity.HIGH, "Kubernetes API exposure should be tightly controlled."),
    "jenkins": (Severity.MEDIUM, "Jenkins exposure can increase CI/CD attack surface."),
    "grafana": (Severity.MEDIUM, "Grafana exposure should be reviewed for auth and data access."),
    "kibana": (Severity.MEDIUM, "Kibana exposure can disclose indexed telemetry."),
    "prometheus": (Severity.MEDIUM, "Prometheus exposure can disclose infrastructure metrics."),
    "rabbitmq": (Severity.MEDIUM, "RabbitMQ management exposure should be restricted."),
    "sonarqube": (Severity.MEDIUM, "SonarQube exposure can disclose source quality metadata."),
    "nexus": (Severity.MEDIUM, "Nexus repository exposure should be owner-approved."),
    "artifactory": (Severity.MEDIUM, "Artifactory exposure should be owner-approved."),
    "tomcat": (Severity.MEDIUM, "Tomcat Manager exposure should be restricted."),
    "jboss": (Severity.HIGH, "JBoss/WildFly management exposure is high risk."),
    "wildfly": (Severity.HIGH, "JBoss/WildFly management exposure is high risk."),
    "weblogic": (Severity.HIGH, "WebLogic exposure should be strictly controlled."),
    "vpn": (Severity.MEDIUM, "VPN/security appliance exposure should be hardened and owner-approved."),
    "fortinet": (Severity.MEDIUM, "VPN/security appliance exposure should be hardened and owner-approved."),
    "palo alto": (Severity.MEDIUM, "VPN/security appliance exposure should be hardened and owner-approved."),
}


def _raise_for_external(severity: Severity) -> Severity:
    if severity == Severity.LOW:
        return Severity.MEDIUM
    if severity == Severity.MEDIUM:
        return Severity.HIGH
    return severity


def evaluate_exposure(service: Service, context: str = "unknown") -> list[Finding]:
    haystack = " ".join([service.service_name, service.product, service.extrainfo, " ".join(service.cpes)]).lower()
    findings: list[Finding] = []
    for key, (base_severity, detail) in RISKY_SERVICES.items():
        if key not in haystack:
            continue
        severity = _raise_for_external(base_severity) if context == "external" else base_severity
        suffix = " Needs Owner Validation" if context == "unknown" else ""
        evidence = Evidence(
            source="nmap-service-fingerprint",
            description=f"Service fingerprint matched exposure keyword '{key}'.",
            strength=2,
            data={"service": service.service_name, "product": service.product, "port": service.port},
        )
        finding = Finding(
            title=f"Exposed {key.upper()} Service{suffix}",
            severity=severity,
            asset=service.host,
            port=service.port,
            protocol=service.protocol,
            service=service.service_name,
            description=detail,
            recommendation="Validate business requirement, restrict network access, and ensure hardened configuration.",
            evidence_strength=2,
            type="exposure",
            evidence=[evidence],
            tags=["exposure", context],
        )
        findings.append(finding)
        break
    return findings

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from portwise.core.models import Asset, ModuleTarget, Service
from portwise.modules.tls.tls_engine import TlsEngine
from portwise.utils.files import ensure_dir, write_json


ROUTE_KEYS = (
    "http_targets",
    "tls_targets",
    "smb_targets",
    "ssh_targets",
    "rdp_targets",
    "winrm_targets",
    "ftp_targets",
    "snmp_targets",
    "dns_targets",
    "ntp_targets",
    "database_targets",
    "devops_targets",
    "kubernetes_targets",
    "mail_targets",
    "vpn_appliance_targets",
    "unknown_services",
)


HTTP_HINTS = ("http", "http-proxy", "web", "apache", "nginx", "iis", "tomcat", "jetty", "gunicorn", "werkzeug", "node", "express")
DB_HINTS = ("mysql", "mariadb", "postgres", "postgresql", "mssql", "oracle", "mongodb", "redis", "elasticsearch", "cassandra", "couchdb", "memcached", "influxdb", "neo4j", "solr", "zookeeper", "etcd")
DEVOPS_HINTS = ("jenkins", "gitlab", "gitea", "nexus", "artifactory", "sonarqube", "grafana", "kibana", "prometheus", "alertmanager", "rabbitmq", "portainer", "docker registry", "harbor", "webmin", "cockpit", "phpmyadmin", "adminer", "tomcat manager", "jboss", "wildfly", "weblogic", "airflow", "jupyter", "minio", "consul", "vault")
K8S_HINTS = ("kubernetes", "kubelet", "docker api", "etcd", "docker registry", "prometheus", "cadvisor", "traefik", "envoy", "portainer", "minio")
VPN_HINTS = ("fortinet", "fortigate", "fortiweb", "fortianalyzer", "palo alto", "globalprotect", "cisco asa", "cisco ftd", "citrix adc", "citrix gateway", "netscaler", "f5", "big-ip", "pulse", "ivanti", "sonicwall", "sophos", "check point", "zyxel", "vmware horizon", "uag", "zscaler", "zpa", "akamai")
MAIL_HINTS = ("smtp", "imap", "pop3", "submission", "smtps", "imaps", "pop3s", "postfix", "exim", "dovecot", "sendmail")


def route_assets(assets: list[Asset], *, probe_tls: bool = False) -> dict[str, list[ModuleTarget]]:
    routes: dict[str, list[ModuleTarget]] = {key: [] for key in ROUTE_KEYS}
    tls_engine = TlsEngine(timeout=2.0) if probe_tls else None

    for asset in assets:
        for service in asset.services:
            if service.state not in {"open", "open|filtered"}:
                continue
            matched = _route_service(service, tls_engine)
            for key, reason in matched:
                routes[key].append(_target(service, reason))
            if not matched:
                routes["unknown_services"].append(_target(service, "No fingerprint route matched."))
    return routes


def write_target_files(routes: dict[str, list[ModuleTarget]], output_root: Path) -> list[str]:
    target_dir = ensure_dir(output_root / "evidence" / "targets")
    written: list[str] = []
    selected = {
        "http_targets": routes.get("http_targets", []),
        "tls_targets": routes.get("tls_targets", []),
        "smb_targets": routes.get("smb_targets", []),
        "database_targets": routes.get("database_targets", []),
        "exposure_targets": _exposure_targets(routes),
        "all_services": _all_targets(routes),
    }
    for name, targets in selected.items():
        path = target_dir / f"{name}.json"
        write_json(path, [asdict(target) for target in targets])
        written.append(str(path))
    return written


def module_target_counts(routes: dict[str, list[ModuleTarget]]) -> dict[str, int]:
    return {key: len(value) for key, value in routes.items()}


def _route_service(service: Service, tls_engine: TlsEngine | None) -> list[tuple[str, str]]:
    text = _fingerprint(service)
    routes: list[tuple[str, str]] = []

    _add_if(routes, "http_targets", any(hint in text for hint in HTTP_HINTS), "HTTP/web fingerprint matched.")
    _add_if(routes, "tls_targets", _is_tls(service, text, tls_engine), "TLS tunnel/fingerprint/handshake matched.")
    _add_if(routes, "smb_targets", any(hint in text for hint in ("microsoft-ds", "netbios-ssn", "smb", "samba")) or service.port in {139, 445}, "SMB fingerprint or fallback port matched.")
    _add_if(routes, "ssh_targets", "ssh" in text, "SSH fingerprint matched.")
    _add_if(routes, "rdp_targets", any(hint in text for hint in ("ms-wbt-server", "rdp", "terminal service")) or service.port == 3389, "RDP fingerprint or fallback port matched.")
    _add_if(routes, "winrm_targets", "winrm" in text or service.port in {5985, 5986}, "WinRM fingerprint or fallback port matched.")
    _add_if(routes, "ftp_targets", "ftp" in text, "FTP fingerprint matched.")
    _add_if(routes, "snmp_targets", "snmp" in text or (service.protocol == "udp" and service.port == 161), "SNMP fingerprint or UDP 161 fallback matched.")
    _add_if(routes, "dns_targets", "domain" in text or "dns" in text or service.port == 53, "DNS fingerprint or port fallback matched.")
    _add_if(routes, "ntp_targets", "ntp" in text or (service.protocol == "udp" and service.port == 123), "NTP fingerprint or UDP 123 fallback matched.")
    _add_if(routes, "database_targets", any(hint in text for hint in DB_HINTS), "Database fingerprint matched.")
    _add_if(routes, "devops_targets", any(hint in text for hint in DEVOPS_HINTS), "DevOps/admin fingerprint matched.")
    _add_if(routes, "kubernetes_targets", any(hint in text for hint in K8S_HINTS), "Kubernetes/container fingerprint matched.")
    _add_if(routes, "mail_targets", any(hint in text for hint in MAIL_HINTS), "Mail service fingerprint matched.")
    _add_if(routes, "vpn_appliance_targets", any(hint in text for hint in VPN_HINTS), "VPN/security appliance fingerprint matched.")
    return routes


def _target(service: Service, reason: str) -> ModuleTarget:
    return ModuleTarget(
        host=service.host,
        port=service.port,
        protocol=service.protocol,
        service=service.service_name,
        product=service.product,
        version=service.version,
        cpe=service.cpes,
        confidence=service.confidence,
        routing_reason=reason,
    )


def _fingerprint(service: Service) -> str:
    return " ".join([
        service.service_name,
        service.product,
        service.version,
        service.extrainfo,
        service.tunnel or "",
        " ".join(service.cpes),
        " ".join(service.scripts.values()),
    ]).lower()


def _is_tls(service: Service, text: str, tls_engine: TlsEngine | None) -> bool:
    if service.tunnel == "ssl" or service.service_name.lower().startswith("ssl/") or "https" in text or " tls" in f" {text}":
        return True
    return bool(tls_engine and service.state == "open" and tls_engine.detect_tls(service.host, service.port, service.hostname))


def _add_if(routes: list[tuple[str, str]], key: str, condition: bool, reason: str) -> None:
    if condition:
        routes.append((key, reason))


def _all_targets(routes: dict[str, list[ModuleTarget]]) -> list[ModuleTarget]:
    seen: set[tuple[str, int, str]] = set()
    all_items: list[ModuleTarget] = []
    for key, targets in routes.items():
        if key == "unknown_services":
            source = targets
        else:
            source = targets
        for target in source:
            identity = (target.host, target.port, target.protocol)
            if identity in seen:
                continue
            seen.add(identity)
            all_items.append(target)
    return all_items


def _exposure_targets(routes: dict[str, list[ModuleTarget]]) -> list[ModuleTarget]:
    exposure_keys = [key for key in ROUTE_KEYS if key not in {"unknown_services"}]
    merged: list[ModuleTarget] = []
    seen: set[tuple[str, int, str]] = set()
    for key in exposure_keys:
        for target in routes.get(key, []):
            identity = (target.host, target.port, target.protocol)
            if identity not in seen:
                seen.add(identity)
                merged.append(target)
    return merged

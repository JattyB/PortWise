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

# Port-based fallbacks: nmap often labels alt ports with default names that are
# not real service fingerprints (e.g. Cloudflare's 2052/2082 as "clearvisn",
# 5000 as "upnp"). Without these, web/TLS/data checks never ran on those ports.
HTTP_PORTS = {
    80, 81, 88, 280, 591, 593, 2052, 2082, 2086, 2095, 3000, 3128, 3333,
    5000, 5104, 5800, 7000, 7001, 8000, 8001, 8008, 8042, 8060, 8069, 8080,
    8081, 8083, 8088, 8090, 8091, 8095, 8118, 8123, 8222, 8280, 8281, 8333,
    8500, 8800, 8880, 8888, 8983, 9000, 9001, 9080, 9090, 9091, 9999, 16080,
}
HTTPS_PORTS = {
    443, 832, 981, 1311, 2053, 2083, 2087, 2096, 4443, 4444, 5443, 7443,
    8443, 8834, 9443, 10443, 12443, 16443, 18443,
}
# port -> database/cache hint used both for routing and probe selection
DB_PORT_HINTS = {
    3306: "mysql", 5432: "postgresql", 1433: "mssql", 1521: "oracle",
    27017: "mongodb", 27018: "mongodb", 6379: "redis", 11211: "memcached",
    9200: "elasticsearch", 9300: "elasticsearch", 5984: "couchdb",
    8983: "solr", 2379: "etcd", 7474: "neo4j", 8086: "influxdb", 9042: "cassandra",
}
# Docker / container management ports
DOCKER_PORTS = {2375, 2376}


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
    port = service.port
    tcp = service.protocol == "tcp"

    web_port = tcp and (port in HTTP_PORTS or port in HTTPS_PORTS)
    _add_if(routes, "http_targets", any(hint in text for hint in HTTP_HINTS) or web_port, "HTTP/web fingerprint or common web port matched.")
    _add_if(routes, "tls_targets", _is_tls(service, text, tls_engine) or (tcp and port in HTTPS_PORTS), "TLS tunnel/fingerprint/handshake or HTTPS port matched.")
    _add_if(routes, "smb_targets", any(hint in text for hint in ("microsoft-ds", "netbios-ssn", "smb", "samba")) or service.port in {139, 445}, "SMB fingerprint or fallback port matched.")
    _add_if(routes, "ssh_targets", "ssh" in text or port == 22, "SSH fingerprint or port 22 matched.")
    _add_if(routes, "rdp_targets", any(hint in text for hint in ("ms-wbt-server", "rdp", "terminal service")) or service.port == 3389, "RDP fingerprint or fallback port matched.")
    _add_if(routes, "winrm_targets", "winrm" in text or service.port in {5985, 5986}, "WinRM fingerprint or fallback port matched.")
    _add_if(routes, "ftp_targets", "ftp" in text or port == 21, "FTP fingerprint or port 21 matched.")
    _add_if(routes, "snmp_targets", "snmp" in text or (service.protocol == "udp" and service.port == 161), "SNMP fingerprint or UDP 161 fallback matched.")
    _add_if(routes, "dns_targets", "domain" in text or "dns" in text or service.port == 53, "DNS fingerprint or port fallback matched.")
    _add_if(routes, "ntp_targets", "ntp" in text or (service.protocol == "udp" and service.port == 123), "NTP fingerprint or UDP 123 fallback matched.")
    db_port = tcp and port in DB_PORT_HINTS
    _add_if(routes, "database_targets", any(hint in text for hint in DB_HINTS) or db_port, "Database fingerprint or well-known DB port matched.")
    _add_if(routes, "devops_targets", any(hint in text for hint in DEVOPS_HINTS), "DevOps/admin fingerprint matched.")
    _add_if(routes, "kubernetes_targets", any(hint in text for hint in K8S_HINTS) or (tcp and port in DOCKER_PORTS), "Kubernetes/container fingerprint or Docker port matched.")
    _add_if(routes, "mail_targets", any(hint in text for hint in MAIL_HINTS) or port in {25, 110, 143, 587, 993, 995}, "Mail service fingerprint or port matched.")
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
        scripts=service.scripts,
        hostname=service.hostname,
    )


def _fingerprint(service: Service) -> str:
    script_texts = []
    for v in service.scripts.values():
        script_texts.append(v.get("output", "") if isinstance(v, dict) else str(v))
    return " ".join([
        service.service_name,
        service.product,
        service.version,
        service.extrainfo,
        service.tunnel or "",
        " ".join(service.cpes),
        " ".join(script_texts),
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

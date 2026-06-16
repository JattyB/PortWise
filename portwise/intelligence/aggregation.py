"""Aggregation helpers that turn a PortWise run into PT-buddy views:

* port-centric rollups ("port 22 open on N hosts, here are the IPs"),
* cleartext-protocol exposure rollups,
* weak-crypto (SSH/SMB/TLS) highlights,
* a compact finding overview.

Everything here reads an already-produced run dict (runs/latest.json), so it is
pure data shaping with no network access.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Well-known service labels for ports that often lack a service name in evidence.
_PORT_LABELS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    514: "syslog", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm-https",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


@dataclass(slots=True)
class PortGroup:
    port: int
    protocol: str
    hosts: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.hosts)

    @property
    def label(self) -> str:
        if self.services:
            return self.services[0]
        return _PORT_LABELS.get(self.port, "unknown")

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.label,
            "host_count": self.count,
            "hosts": self.hosts,
            "services_seen": self.services,
        }


def _state(run: dict[str, Any]) -> dict[str, Any]:
    return (run.get("metadata", {}) or {}).get("state", {}) or {}


def aggregate_ports(run: dict[str, Any]) -> list[PortGroup]:
    """Build per-(protocol, port) rollups across all hosts in a run."""
    state = _state(run)
    groups: dict[tuple[str, int], PortGroup] = {}

    def _group(protocol: str, port: int) -> PortGroup:
        key = (protocol, int(port))
        if key not in groups:
            groups[key] = PortGroup(port=int(port), protocol=protocol)
        return groups[key]

    # Richest source first: services_by_host carries service names.
    services_by_host = state.get("services_by_host", {}) or {}
    for host, services in services_by_host.items():
        for svc in services:
            if str(svc.get("state", "open")) not in ("open", "open|filtered"):
                continue
            proto = str(svc.get("protocol", "tcp"))
            port = int(svc.get("port", 0) or 0)
            if port <= 0:
                continue
            grp = _group(proto, port)
            if host not in grp.hosts:
                grp.hosts.append(host)
            name = str(svc.get("service_name", "") or "").strip()
            if name and name not in grp.services:
                grp.services.append(name)

    # Fall back to raw open-port maps for anything not already captured.
    for proto, key in (("tcp", "tcp_open_ports_by_host"), ("udp", "udp_open_ports_by_host")):
        for host, ports in (state.get(key, {}) or {}).items():
            for port in ports:
                grp = _group(proto, int(port))
                if host not in grp.hosts:
                    grp.hosts.append(host)

    for grp in groups.values():
        grp.hosts.sort()

    return sorted(groups.values(), key=lambda g: (-g.count, g.protocol, g.port))


def filter_ports(
    groups: list[PortGroup],
    *,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
    min_count: int = 1,
) -> list[PortGroup]:
    out = []
    svc = (service or "").lower()
    for g in groups:
        if port is not None and g.port != port:
            continue
        if protocol and g.protocol != protocol.lower():
            continue
        if svc and svc not in g.label.lower() and not any(svc in s.lower() for s in g.services):
            continue
        if g.count < min_count:
            continue
        out.append(g)
    return out


def plaintext_summary(run: dict[str, Any]) -> list[dict[str, Any]]:
    """Group cleartext-protocol findings by label with affected hosts."""
    buckets: dict[str, dict[str, Any]] = {}
    for f in run.get("findings", []) or []:
        tags = f.get("tags", []) or []
        if "plaintext-protocol" not in tags:
            continue
        title = f.get("title", "Cleartext Protocol")
        label = title.split("—")[-1].strip() if "—" in title else title
        b = buckets.setdefault(label, {
            "protocol": label,
            "severity": f.get("severity", "low"),
            "hosts": [],
            "ports": set(),
        })
        endpoint = f"{f.get('asset', '')}:{f.get('port', '')}"
        if endpoint not in b["hosts"]:
            b["hosts"].append(endpoint)
        if f.get("port"):
            b["ports"].add(int(f["port"]))
    out = []
    for b in buckets.values():
        b["ports"] = sorted(b["ports"])
        b["host_count"] = len(b["hosts"])
        out.append(b)
    return sorted(out, key=lambda x: (-x["host_count"], x["protocol"]))


_WEAK_TITLE_HINTS = (
    "weak ssh", "deprecated ssh", "smbv1", "smb signing", "anonymous ftp",
    "rdp nla", "weak rdp", "default", "self-signed", "expired", "sslv", "tls 1.0",
    "tls 1.1", "weak cipher", "rc4", "sweet32", "heartbleed",
)


def weak_crypto_summary(run: dict[str, Any]) -> list[dict[str, Any]]:
    """High-signal hardening findings (weak SSH/SMB/RDP/TLS) grouped by title."""
    buckets: dict[str, dict[str, Any]] = {}
    for f in run.get("findings", []) or []:
        title = str(f.get("title", ""))
        tl = title.lower()
        if not any(h in tl for h in _WEAK_TITLE_HINTS):
            continue
        if str(f.get("confidence")) in ("False Positive Candidate",):
            continue
        b = buckets.setdefault(title, {
            "title": title,
            "severity": f.get("severity", "medium"),
            "confidence": f.get("confidence", ""),
            "hosts": [],
        })
        endpoint = f"{f.get('asset', '')}:{f.get('port', '')}"
        if endpoint not in b["hosts"]:
            b["hosts"].append(endpoint)
    out = []
    for b in buckets.values():
        b["host_count"] = len(b["hosts"])
        out.append(b)
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    return sorted(out, key=lambda x: (_sev_rank.get(str(x["severity"]), 5), -x["host_count"]))


def finding_overview(run: dict[str, Any]) -> dict[str, Any]:
    """Compact counts that exclude pure-noise rows."""
    findings = run.get("findings", []) or []
    by_conf: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    actionable = 0
    for f in findings:
        conf = str(f.get("confidence", ""))
        sev = str(f.get("severity", ""))
        by_conf[conf] = by_conf.get(conf, 0) + 1
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if conf in ("Confirmed", "Likely") and sev in ("critical", "high", "medium"):
            actionable += 1
    return {
        "total": len(findings),
        "actionable": actionable,
        "by_confidence": by_conf,
        "by_severity": by_sev,
    }

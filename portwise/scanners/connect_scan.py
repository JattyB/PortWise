"""Native async TCP connect scanner.

This is the last-ditch discovery path when Nmap is unavailable or explicitly
disabled. It performs bounded concurrent TCP connect attempts against a
configurable port set, records open ports, and synthesizes PortWise assets so
the existing module-routing pipeline can run unchanged.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from time import perf_counter
from typing import Any

from portwise.core.models import Asset, Service

DEFAULT_CONNECT_SCAN_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1010, 1011, 1012, 1433, 1521, 2049, 2375, 2376, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
)

PORT_SERVICE_HINTS: dict[int, tuple[str, str, str, str | None]] = {
    21: ("ftp", "ftp", "", None),
    22: ("ssh", "ssh", "", None),
    23: ("telnet", "telnet", "", None),
    25: ("smtp", "smtp", "", None),
    53: ("domain", "dns", "", None),
    80: ("http", "http", "", None),
    110: ("pop3", "pop3", "", None),
    111: ("sunrpc", "rpcbind", "", None),
    135: ("msrpc", "msrpc", "", None),
    139: ("netbios-ssn", "netbios-ssn", "", None),
    143: ("imap", "imap", "", None),
    389: ("ldap", "ldap", "", None),
    443: ("https", "https", "", "ssl"),
    1010: ("https", "https", "", "ssl"),
    1011: ("https", "https", "", "ssl"),
    1012: ("https", "https", "", "ssl"),
    445: ("microsoft-ds", "smb", "", None),
    465: ("smtps", "smtp", "", "ssl"),
    587: ("submission", "smtp", "", None),
    636: ("ldaps", "ldap", "", "ssl"),
    993: ("imaps", "imap", "", "ssl"),
    995: ("pop3s", "pop3", "", "ssl"),
    1433: ("ms-sql-s", "mssql", "", None),
    1521: ("oracle", "oracle", "", None),
    2049: ("nfs", "nfs", "", None),
    2375: ("docker", "docker", "", None),
    2376: ("docker", "docker", "", "ssl"),
    3306: ("mysql", "mysql", "", None),
    3389: ("ms-wbt-server", "rdp", "", None),
    5432: ("postgresql", "postgresql", "", None),
    5900: ("vnc", "vnc", "", None),
    6379: ("redis", "redis", "", None),
    8080: ("http", "http-proxy", "", None),
    8443: ("https", "https", "", "ssl"),
    9200: ("http", "elasticsearch", "", None),
    11211: ("memcache", "memcached", "", None),
    27017: ("mongodb", "mongodb", "", None),
}


@dataclass(slots=True)
class NativeConnectScanResult:
    hosts: list[str]
    ports: list[int]
    open_ports_by_host: dict[str, list[int]] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    ports_scanned: int = 0
    open_ports: int = 0
    ports_per_second: float = 0.0
    errors: list[str] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": self.hosts,
            "ports": self.ports,
            "open_ports_by_host": {host: ports[:] for host, ports in self.open_ports_by_host.items()},
            "elapsed_seconds": self.elapsed_seconds,
            "ports_scanned": self.ports_scanned,
            "open_ports": self.open_ports,
            "ports_per_second": self.ports_per_second,
            "errors": self.errors[:],
            "assets": [asdict(asset) for asset in self.assets],
        }


async def run_native_connect_scan(
    hosts: list[str],
    ports: list[int] | tuple[int, ...],
    *,
    timeout: float = 1.5,
    concurrency: int = 256,
) -> NativeConnectScanResult:
    """Run a bounded async TCP connect scan across hosts and ports."""
    normalized_hosts = [str(host).strip() for host in hosts if str(host).strip()]
    normalized_ports = [int(port) for port in ports if int(port) > 0]
    result = NativeConnectScanResult(hosts=normalized_hosts, ports=normalized_ports)
    if not normalized_hosts or not normalized_ports:
        return result

    started = perf_counter()
    semaphore = asyncio.Semaphore(max(1, int(concurrency)))
    tasks = [
        asyncio.create_task(_probe_port(host, port, timeout, semaphore))
        for host in normalized_hosts
        for port in normalized_ports
    ]
    result.ports_scanned = len(tasks)
    try:
        for host, port, open_, error in await asyncio.gather(*tasks):
            if open_:
                result.open_ports_by_host.setdefault(host, []).append(port)
                result.open_ports += 1
            elif error:
                result.errors.append(f"{host}:{port}: {error}")
    finally:
        result.elapsed_seconds = max(0.0, perf_counter() - started)
        result.ports_per_second = round(result.ports_scanned / result.elapsed_seconds, 2) if result.elapsed_seconds > 0 else float(result.ports_scanned)
        for host, ports_for_host in list(result.open_ports_by_host.items()):
            result.open_ports_by_host[host] = sorted(set(ports_for_host))
        result.assets = _assets_from_open_ports(result.open_ports_by_host)
    return result


async def _probe_port(host: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> tuple[str, int, bool, str]:
    async with semaphore:
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout)
        except Exception:
            return host, port, False, ""
        try:
            writer.close()
            wait_closed = getattr(writer, "wait_closed", None)
            if callable(wait_closed):
                try:
                    await asyncio.wait_for(wait_closed(), timeout=min(timeout, 1.0))
                except Exception:
                    pass
        except Exception:
            pass
        return host, port, True, ""


def _assets_from_open_ports(open_ports_by_host: dict[str, list[int]]) -> list[Asset]:
    assets: list[Asset] = []
    for host in sorted(open_ports_by_host):
        asset = Asset(ip=host, status="up")
        for port in sorted(set(open_ports_by_host[host])):
            service = _service_for_port(host, port)
            asset.add_service(service)
        assets.append(asset)
    return assets


def _service_for_port(host: str, port: int) -> Service:
    service_name, product, version, tunnel = PORT_SERVICE_HINTS.get(
        port,
        ("", "", "", None),
    )
    return Service(
        host=host,
        port=port,
        protocol="tcp",
        state="open",
        service_name=service_name,
        product=product,
        version=version,
        tunnel=tunnel,
        reason="connect-success",
    )

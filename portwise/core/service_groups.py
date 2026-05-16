from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from portwise.core.models import CommandResult
from portwise.utils.files import ensure_dir


@dataclass(slots=True)
class ServiceDetectionGroup:
    group_id: str
    ports: list[int]
    hosts: list[str]
    hosts_file: str | None = None
    command: list[str] | None = None
    output_prefix: str | None = None
    parsed_xml_file: str | None = None
    service_count_after_merge: int = 0

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["host_count"] = self.host_count
        return data


def group_hosts_by_ports(open_ports_by_host: dict[str, list[int]], protocol: str) -> list[ServiceDetectionGroup]:
    grouped: dict[tuple[int, ...], list[str]] = {}
    for host in sorted(open_ports_by_host):
        ports = sorted({int(port) for port in open_ports_by_host[host] if int(port) > 0})
        if not ports:
            continue
        grouped.setdefault(tuple(ports), []).append(host)

    groups: list[ServiceDetectionGroup] = []
    for index, ports in enumerate(sorted(grouped), start=1):
        groups.append(ServiceDetectionGroup(
            group_id=f"{protocol}_group_{index:03d}",
            ports=list(ports),
            hosts=sorted(grouped[ports]),
        ))
    return groups


def prepare_group_files(groups: list[ServiceDetectionGroup], workspace: Path) -> list[str]:
    output_dir = ensure_dir(workspace / "scans" / "service_groups")
    generated: list[str] = []
    for group in groups:
        path = output_dir / f"{group.group_id}_hosts.txt"
        path.write_text("\n".join(group.hosts) + "\n", encoding="utf-8")
        group.hosts_file = str(path)
        generated.append(str(path))
    return generated


def ports_to_arg(ports: list[int]) -> str:
    return ",".join(str(port) for port in sorted(ports))


def command_to_dict(command: CommandResult) -> dict[str, object]:
    return asdict(command)

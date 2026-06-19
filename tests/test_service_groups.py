from pathlib import Path

from portwise.core.config import load_config
from portwise.core.models import Asset, Service
from portwise.core.runner import _merge_assets, run_scan
from portwise.core.service_groups import group_hosts_by_ports, prepare_group_files
from portwise.scanners.nmap_runner import NmapRunner


def test_group_hosts_by_identical_tcp_port_sets() -> None:
    groups = group_hosts_by_ports({
        "192.0.2.8": [5985, 3389],
        "192.0.2.5": [443, 80, 22],
        "192.0.2.6": [22, 80, 443],
        "192.0.2.7": [445],
        "192.0.2.9": [3389, 5985],
        "192.0.2.10": [],
    }, "tcp")

    assert [group.group_id for group in groups] == ["tcp_group_001", "tcp_group_002", "tcp_group_003"]
    assert groups[0].ports == [22, 80, 443]
    assert groups[0].hosts == ["192.0.2.5", "192.0.2.6"]
    assert groups[1].ports == [445]
    assert groups[2].ports == [3389, 5985]
    assert groups[2].hosts == ["192.0.2.8", "192.0.2.9"]


def test_group_hosts_by_identical_udp_port_sets() -> None:
    groups = group_hosts_by_ports({
        "192.0.2.5": [161, 53],
        "192.0.2.6": [53, 161],
        "192.0.2.7": [123],
        "192.0.2.8": [],
    }, "udp")

    assert [group.group_id for group in groups] == ["udp_group_001", "udp_group_002"]
    assert groups[0].ports == [53, 161]
    assert groups[0].hosts == ["192.0.2.5", "192.0.2.6"]
    assert groups[1].ports == [123]


def test_tcp_group_command_generation(tmp_path: Path) -> None:
    runner = NmapRunner(tmp_path)
    groups = group_hosts_by_ports({"192.0.2.5": [22, 80, 443]}, "tcp")
    prepare_group_files(groups, tmp_path)

    command = runner.build_service_detection_command("tcp", groups[0])

    assert command[:5] == ["nmap", "-sV", "--version-light", "-Pn", "-sC"]
    assert "--script" in command
    scripts = command[command.index("--script") + 1]
    assert "ssh2-enum-algos" in scripts
    assert "smb-security-mode" in scripts and "smb2-security-mode" in scripts
    assert "ssl-enum-ciphers" in scripts
    assert "--reason" in command
    assert "-Pn" in command
    assert Path(command[command.index("-iL") + 1]).is_absolute()
    assert command[-6:] == [
        "-p",
        "22,80,443",
        "-iL",
        str(tmp_path / "scans" / "service_groups" / "tcp_group_001_hosts.txt"),
        "-oA",
        str((tmp_path / "scans" / "04_tcp_services_tcp_group_001").resolve()),
    ]


def test_udp_group_command_generation(tmp_path: Path) -> None:
    runner = NmapRunner(tmp_path)
    groups = group_hosts_by_ports({"192.0.2.5": [53, 161]}, "udp")
    prepare_group_files(groups, tmp_path)

    command = runner.build_service_detection_command("udp", groups[0])

    assert command[:5] == ["nmap", "-sU", "-sV", "--version-light", "-Pn"]
    assert "--script" in command
    scripts = command[command.index("--script") + 1]
    assert "snmp-info" in scripts
    assert Path(command[command.index("-iL") + 1]).is_absolute()
    assert command[-6:] == [
        "-p",
        "53,161",
        "-iL",
        str(tmp_path / "scans" / "service_groups" / "udp_group_001_hosts.txt"),
        "-oA",
        str((tmp_path / "scans" / "07_udp_services_udp_group_001").resolve()),
    ]


def test_merging_duplicate_services_keeps_richer_record() -> None:
    poor = Asset(ip="192.0.2.5", services=[
        Service(host="192.0.2.5", port=443, protocol="tcp", state="open", service_name="https", confidence=3)
    ])
    rich = Asset(ip="192.0.2.5", services=[
        Service(
            host="192.0.2.5",
            port=443,
            protocol="tcp",
            state="open",
            service_name="https",
            product="nginx",
            version="1.24.0",
            cpes=["cpe:/a:nginx:nginx:1.24.0"],
            scripts={"ssl-cert": {"output": "subject=example", "data": {}}},
            confidence=10,
            source_file="04_tcp_services_tcp_group_001.xml",
        )
    ])

    merged = _merge_assets([poor], [rich])
    service = merged[0].services[0]

    assert len(merged[0].services) == 1
    assert service.product == "nginx"
    assert service.version == "1.24.0"
    assert service.scripts["ssl-cert"]["output"] == "subject=example"
    assert service.source_file == "04_tcp_services_tcp_group_001.xml"


def test_dry_run_includes_grouped_tcp_commands(tmp_path: Path) -> None:
    scans = tmp_path / "scans"
    scans.mkdir()
    (tmp_path / "runs").mkdir()
    (tmp_path / "logs").mkdir()
    targets = tmp_path / "targets.txt"
    targets.write_text("192.0.2.5\n192.0.2.6\n192.0.2.7\n", encoding="utf-8")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(_config_yaml(), encoding="utf-8")
    (scans / "01_discovery.xml").write_text(_discovery_xml(), encoding="utf-8")
    (scans / "02_tcp_top_1000.xml").write_text(_tcp_ports_xml(), encoding="utf-8")

    config = load_config(config_path)
    run = run_scan(tmp_path, config, config.get_profile("full-vapt"), targets, dry_run=True)

    commands = [" ".join(command.command) for command in run.commands]
    state = run.metadata["state"]

    assert any("04_tcp_services_tcp_group_001" in command for command in commands)
    assert any("04_tcp_services_tcp_group_002" in command for command in commands)
    assert len(state["tcp_service_detection_groups"]) == 2
    assert state["tcp_service_detection_groups"][0]["ports"] == [22, 80, 443]
    assert state["tcp_service_detection_groups"][0]["host_count"] == 2
    assert state["tcp_service_detection_groups"][1]["ports"] == [445]
    assert any(path.endswith("tcp_group_001_hosts.txt") for path in state["generated_files"])
    http_ports = {(target["host"], target["port"]) for target in state["module_targets"]["http_targets"]}
    tls_ports = {(target["host"], target["port"]) for target in state["module_targets"]["tls_targets"]}
    ssh_ports = {(target["host"], target["port"]) for target in state["module_targets"]["ssh_targets"]}
    assert ("192.0.2.5", 80) in http_ports
    assert ("192.0.2.6", 80) in http_ports
    assert ("192.0.2.5", 443) in tls_ports
    assert ("192.0.2.6", 443) in tls_ports
    assert ("192.0.2.5", 22) in ssh_ports
    assert ("192.0.2.6", 22) in ssh_ports


def test_nmap_runner_resolves_workspace_and_target_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("relative-workspace").mkdir()
    Path("targets.txt").write_text("192.0.2.5\n", encoding="utf-8")
    runner = NmapRunner(Path("relative-workspace"))

    command, _ = runner.build_command("discovery", Path("targets.txt"))

    assert runner.workspace.is_absolute()
    assert Path(command[command.index("-iL") + 1]).is_absolute()
    assert Path(command[command.index("-oA") + 1]).is_absolute()


def _config_yaml() -> str:
    return """
project:
  name: Test
scanner:
  nmap_timeout_seconds: 30
  udp_service_detection_on_open_filtered: false
profiles:
  full-vapt:
    context: unknown
    nmap_steps:
      - discovery
      - tcp_top_1000
      - tcp_services
    modules:
      exposure: true
    reports: [json]
"""


def _discovery_xml() -> str:
    return """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="192.0.2.6" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="192.0.2.7" addrtype="ipv4"/></host>
</nmaprun>
"""


def _tcp_ports_xml() -> str:
    return """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/><address addr="192.0.2.6" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
      <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/><address addr="192.0.2.7" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds"/></port>
    </ports>
  </host>
</nmaprun>
"""

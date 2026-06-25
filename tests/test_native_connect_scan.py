from __future__ import annotations

import asyncio
from pathlib import Path

from portwise.core.config import load_config
from portwise.core.models import Asset, Service
from portwise.core.routing import route_assets
from portwise.core.runner import run_scan
from portwise.scanners.connect_scan import NativeConnectScanResult, run_native_connect_scan


class _FakeWriter:
    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


async def _fake_open_connection(*, host=None, port=None, **_kwargs):
    if int(port) in {22, 80}:
        return object(), _FakeWriter()
    raise ConnectionRefusedError


def test_native_connect_scan_detects_open_ports(monkeypatch):
    monkeypatch.setattr("portwise.scanners.connect_scan.asyncio.open_connection", _fake_open_connection)

    result = asyncio.run(run_native_connect_scan(["scanme.nmap.org"], [22, 80, 443], timeout=0.05, concurrency=10))

    assert result.open_ports_by_host["scanme.nmap.org"] == [22, 80]
    assert result.open_ports == 2
    assert result.ports_scanned == 3
    assert result.ports_per_second > 0


def test_native_connect_scan_marks_legacy_tls_ports_as_tls():
    result = asyncio.run(run_native_connect_scan(["tls-v1-0.badssl.com"], [1010, 1011, 1012], timeout=0.01, concurrency=3))

    asset = Asset(ip="tls-v1-0.badssl.com", status="up")
    asset.add_service(Service(host="tls-v1-0.badssl.com", port=1010, protocol="tcp", state="open", service_name="https", tunnel="ssl"))
    routes = route_assets([asset], probe_tls=False)

    assert result.ports == [1010, 1011, 1012]
    assert routes["tls_targets"][0].port == 1010


def test_run_scan_uses_native_connect_scan_when_nmap_missing(monkeypatch, tmp_path: Path):
    _write_workspace_inputs(tmp_path)
    config = load_config(tmp_path / "config.yaml")
    profile = config.get_profile("full-vapt")

    async def fake_native(hosts, ports, *, timeout=1.5, concurrency=256):
        asset = Asset(ip=hosts[0], status="up")
        asset.add_service(Service(host=hosts[0], port=22, protocol="tcp", state="open", service_name="ssh"))
        asset.add_service(Service(host=hosts[0], port=80, protocol="tcp", state="open", service_name="http"))
        return NativeConnectScanResult(
            hosts=list(hosts),
            ports=list(ports),
            open_ports_by_host={hosts[0]: [22, 80]},
            elapsed_seconds=0.1,
            ports_scanned=2,
            open_ports=2,
            ports_per_second=20.0,
            assets=[asset],
        )

    monkeypatch.setattr("portwise.core.runner.NmapRunner.nmap_available", staticmethod(lambda: False))
    monkeypatch.setattr("portwise.core.runner.run_native_connect_scan", fake_native)

    run = run_scan(
        tmp_path,
        config,
        profile,
        tmp_path / "targets.txt",
        dry_run=False,
        no_modules=True,
        no_cve=True,
    )

    state = run.metadata["state"]
    assert run.commands[0].name == "native_connect_scan"
    assert run.metadata["native_connect_scan"]["open_ports_by_host"]["scanme.nmap.org"] == [22, 80]
    assert state["module_targets"]["ssh_targets"][0]["port"] == 22
    assert state["module_targets"]["http_targets"][0]["port"] == 80


def test_run_scan_keeps_nmap_when_present(monkeypatch, tmp_path: Path):
    _write_workspace_inputs(tmp_path)
    config = load_config(tmp_path / "config.yaml")
    profile = config.get_profile("full-vapt")

    def _fail(*_args, **_kwargs):
        raise AssertionError("native connect scan should not run when nmap is present")

    monkeypatch.setattr("portwise.core.runner.NmapRunner.nmap_available", staticmethod(lambda: True))
    monkeypatch.setattr("portwise.core.runner.run_native_connect_scan", _fail)

    run = run_scan(
        tmp_path,
        config,
        profile,
        tmp_path / "targets.txt",
        dry_run=True,
        no_modules=True,
        no_cve=True,
    )

    assert run.commands
    assert run.commands[0].name == "discovery"
    assert not any(command.name == "native_connect_scan" for command in run.commands)


def _write_workspace_inputs(tmp_path: Path) -> None:
    for name in ("scans", "runs", "logs", "evidence"):
        (tmp_path / name).mkdir(exist_ok=True)
    (tmp_path / "targets.txt").write_text("scanme.nmap.org\n", encoding="utf-8")
    (tmp_path / "config.yaml").write_text(
        "\n".join([
            "project:",
            "  name: Test",
            "scanner:",
            "  nmap_timeout_seconds: 1",
            "  timeout: 1",
            "  assume_hosts_up: false",
            "  native_connect_scan_ports: [22, 80, 443, 1010, 1011, 1012]",
            "profiles:",
            "  full-vapt:",
            "    context: unknown",
            "    nmap_steps:",
            "      - discovery",
            "      - tcp_top_1000",
            "      - tcp_services",
            "    modules:",
            "      exposure: true",
            "      http: true",
            "      ssh: true",
            "      cve_enrichment: false",
            "    reports: [json]",
        ]),
        encoding="utf-8",
    )

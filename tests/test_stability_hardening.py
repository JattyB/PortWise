from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from portwise.cli import main
from portwise.core.config import load_config
from portwise.core.progress import ProgressTracker, default_scan_phases, load_progress
from portwise.core.runner import run_scan
from portwise.reporting.excel_report import write_excel_report
from portwise.reporting.html_report import write_html_report
from portwise.reporting.json_report import build_json_report_from_dict
from portwise.scanners.nmap_parser import parse_nmap_xml
from portwise.scanners.nmap_runner import NmapRunner
from portwise.utils.files import ensure_text, make_json_safe, write_json


@dataclass
class _Example:
    value: bytes


def test_ensure_text_normalizes_common_values() -> None:
    assert ensure_text(None) == ""
    assert ensure_text(b"hello\xff").startswith("hello")
    assert ensure_text("ready") == "ready"
    assert ensure_text(42) == "42"


def test_make_json_safe_handles_nested_non_json_values() -> None:
    obj = {
        b"key": [b"value", Path("runs/latest.json"), {1, 2}, (3, 4)],
        "time": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "error": ValueError("bad"),
        "dataclass": _Example(b"bytes"),
    }

    safe = make_json_safe(obj)

    assert safe["key"][0] == "value"
    assert safe["time"].startswith("2026-01-01")
    json.dumps(safe)


def test_nmap_runner_handles_bytes_stdout_and_stderr(monkeypatch, tmp_path: Path) -> None:
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=1, stdout=b"udp bytes out", stderr=b"udp bytes err")

    monkeypatch.setattr(NmapRunner, "nmap_available", staticmethod(lambda: True))
    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = NmapRunner(tmp_path, timeout_seconds=1)

    result = runner.run_step("udp_top_1000", tmp_path / "targets.txt", dry_run=False, live_hosts_file=tmp_path / "live_hosts.txt")

    assert isinstance(result.error, str)
    assert "udp bytes err" in result.error
    assert (tmp_path / "logs" / "commands" / "udp_top_1000.stdout.log").read_text(encoding="utf-8") == "udp bytes out"
    json.dumps(make_json_safe(result))


def test_nmap_runner_handles_timeout_bytes(monkeypatch, tmp_path: Path) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1, output=b"partial out", stderr=b"partial err")

    monkeypatch.setattr(NmapRunner, "nmap_available", staticmethod(lambda: True))
    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = NmapRunner(tmp_path, timeout_seconds=1)

    result = runner.run_step("udp_top_1000", tmp_path / "targets.txt", dry_run=False)

    assert "timed out" in result.error
    assert "partial err" in result.error
    assert "partial out" in (tmp_path / "logs" / "commands" / "udp_top_1000.stdout.log").read_text(encoding="utf-8")


def test_udp_phase_bytes_regression_does_not_crash(monkeypatch, tmp_path: Path) -> None:
    _write_workspace_inputs(tmp_path, steps=["discovery", "tcp_top_1000", "udp_top_1000"])
    (tmp_path / "scans" / "01_discovery.xml").write_text(_discovery_xml(), encoding="utf-8")
    (tmp_path / "scans" / "02_tcp_top_1000.xml").write_text(_tcp_xml(), encoding="utf-8")

    def fake_run_step(self, step, *args, **kwargs):
        if step == "udp_top_1000":
            result = self.run_command("udp_top_1000", ["nmap", "-sU"], dry_run=True)
            result.skipped = False
            result.dry_run = False
            result.return_code = 1
            result.error = b"udp failed with bytes"
            return result
        return self.run_command(step, ["nmap"], dry_run=True)

    monkeypatch.setattr(NmapRunner, "run_step", fake_run_step)
    config = load_config(tmp_path / "config.yaml")
    progress = ProgressTracker(workspace=tmp_path, profile="full-vapt", phases=default_scan_phases(config.get_profile("full-vapt").nmap_steps), enabled=False)

    run_scan(tmp_path, config, config.get_profile("full-vapt"), tmp_path / "targets.txt", dry_run=False, no_modules=True, no_cve=True, progress=progress)

    latest = json.loads((tmp_path / "runs" / "latest.json").read_text(encoding="utf-8"))
    progress_data = load_progress(tmp_path)
    assert any("udp_top_1000" in item for item in latest["metadata"]["state"]["failed_phases"])
    assert isinstance(progress_data["phases"][3]["message"], str)
    json.dumps(latest)


def test_missing_empty_and_malformed_xml_are_safe(tmp_path: Path) -> None:
    missing = tmp_path / "missing.xml"
    empty = tmp_path / "empty.xml"
    malformed = tmp_path / "malformed.xml"
    empty.write_text("", encoding="utf-8")
    malformed.write_text("<nmaprun><host>", encoding="utf-8")

    assert parse_nmap_xml(missing) == []
    assert parse_nmap_xml(empty) == []
    assert parse_nmap_xml(malformed) == []


def test_json_excel_html_reports_tolerate_weird_values(tmp_path: Path) -> None:
    data = {
        "project": b"Project",
        "profile": "offline",
        "assets": [],
        "findings": [{"title": b"<script>", "severity": b"high", "evidence": [{"description": b"bytes"}]}],
        "metadata": {"state": {"skipped_phases": [b"skip"], "failed_phases": [ValueError("fail")]}}
    }

    report = build_json_report_from_dict(data)
    write_json(tmp_path / "report.json", report)
    write_excel_report(report, tmp_path / "report.xlsx")
    write_html_report(report, tmp_path / "report.html")

    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.xlsx").exists()
    assert "&lt;script&gt;" in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_cli_help_commands_smoke(capsys) -> None:
    for argv in (
        ["--help"],
        ["scan", "--help"],
        ["report", "--help"],
        ["retest", "--help"],
        ["status", "--help"],
    ):
        try:
            main(argv)
        except SystemExit as exc:
            assert exc.code == 0
    assert "usage:" in capsys.readouterr().out


def test_dry_run_skip_udp_and_udp_open_filtered(tmp_path: Path) -> None:
    _write_workspace_inputs(tmp_path, steps=["discovery", "tcp_top_1000", "udp_top_1000", "udp_services"])
    config_path = tmp_path / "config.yaml"

    assert main(["scan", "--targets", str(tmp_path / "targets.txt"), "--profile", "full-vapt", "--config", str(config_path), "--workspace", str(tmp_path), "--dry-run", "--skip-udp", "--no-progress"]) == 0
    assert main(["scan", "--targets", str(tmp_path / "targets.txt"), "--profile", "full-vapt", "--config", str(config_path), "--workspace", str(tmp_path), "--dry-run", "--udp-open-filtered", "--no-progress"]) == 0


def _write_workspace_inputs(tmp_path: Path, steps: list[str]) -> None:
    for name in ("scans", "runs", "logs", "evidence"):
        (tmp_path / name).mkdir(exist_ok=True)
    (tmp_path / "targets.txt").write_text("192.0.2.10\n", encoding="utf-8")
    (tmp_path / "config.yaml").write_text(
        "\n".join([
            "project:",
            "  name: Test",
            "scanner:",
            "  nmap_timeout_seconds: 1",
            "  udp_service_detection_on_open_filtered: false",
            "profiles:",
            "  full-vapt:",
            "    context: unknown",
            "    nmap_steps:",
            *[f"      - {step}" for step in steps],
            "    modules:",
            "      exposure: true",
            "      cve_enrichment: false",
            "    reports: [json]",
        ]),
        encoding="utf-8",
    )


def _discovery_xml() -> str:
    return """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host>
</nmaprun>
"""


def _tcp_xml() -> str:
    return """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port></ports>
  </host>
</nmaprun>
"""

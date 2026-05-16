from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def write_html_report(data: dict[str, Any], output_path: Path) -> Path:
    findings = data.get("findings", [])
    state = data.get("metadata", {}).get("state", {})
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>PortWise Report</title>",
        "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#202124}table{border-collapse:collapse;width:100%;margin:16px 0}th,td{border:1px solid #ddd;padding:8px;vertical-align:top}th{background:#f3f5f7;text-align:left}.critical{color:#8b0000;font-weight:700}.high{color:#b3261e;font-weight:700}.medium{color:#b06000}.low{color:#33691e}.informational{color:#4b5563}.card{display:inline-block;border:1px solid #ddd;padding:12px;margin:6px 8px 6px 0;border-radius:6px;background:#fafafa}</style>",
        "</head><body>",
        "<h1>PortWise VAPT Intelligence Report</h1>",
        f"<p>Project: {esc(data.get('project'))} | Profile: {esc(data.get('profile'))}</p>",
        "<h2>Executive Summary</h2>",
        summary_cards(data),
        "<h2>Top Risk Findings</h2>",
        findings_table(sorted(findings, key=lambda f: str(f.get('priority','P5')))[:15]),
        "<h2>Asset Inventory</h2>",
        mapping_table(state.get("services_by_host", {})),
        "<h2>Findings</h2>",
        findings_table(findings),
        "<h2>CVE Findings</h2>",
        findings_table([f for f in findings if f.get("type") == "CVE"]),
        "<h2>TLS Findings</h2>",
        findings_table([f for f in findings if f.get("module") == "tls" or str(f.get("type", "")).startswith("tls")]),
        "<h2>HTTP Findings</h2>",
        findings_table([f for f in findings if f.get("module") == "http" or str(f.get("type", "")).startswith("http")]),
        "<h2>Exposure Findings</h2>",
        findings_table([f for f in findings if f.get("module") == "exposure" or f.get("type") in {"Exposure", "Risk Indicator", "Needs Owner Validation"}]),
        "<h2>Module Coverage</h2>",
        dict_table(state.get("findings_by_module", {})),
        "<h2>Skipped and Failed Checks</h2>",
        list_table("Skipped", state.get("skipped_phases", []) + data.get("skipped_checks", [])),
        list_table("Failed", state.get("failed_phases", []) + data.get("failed_checks", [])),
        "<h2>Commands Executed</h2>",
        commands_table(data.get("commands", [])),
        "</body></html>",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(parts), encoding="utf-8")
    return output_path


def summary_cards(data: dict[str, Any]) -> str:
    state = data.get("metadata", {}).get("state", {})
    findings = data.get("findings", [])
    cards = {
        "Targets": len(state.get("targets_loaded", [])),
        "Live Hosts": len(state.get("live_hosts", [])),
        "Services": sum(len(v) for v in state.get("services_by_host", {}).values()),
        "Findings": len(findings),
        "Confirmed": sum(1 for f in findings if f.get("confidence") == "Confirmed"),
        "Needs Validation": sum(1 for f in findings if f.get("manual_validation")),
    }
    return "".join(f"<div class='card'><strong>{esc(k)}</strong><br>{v}</div>" for k, v in cards.items())


def findings_table(findings: list[dict[str, Any]]) -> str:
    headers = ["priority", "status", "severity", "confidence", "evidence_strength", "false_positive_risk", "title", "asset", "port", "module", "recommendation"]
    rows = ["<table><tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>"]
    for finding in findings:
        rows.append("<tr>" + "".join(cell(finding.get(h, ""), h == "severity") for h in headers) + "</tr>")
    rows.append("</table>")
    return "\n".join(rows)


def mapping_table(mapping: dict[str, Any]) -> str:
    rows = ["<table><tr><th>Host</th><th>Services</th></tr>"]
    for host, services in mapping.items():
        value = "<br>".join(f"{esc(s.get('protocol'))}/{esc(s.get('port'))} {esc(s.get('service_name'))} {esc(s.get('product'))} {esc(s.get('version'))}" for s in services)
        rows.append(f"<tr><td>{esc(host)}</td><td>{value}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def dict_table(mapping: dict[str, Any]) -> str:
    rows = ["<table><tr><th>Name</th><th>Value</th></tr>"]
    for key, value in mapping.items():
        rows.append(f"<tr><td>{esc(key)}</td><td>{esc(value)}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def list_table(title: str, items: list[Any]) -> str:
    rows = [f"<h3>{esc(title)}</h3><table><tr><th>Item</th></tr>"]
    for item in items:
        rows.append(f"<tr><td>{esc(item)}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def commands_table(commands: list[dict[str, Any]]) -> str:
    rows = ["<table><tr><th>Name</th><th>Command</th><th>Skipped</th><th>Error</th></tr>"]
    for command in commands:
        rows.append(f"<tr><td>{esc(command.get('name'))}</td><td>{esc(' '.join(command.get('command', [])))}</td><td>{esc(command.get('skipped'))}</td><td>{esc(command.get('error'))}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def cell(value: Any, severity: bool = False) -> str:
    cls = f" class='{esc(value)}'" if severity else ""
    return f"<td{cls}>{esc(value)}</td>"


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))

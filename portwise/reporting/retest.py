from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from portwise.reporting.excel_report import write_excel_report
from portwise.utils.files import write_json


def compare_runs(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    previous_services = _service_keys(previous)
    current_services = _service_keys(current)
    previous_findings = _finding_keys(previous)
    current_findings = _finding_keys(current)
    return {
        "services": _compare_sets(previous_services, current_services),
        "open_ports": _compare_sets(_port_keys(previous), _port_keys(current)),
        "findings": _compare_sets(previous_findings, current_findings),
        "cves": _compare_sets(_cve_keys(previous), _cve_keys(current)),
        "tls_findings": _compare_sets(_module_finding_keys(previous, "tls"), _module_finding_keys(current, "tls")),
        "http_findings": _compare_sets(_module_finding_keys(previous, "http"), _module_finding_keys(current, "http")),
        "exposure_findings": _compare_sets(_module_finding_keys(previous, "exposure"), _module_finding_keys(current, "exposure")),
    }


def write_retest_report(previous_path: Path, current_path: Path, output_dir: Path, format_: str) -> list[Path]:
    previous = json.loads(previous_path.read_text(encoding="utf-8"))
    current = json.loads(current_path.read_text(encoding="utf-8"))
    result = compare_runs(previous, current)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if format_ in {"json", "all"}:
        path = output_dir / "PortWise_Retest.json"
        write_json(path, result)
        written.append(path)
    if format_ in {"excel", "all"}:
        path = output_dir / "PortWise_Retest.xlsx"
        write_retest_excel(result, path)
        written.append(path)
    return written


def write_retest_excel(result: dict[str, Any], output_path: Path) -> Path:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ModuleNotFoundError:
        rows_as_findings = [
            {"priority": "P5", "severity": "informational", "confidence": "Informational", "title": f"{section}: {status}", "description": ", ".join(values)}
            for section, statuses in result.items()
            for status, values in statuses.items()
        ]
        return write_excel_report({"findings": rows_as_findings, "metadata": {"state": {}}}, output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    ws.append(["Section", "Fixed", "Still Open", "New", "Changed", "Not Verifiable"])
    for section, statuses in result.items():
        ws.append([section, len(statuses["Fixed"]), len(statuses["Still Open"]), len(statuses["New"]), len(statuses["Changed"]), len(statuses["Not Verifiable"])])
    for status in ["Fixed", "Still Open", "New", "Changed", "Not Verifiable"]:
        sheet = wb.create_sheet(status[:31])
        sheet.append(["Section", "Item"])
        for section, statuses in result.items():
            for item in statuses[status]:
                sheet.append([section, item])
    for sheet in wb.worksheets:
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
        for cell in sheet[1]:
            cell.font = Font(bold=True)
    wb.save(output_path)
    return output_path


def _compare_sets(previous: set[str], current: set[str]) -> dict[str, list[str]]:
    return {
        "Fixed": sorted(previous - current),
        "Still Open": sorted(previous & current),
        "New": sorted(current - previous),
        "Changed": [],
        "Not Verifiable": [],
    }


def _service_keys(data: dict[str, Any]) -> set[str]:
    return {f"{svc.get('host')}:{svc.get('port')}/{svc.get('protocol')}:{svc.get('service_name')}" for asset in data.get("assets", []) for svc in asset.get("services", [])}


def _port_keys(data: dict[str, Any]) -> set[str]:
    return {f"{svc.get('host')}:{svc.get('port')}/{svc.get('protocol')}" for asset in data.get("assets", []) for svc in asset.get("services", [])}


def _finding_keys(data: dict[str, Any]) -> set[str]:
    return {f"{f.get('title')}|{f.get('asset')}|{f.get('port')}|{f.get('protocol')}|{f.get('module')}|{f.get('cve_id') or ''}" for f in data.get("findings", [])}


def _cve_keys(data: dict[str, Any]) -> set[str]:
    return {str(f.get("cve_id")) for f in data.get("findings", []) if f.get("cve_id")}


def _module_finding_keys(data: dict[str, Any], module: str) -> set[str]:
    return {f"{f.get('title')}|{f.get('asset')}|{f.get('port')}" for f in data.get("findings", []) if f.get("module") == module}

from __future__ import annotations

from pathlib import Path
from typing import Any

from portwise.core.models import RunResult
from portwise.intelligence.risk_scoring import finding_counts
from portwise.utils.files import write_json


def build_json_report(run: RunResult) -> dict[str, Any]:
    data = run.to_dict()
    data["summary"] = finding_counts(run.findings)
    _promote_state(data)
    data["project_info"] = {
        "project": run.project,
        "profile": run.profile,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
    }
    return data


def write_json_report(run: RunResult, output_path: Path) -> Path:
    write_json(output_path, build_json_report(run))
    return output_path


def build_json_report_from_dict(data: dict[str, Any]) -> dict[str, Any]:
    findings = data.get("findings", [])
    summary = {
        "by_severity": _count_dicts(findings, "severity"),
        "by_status": _count_dicts(findings, "status"),
        "by_type": _count_dicts(findings, "type"),
        "by_confidence": _count_dicts(findings, "confidence"),
    }
    report = dict(data)
    report["summary"] = summary
    _promote_state(report)
    report["project_info"] = {
        "project": data.get("project"),
        "profile": data.get("profile"),
        "started_at": data.get("started_at"),
        "finished_at": data.get("finished_at"),
    }
    return report


def _promote_state(report: dict[str, Any]) -> None:
    state = report.get("metadata", {}).get("state", {})
    if not state:
        return
    report["live_hosts"] = state.get("live_hosts", [])
    report["dead_hosts"] = state.get("dead_hosts", [])
    report["services"] = state.get("services_by_host", {})
    report["tcp_open_ports_summary"] = state.get("tcp_open_ports_by_host", {})
    report["udp_open_ports_summary"] = state.get("udp_open_ports_by_host", {})
    report["udp_open_filtered_summary"] = state.get("udp_open_filtered_ports_by_host", {})
    report["module_target_details"] = state.get("module_targets", {})
    report["module_target_counts"] = {
        key: len(value) for key, value in state.get("module_targets", {}).items()
    }
    report["skipped_phases"] = state.get("skipped_phases", [])
    report["tcp_service_detection_groups"] = state.get("tcp_service_detection_groups", [])
    report["udp_service_detection_groups"] = state.get("udp_service_detection_groups", [])
    report["module_runs"] = state.get("module_runs", [])
    report["module_errors"] = state.get("module_errors", [])
    report["findings_by_module"] = state.get("findings_by_module", {})
    report["evidence_by_module"] = state.get("evidence_by_module", {})


def _count_dicts(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return counts

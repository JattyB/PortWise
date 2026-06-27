"""Client branding, manual findings, and persistent false-positive suppression."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml


def finding_fingerprint(finding: dict[str, Any]) -> str:
    material = "|".join(str(finding.get(key, "")).strip().lower()
                        for key in ("asset", "port", "protocol", "type", "title"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def apply_report_inputs(
    report: dict[str, Any],
    *,
    manual_file: Path | None = None,
    suppression_file: Path | None = None,
    client_name: str = "",
    logo: str = "",
) -> dict[str, Any]:
    result = dict(report)
    findings = [dict(item) for item in report.get("findings", [])]
    if manual_file:
        loaded = _load(manual_file)
        manual = loaded.get("findings", []) if isinstance(loaded, dict) else loaded
        for item in manual if isinstance(manual, list) else []:
            if isinstance(item, dict):
                row = dict(item)
                row.setdefault("module", "operator")
                row.setdefault("type", "manual")
                row.setdefault("status", "open")
                row.setdefault("confidence", "Confirmed")
                findings.append(row)
    suppressed = _suppression_ids(suppression_file)
    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        finding["fingerprint"] = fingerprint
        if fingerprint in suppressed:
            finding["status"] = "suppressed"
            tags = list(finding.get("tags", []) or [])
            if "false-positive-suppressed" not in tags:
                tags.append("false-positive-suppressed")
            finding["tags"] = tags
    result["findings"] = findings
    result["branding"] = {"client_name": client_name, "logo": logo}
    return result


def _suppression_ids(path: Path | None) -> set[str]:
    if not path or not path.exists():
        return set()
    loaded = _load(path)
    values = loaded.get("suppressions", []) if isinstance(loaded, dict) else loaded
    return {str(value.get("fingerprint") if isinstance(value, dict) else value)
            for value in values if value}


def _load(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix.lower() == ".json":
            return json.load(handle)
        return yaml.safe_load(handle) or {}

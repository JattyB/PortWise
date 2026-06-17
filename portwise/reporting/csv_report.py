"""CSV findings export — a flat, spreadsheet/grep-friendly view of findings."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from portwise.utils.files import ensure_text

_COLUMNS = [
    "priority",
    "severity",
    "title",
    "asset",
    "port",
    "protocol",
    "service",
    "module",
    "category",
    "confidence",
    "false_positive_risk",
    "evidence_strength",
    "cve_id",
    "cvss",
    "epss",
    "kev",
    "exploit_available",
    "exploit_refs",
    "tags",
    "description",
    "recommendation",
]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}


def build_csv_rows(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for f in findings:
        rows.append({
            "priority": ensure_text(f.get("priority", "")),
            "severity": ensure_text(f.get("severity", "")),
            "title": ensure_text(f.get("title", "")),
            "asset": ensure_text(f.get("asset", "")),
            "port": ensure_text(f.get("port", "")),
            "protocol": ensure_text(f.get("protocol", "")),
            "service": ensure_text(f.get("service", "")),
            "module": ensure_text(f.get("module", "")),
            "category": ensure_text(f.get("category", "")),
            "confidence": ensure_text(f.get("confidence", "")),
            "false_positive_risk": ensure_text(f.get("false_positive_risk", "")),
            "evidence_strength": ensure_text(f.get("evidence_strength", "")),
            "cve_id": ensure_text(f.get("cve_id", "")),
            "cvss": ensure_text(f.get("cvss", "")),
            "epss": ensure_text(f.get("epss", "")),
            "kev": "yes" if f.get("kev") else "",
            "exploit_available": "yes" if f.get("exploit_available") else "",
            "exploit_refs": " | ".join(ensure_text(r) for r in (f.get("exploit_refs") or [])),
            "tags": " ".join(ensure_text(t) for t in (f.get("tags") or [])),
            "description": ensure_text(f.get("description", "")).replace("\n", " "),
            "recommendation": ensure_text(f.get("recommendation", "")).replace("\n", " "),
        })
    rows.sort(key=lambda r: (_SEV_ORDER.get(r["severity"].lower(), 9), r["priority"], r["asset"]))
    return rows


def write_csv_report(data: dict[str, Any], output_path: Path) -> Path:
    findings = data.get("findings", []) or []
    rows = build_csv_rows(findings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return output_path

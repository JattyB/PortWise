from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from portwise.core.models import Confidence, Evidence, Finding, Severity
from portwise.intelligence.risk_scoring import assign_priority


def import_testssl_json(directory: Path | None) -> tuple[list[Finding], list[str]]:
    if directory is None:
        return [], []
    notes: list[str] = []
    findings: list[Finding] = []
    if not directory.exists():
        return [], [f"testssl import skipped: directory not found: {directory}"]
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            notes.append(f"testssl import skipped malformed file {path.name}: {exc}")
            continue
        items = data if isinstance(data, list) else data.get("scanResult", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            notes.append(f"testssl import skipped unsupported file {path.name}")
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            severity = _severity(str(item.get("severity", item.get("finding", ""))))
            if severity == Severity.INFO and not item.get("id"):
                continue
            host = str(item.get("ip", item.get("host", item.get("server", ""))))
            port = int(item.get("port", 443) or 443)
            title = str(item.get("id", item.get("finding", "Imported testssl Finding"))).replace("_", " ")
            evidence = Evidence("testssl-json-import", "Imported from testssl JSON; not revalidated by PortWise.", 3, {"file": path.name, "raw": _small(item)})
            findings.append(assign_priority(Finding(
                title=title,
                severity=severity,
                asset=host,
                port=port,
                protocol="tcp",
                service="tls",
                description=str(item.get("finding", item.get("description", title))),
                recommendation=str(item.get("recommendation", "Validate TLS configuration and remediate according to policy.")),
                confidence=Confidence.POSSIBLE,
                evidence_strength=3,
                type="TLS Import",
                module="testssl-import",
                false_positive_risk="medium",
                manual_validation=True,
                evidence=[evidence],
            )))
    return findings, notes


def import_nessus_csv(path: Path | None) -> tuple[list[Finding], list[str]]:
    if path is None:
        return [], []
    if not path.exists():
        return [], [f"Nessus import skipped: file not found: {path}"]
    findings: list[Finding] = []
    notes: list[str] = []
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                title = row.get("Name") or row.get("Plugin Name") or "Imported Nessus Finding"
                evidence = Evidence("nessus-csv-import", "Imported from Nessus CSV; not revalidated by PortWise.", 3, _small(row))
                finding = Finding(
                    title=title,
                    severity=_severity(row.get("Risk", "")),
                    asset=row.get("Host", ""),
                    port=int(row.get("Port", 0) or 0),
                    protocol=row.get("Protocol", ""),
                    service="",
                    description=row.get("Description") or row.get("Synopsis") or title,
                    recommendation=row.get("Solution") or "Validate imported finding and remediate according to vendor guidance.",
                    confidence=Confidence.POSSIBLE,
                    evidence_strength=3,
                    type="Nessus Import",
                    module="nessus-import",
                    false_positive_risk="medium",
                    manual_validation=True,
                    cve_id=(row.get("CVE") or "").split(",")[0].strip() or None,
                    cvss=float(row["CVSS"]) if row.get("CVSS", "").replace(".", "", 1).isdigit() else None,
                    references=[item.strip() for item in (row.get("See Also") or "").split(",") if item.strip()][:5],
                    evidence=[evidence],
                )
                findings.append(assign_priority(finding))
    except Exception as exc:
        notes.append(f"Nessus import failed: {exc}")
    return findings, notes


def _severity(value: str) -> Severity:
    lower = value.lower()
    if "critical" in lower:
        return Severity.CRITICAL
    if "high" in lower:
        return Severity.HIGH
    if "medium" in lower:
        return Severity.MEDIUM
    if "low" in lower:
        return Severity.LOW
    return Severity.INFO


def _small(value: dict[str, Any]) -> dict[str, Any]:
    return {str(k): str(v)[:500] for k, v in value.items()}

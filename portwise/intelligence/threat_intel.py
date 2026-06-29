from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from portwise.core.models import Finding
from portwise.intelligence.risk_scoring import assign_priority


def enrich_findings_with_local_threat_intel(
    findings: list[Finding],
    *,
    data_dir: Path | None = None,
    context: str = "unknown",
    internet_facing: bool = False,
) -> list[str]:
    root = data_dir or (Path(__file__).resolve().parents[1] / "data" / "threat_intel")
    epss_doc = _load(root / "epss.json")
    kev_doc = _load(root / "kev.json")
    epss = {
        str(item.get("cve", "")).upper(): item
        for item in epss_doc.get("data", [])
        if item.get("cve")
    }
    kev = {
        str(item.get("cveID", "")).upper(): item
        for item in kev_doc.get("vulnerabilities", [])
        if item.get("cveID")
    }
    enriched = 0
    for finding in findings:
        cve_id = str(finding.cve_id or "").upper()
        if not cve_id:
            continue
        record = epss.get(cve_id)
        if record:
            finding.epss = float(record.get("epss", 0) or 0)
            finding.epss_percentile = float(record.get("percentile", 0) or 0)
            if "epss-enriched" not in finding.tags:
                finding.tags.append("epss-enriched")
        if cve_id in kev:
            finding.kev = True
            if "cisa-kev" not in finding.tags:
                finding.tags.append("cisa-kev")
            notes = str(kev[cve_id].get("notes", "") or "")
            if notes.startswith("http") and notes not in finding.references:
                finding.references.append(notes)
        if record or cve_id in kev:
            enriched += 1
        assign_priority(finding, context=context, internet_facing=internet_facing)
    return [f"threat_intel: enriched {enriched} CVE finding(s) from packaged EPSS/KEV data"]


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}

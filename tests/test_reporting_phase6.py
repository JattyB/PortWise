from __future__ import annotations

import csv
from pathlib import Path

from portwise.reporting.csv_report import build_csv_rows, write_csv_report
from portwise.reporting.html_report import write_html_report
from portwise.reporting.narrative import executive_summary_text, summary_facts


def _data(**overrides) -> dict:
    data = {
        "project": "Acme Corp",
        "profile": "full-vapt",
        "findings": [
            {
                "title": "Apache Log4j RCE", "severity": "critical", "confidence": "Likely",
                "priority": "P1", "asset": "10.0.0.5", "port": 8080, "protocol": "tcp",
                "service": "http", "module": "nuclei", "category": "vulnerability",
                "description": "Log4Shell", "recommendation": "Patch", "evidence_strength": 4,
                "cve_id": "CVE-2021-44228", "cvss": 10.0, "kev": True,
                "exploit_available": True,
                "exploit_refs": ["ExploitDB EDB-50592: Log4j RCE", "nuclei template: /x/CVE-2021-44228.yaml"],
                "tags": ["nuclei", "exploit-available"],
            },
            {
                "title": "Cleartext Protocol Exposed — Telnet", "severity": "high", "confidence": "Confirmed",
                "priority": "P2", "asset": "10.0.0.6", "port": 23, "protocol": "tcp",
                "service": "telnet", "module": "plaintext", "category": "vulnerability",
                "description": "Telnet cleartext", "recommendation": "Disable", "evidence_strength": 4,
                "tags": ["plaintext-protocol"],
            },
            {
                "title": "HTTP Service Metadata", "severity": "informational", "confidence": "Likely",
                "priority": "P5", "asset": "10.0.0.5", "port": 8080, "protocol": "tcp",
                "service": "http", "module": "http", "category": "information",
                "description": "meta", "recommendation": "", "evidence_strength": 4,
            },
        ],
        "metadata": {"state": {
            "targets_loaded": ["10.0.0.5", "10.0.0.6"],
            "live_hosts": ["10.0.0.5", "10.0.0.6"],
            "services_by_host": {"10.0.0.5": [{"protocol": "tcp", "port": 8080, "service_name": "http"}]},
            "skipped_phases": [], "failed_phases": [],
        }},
        "commands": [],
        "skipped_checks": [], "failed_checks": [],
    }
    data.update(overrides)
    return data


# --- narrative ---------------------------------------------------------------

def test_summary_facts_counts():
    facts = summary_facts(_data())
    assert facts["total_findings"] == 3
    assert facts["severity"]["critical"] == 1
    assert facts["severity"]["high"] == 1
    assert facts["vulnerabilities"] == 2
    assert facts["confirmed"] == 1
    assert facts["kev"] == 1
    assert facts["exploitable"] == 1
    assert facts["cleartext"] == 1
    # info findings excluded from "top"
    assert all("Metadata" not in f["title"] for f in facts["top"])


def test_executive_summary_text_mentions_drivers():
    text = executive_summary_text(_data())
    assert "Acme Corp" in text
    assert "known public exploit" in text
    assert "KEV" in text
    assert "Log4j" in text  # top item listed


# --- CSV ---------------------------------------------------------------------

def test_csv_rows_sorted_and_flagged():
    rows = build_csv_rows(_data()["findings"])
    # critical first
    assert rows[0]["severity"] == "critical"
    assert rows[0]["exploit_available"] == "yes"
    assert rows[0]["kev"] == "yes"
    assert "EDB-50592" in rows[0]["exploit_refs"]


def test_write_csv_report(tmp_path: Path):
    out = write_csv_report(_data(), tmp_path / "f.csv")
    assert out.exists()
    with out.open(encoding="utf-8") as handle:
        reader = list(csv.DictReader(handle))
    assert len(reader) == 3
    assert reader[0]["title"] == "Apache Log4j RCE"
    assert reader[0]["exploit_available"] == "yes"


# --- HTML integration --------------------------------------------------------

def test_html_has_exec_summary_and_per_host(tmp_path: Path):
    out = write_html_report(_data(), tmp_path / "r.html")
    content = out.read_text(encoding="utf-8")
    assert "exec-section" in content
    assert "Executive Summary" in content
    assert "Findings by Host" in content
    # exploit surfacing
    assert "EXPLOIT" in content
    # per-host groups both hosts
    assert "10.0.0.5" in content and "10.0.0.6" in content


def test_html_retest_diff_section(tmp_path: Path):
    data = _data()
    data["retest"] = {
        "findings": {"Fixed": ["a|x"], "Still Open": ["b|y"], "New": ["c|z"], "Changed": [], "Not Verifiable": []},
        "cves": {"Fixed": [], "Still Open": [], "New": ["CVE-2021-44228"], "Changed": [], "Not Verifiable": []},
    }
    out = write_html_report(data, tmp_path / "r.html")
    content = out.read_text(encoding="utf-8")
    assert "Retest Diff" in content
    assert "Fixed" in content and "Still Open" in content


def test_html_no_retest_section_when_absent(tmp_path: Path):
    out = write_html_report(_data(), tmp_path / "r.html")
    content = out.read_text(encoding="utf-8")
    assert "Retest Diff" not in content

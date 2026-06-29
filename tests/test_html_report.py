from __future__ import annotations

from pathlib import Path


from portwise.reporting.html_report import write_html_report


def _sample_data(**overrides) -> dict:
    data = {
        "project": "Test Project",
        "profile": "test",
        "findings": [
            {
                "title": "SQL Injection",
                "severity": "high",
                "confidence": "confirmed",
                "priority": "P1",
                "asset": "192.168.1.1",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "module": "http",
                "category": "vulnerability",
                "description": "Unparameterised query detected.",
                "recommendation": "Use parameterised queries.",
                "evidence_strength": 8,
                "false_positive_risk": "low",
                "tags": ["safe-active"],
                "evidence": [{"source": "http-response", "description": "Error output revealed query"}],
                "cves": [{"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "epss_score": 0.05,
                          "kev": True, "description": "Remote code execution", "references": []}],
            },
            {
                "title": "Missing HSTS Header",
                "severity": "low",
                "confidence": "likely",
                "priority": "P3",
                "asset": "192.168.1.1",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "module": "http",
                "category": "best_practice",
                "description": "HSTS not set.",
                "recommendation": "Add HSTS header.",
                "evidence_strength": 5,
            },
        ],
        "metadata": {
            "state": {
                "targets_loaded": ["192.168.1.1"],
                "live_hosts": ["192.168.1.1"],
                "services_by_host": {
                    "192.168.1.1": [
                        {"protocol": "tcp", "port": 443, "service_name": "https", "product": "nginx", "version": "1.24"},
                    ]
                },
                "findings_by_module": {"http": 2},
                "skipped_phases": [],
                "failed_phases": [],
            }
        },
        "commands": [
            {"name": "nmap-tcp", "command": ["nmap", "-sV", "192.168.1.1"], "skipped": None, "error": None},
        ],
        "skipped_checks": [],
        "failed_checks": [],
    }
    data.update(overrides)
    return data


def test_html_report_renders_all_sections(tmp_path: Path) -> None:
    out = write_html_report(_sample_data(), tmp_path / "report.html")
    content = out.read_text(encoding="utf-8")
    assert out.exists()
    assert "<!doctype html>" in content
    # Key structural sections present
    for marker in ("site-header", "stat-grid", "charts-section", "findings-section",
                   "section-wrap", "site-footer"):
        assert marker in content, f"Missing section marker: {marker}"
    # Both findings appear
    assert "SQL Injection" in content
    assert "Missing HSTS Header" in content


def test_html_report_is_self_contained(tmp_path: Path) -> None:
    out = write_html_report(_sample_data(), tmp_path / "report.html")
    content = out.read_text(encoding="utf-8")
    # No CDN links — nothing referencing external http(s):// resources
    import re
    cdn_refs = re.findall(r'(?:src|href)\s*=\s*["\']https?://', content, re.IGNORECASE)
    assert not cdn_refs, f"CDN references found: {cdn_refs}"
    # No <script src="..."> or <link href="..."> pointing elsewhere
    assert 'src="http' not in content
    assert "src='http" not in content


def test_html_report_escapes_untrusted_values(tmp_path: Path) -> None:
    xss_title = '<script>alert("xss")</script>'
    data = _sample_data()
    data["findings"][0]["title"] = xss_title
    data["project"] = '<img src=x onerror=alert(1)>'
    out = write_html_report(data, tmp_path / "report.html")
    content = out.read_text(encoding="utf-8")
    # Raw exploitable tags must not appear unescaped
    assert "<script>alert" not in content
    assert "<img src=x onerror" not in content
    # Escaped form should be present
    assert "&lt;script&gt;" in content
    assert "&lt;img" in content


def test_html_report_handles_missing_category_field(tmp_path: Path) -> None:
    data = _sample_data()
    for f in data["findings"]:
        f.pop("category", None)
    # Should not raise
    out = write_html_report(data, tmp_path / "report.html")
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "SQL Injection" in content


def test_html_report_empty_findings_ok(tmp_path: Path) -> None:
    data = _sample_data(findings=[])
    out = write_html_report(data, tmp_path / "report.html")
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "<!doctype html>" in content
    assert "No findings" in content or "0</span>" in content or "pw-count" in content


def test_html_report_kev_badge_shown(tmp_path: Path) -> None:
    out = write_html_report(_sample_data(), tmp_path / "report.html")
    content = out.read_text(encoding="utf-8")
    assert "kev-badge" in content or "KEV" in content


def test_html_report_severity_badges_colored(tmp_path: Path) -> None:
    out = write_html_report(_sample_data(), tmp_path / "report.html")
    content = out.read_text(encoding="utf-8")
    assert "badge-high" in content
    assert "badge-low" in content


def test_html_report_stat_cards_show_counts(tmp_path: Path) -> None:
    out = write_html_report(_sample_data(), tmp_path / "report.html")
    content = out.read_text(encoding="utf-8")
    assert "AUTHORIZED" not in content.upper()
    assert "SAFE-ACTIVE" not in content.upper()
    # 1 target, 1 live host, 1 vulnerability
    assert "stat-value" in content
    assert "Targets" in content
    assert "Vulnerabilities" in content


def test_html_report_preserves_function_signature(tmp_path: Path) -> None:
    """Callers must not need to change — write_html_report(data, path) -> Path."""
    result = write_html_report(_sample_data(), tmp_path / "out.html")
    assert isinstance(result, Path)
    assert result.exists()
